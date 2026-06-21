"""Async VirusTotal + AbuseIPDB enrichment. API keys from env only."""
from __future__ import annotations
import asyncio
import httpx
from loguru import logger
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential
from nyx_sentinel.config.settings import settings
from nyx_sentinel.parsers.models import IOC, IOCType

_VT_BASE = "https://www.virustotal.com/api/v3"
_ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
_VT_REQUEST_DELAY = 15.5


async def enrich_iocs(iocs: list[IOC]) -> list[IOC]:
    if not iocs: return iocs
    enrichable = [i for i in iocs if i.ioc_type in
                  (IOCType.IP_ADDRESS, IOCType.DOMAIN, IOCType.MD5,
                   IOCType.SHA1, IOCType.SHA256, IOCType.URL)]
    logger.info("Enriching {} / {} IOCs.", len(enrichable), len(iocs))
    async with httpx.AsyncClient(timeout=settings.api_timeout_seconds) as client:
        for ioc in enrichable:
            try:
                if ioc.ioc_type == IOCType.IP_ADDRESS:
                    await _enrich_ip(client, ioc)
                elif ioc.ioc_type == IOCType.DOMAIN:
                    await _enrich_domain(client, ioc)
                elif ioc.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
                    await _enrich_hash(client, ioc)
                elif ioc.ioc_type == IOCType.URL:
                    await _enrich_url(client, ioc)
            except Exception as exc:
                ioc.enrichment_error = str(exc)
                logger.warning("Enrichment failed for IOC type={}: {}", ioc.ioc_type, exc)
            await asyncio.sleep(_VT_REQUEST_DELAY)
    malicious = sum(1 for i in iocs if i.is_malicious)
    logger.info("Enrichment complete. {} flagged malicious.", malicious)
    return iocs


async def _enrich_ip(client: httpx.AsyncClient, ioc: IOC) -> None:
    if settings.enable_virustotal and settings.virustotal_api_key:
        _apply_vt_stats(ioc, await _vt_get(client, f"/ip_addresses/{ioc.value}"))
    if settings.enable_abuseipdb and settings.abuseipdb_api_key:
        _apply_abuseipdb(ioc, await _abuseipdb_check(client, ioc.value))

async def _enrich_domain(client: httpx.AsyncClient, ioc: IOC) -> None:
    if settings.enable_virustotal and settings.virustotal_api_key:
        _apply_vt_stats(ioc, await _vt_get(client, f"/domains/{ioc.value}"))

async def _enrich_hash(client: httpx.AsyncClient, ioc: IOC) -> None:
    if settings.enable_virustotal and settings.virustotal_api_key:
        _apply_vt_stats(ioc, await _vt_get(client, f"/files/{ioc.value}"))

async def _enrich_url(client: httpx.AsyncClient, ioc: IOC) -> None:
    if settings.enable_virustotal and settings.virustotal_api_key:
        import base64
        url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
        _apply_vt_stats(ioc, await _vt_get(client, f"/urls/{url_id}"))


@retry(retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
       stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1,min=2,max=30), reraise=True)
async def _vt_get(client: httpx.AsyncClient, path: str) -> dict:
    if not settings.virustotal_api_key: return {}
    r = await client.get(f"{_VT_BASE}{path}", headers={"x-apikey": settings.virustotal_api_key})
    if r.status_code == 404: return {}
    if r.status_code == 429:
        raise httpx.TimeoutException("VT rate limit", request=r.request)
    r.raise_for_status()
    return r.json()


@retry(retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
       stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1,min=2,max=30), reraise=True)
async def _abuseipdb_check(client: httpx.AsyncClient, ip: str) -> dict:
    if not settings.abuseipdb_api_key: return {}
    r = await client.get(f"{_ABUSEIPDB_BASE}/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"})
    if r.status_code in (422, 429): return {}
    r.raise_for_status()
    return r.json().get("data", {})


def _apply_vt_stats(ioc: IOC, data: dict) -> None:
    if not data: return
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
    if not stats:  # None or empty dict — no enrichment data available
        return
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    ioc.vt_malicious = int(malicious)
    ioc.vt_total = int(total)
    if ioc.vt_malicious and ioc.vt_malicious >= 2:
        ioc.is_malicious = True


def _apply_abuseipdb(ioc: IOC, data: dict) -> None:
    if not data: return
    confidence = int(data.get("abuseConfidenceScore", 0))
    ioc.abuse_confidence = confidence
    ioc.abuse_country = data.get("countryCode")
    if confidence >= 50:
        ioc.is_malicious = True


def enrich_iocs_sync(iocs: list[IOC]) -> list[IOC]:
    return asyncio.run(enrich_iocs(iocs))


def enrich_iocs_stub(iocs: list[IOC]) -> list[IOC]:
    for ioc in iocs:
        val = ioc.value.lower()
        if any(x in val for x in ("malicious", "evil", "hack")):
            ioc.vt_malicious = 15; ioc.vt_total = 72
            ioc.abuse_confidence = 85; ioc.is_malicious = True
        else:
            ioc.vt_malicious = 0; ioc.vt_total = 72
            ioc.abuse_confidence = 0; ioc.is_malicious = False
    return iocs
