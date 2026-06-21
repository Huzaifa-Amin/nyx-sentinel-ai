"""Extract Indicators of Compromise from parsed Wazuh alerts (ReDoS-safe)."""
from __future__ import annotations
import re
from typing import Any, Optional
from loguru import logger
from nyx_sentinel.parsers.models import IOC, IOCType, ParsedAlert

_RE_IPV4   = re.compile(r"(?<![.\d])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![.\d])")
_RE_DOMAIN = re.compile(r"(?<![/@\w])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,10}[a-zA-Z]{2,13}(?![.\w])")
_RE_URL    = re.compile(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{1,2000}")
_RE_MD5    = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")
_RE_SHA1   = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])")
_RE_SHA256 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_RE_EMAIL  = re.compile(r"[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,13}")
_RE_CVE    = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_RE_WINPATH= re.compile(r"(?:[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,255}\\){0,20}[^\\/:*?\"<>|\r\n]{0,255})|(?:\\\\[^\\/:*?\"<>|\r\n]{1,255}(?:\\[^\\/:*?\"<>|\r\n]{1,255})+)")

_NOISE_IPS = frozenset({"0.0.0.0","127.0.0.1","255.255.255.255","::1"})
_NOISE_DOMS = frozenset({"localhost","local","internal","example.com","test.com"})

_STRUCTURED_FIELDS: list[tuple[str,str]] = [
    ("data.srcip", IOCType.IP_ADDRESS), ("data.dstip", IOCType.IP_ADDRESS),
    ("data.win.eventdata.ipAddress", IOCType.IP_ADDRESS),
    ("data.win.eventdata.destinationIp", IOCType.IP_ADDRESS),
    ("data.win.eventdata.targetUserName", IOCType.USERNAME),
    ("data.win.eventdata.subjectUserName", IOCType.USERNAME),
    ("data.dstuser", IOCType.USERNAME), ("data.srcuser", IOCType.USERNAME),
    ("data.win.eventdata.processName", IOCType.PROCESS),
    ("data.win.eventdata.parentProcessName", IOCType.PROCESS),
    ("data.process.name", IOCType.PROCESS),
    ("data.win.eventdata.hashes", IOCType.SHA256),
    ("syscheck.sha256_after", IOCType.SHA256),
    ("syscheck.md5_after", IOCType.MD5), ("syscheck.sha1_after", IOCType.SHA1),
    ("syscheck.path", IOCType.FILE_PATH),
    ("data.win.eventdata.imagePath", IOCType.FILE_PATH),
]


def extract_iocs(alert: ParsedAlert) -> list[IOC]:
    iocs: list[IOC] = []
    iocs.extend(_extract_structured(alert.raw_data))
    if alert.full_log:
        iocs.extend(_extract_from_text(alert.full_log, "full_log"))
    if alert.rule.description:
        iocs.extend(_extract_from_text(alert.rule.description, "rule.description"))
    seen: set[tuple[str,str]] = set()
    unique: list[IOC] = []
    for ioc in iocs:
        key = (ioc.ioc_type, ioc.value.lower())
        if key not in seen:
            seen.add(key)
            unique.append(ioc)
    logger.info("Extracted {} unique IOCs from alert id={}", len(unique), alert.alert_id)
    return unique


def _extract_structured(raw: dict[str,Any]) -> list[IOC]:
    iocs: list[IOC] = []
    for field_path, ioc_type in _STRUCTURED_FIELDS:
        value = _deep_get(raw, field_path)
        if not value: continue
        candidates = _split_hash_field(str(value)) if "hashes" in field_path else [str(value)]
        for candidate in candidates:
            candidate = candidate.strip()
            if not candidate: continue
            normalised = _normalise(ioc_type, candidate)
            if normalised and not _is_noise(ioc_type, normalised):
                iocs.append(IOC(ioc_type=ioc_type, value=normalised, source_field=field_path, confidence=0.95))
    return iocs


def _extract_from_text(text: str, source_field: str) -> list[IOC]:
    iocs: list[IOC] = []
    url_spans: list[tuple[int,int]] = []
    for m in _RE_URL.finditer(text):
        iocs.append(IOC(ioc_type=IOCType.URL, value=m.group(), source_field=source_field))
        url_spans.append(m.span())

    def _not_in_url(match: re.Match) -> bool:
        s, e = match.span()
        return not any(us <= s and e <= ue for us, ue in url_spans)

    for m in _RE_SHA256.finditer(text):
        iocs.append(IOC(ioc_type=IOCType.SHA256, value=m.group().lower(), source_field=source_field))
    for m in _RE_SHA1.finditer(text):
        iocs.append(IOC(ioc_type=IOCType.SHA1, value=m.group().lower(), source_field=source_field))
    for m in _RE_MD5.finditer(text):
        iocs.append(IOC(ioc_type=IOCType.MD5, value=m.group().lower(), source_field=source_field))
    for m in _RE_IPV4.finditer(text):
        if _not_in_url(m):
            ip = m.group()
            if not _is_noise(IOCType.IP_ADDRESS, ip):
                iocs.append(IOC(ioc_type=IOCType.IP_ADDRESS, value=ip, source_field=source_field))
    for m in _RE_EMAIL.finditer(text):
        iocs.append(IOC(ioc_type=IOCType.EMAIL, value=m.group().lower(), source_field=source_field))
    for m in _RE_CVE.finditer(text):
        iocs.append(IOC(ioc_type=IOCType.CVE, value=m.group().upper(), source_field=source_field))
    existing = {ioc.value for ioc in iocs}
    for m in _RE_DOMAIN.finditer(text):
        if _not_in_url(m):
            dom = m.group().lower()
            if dom not in existing and not _is_noise(IOCType.DOMAIN, dom):
                iocs.append(IOC(ioc_type=IOCType.DOMAIN, value=dom, source_field=source_field))
    for m in _RE_WINPATH.finditer(text):
        iocs.append(IOC(ioc_type=IOCType.FILE_PATH, value=m.group(), source_field=source_field))
    return iocs


def _deep_get(obj: dict[str,Any], path: str) -> Optional[str]:
    parts = path.split(".")
    current: Any = obj
    for part in parts:
        if not isinstance(current, dict): return None
        current = current.get(part)
    return str(current) if current is not None else None


def _split_hash_field(value: str) -> list[str]:
    if "=" in value:
        parts = []
        for seg in value.split(","):
            seg = seg.strip()
            parts.append(seg.split("=",1)[1] if "=" in seg else seg)
        return parts
    return [value]


def _normalise(ioc_type: str, value: str) -> str:
    if ioc_type in (IOCType.IP_ADDRESS, IOCType.DOMAIN, IOCType.URL, IOCType.EMAIL,
                    IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        return value.lower().strip()
    return value.strip()


def _is_noise(ioc_type: str, value: str) -> bool:
    if ioc_type == IOCType.IP_ADDRESS and value in _NOISE_IPS: return True
    if ioc_type == IOCType.DOMAIN and value.lower() in _NOISE_DOMS: return True
    if ioc_type == IOCType.DOMAIN and "." not in value: return True
    return False
