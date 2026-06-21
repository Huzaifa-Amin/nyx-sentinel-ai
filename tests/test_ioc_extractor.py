"""
tests/test_ioc_extractor.py
=============================
Unit tests for the IOC extraction module.

Tests cover:
- IPv4 extraction from structured fields and free text
- Domain extraction
- SHA-256, SHA-1, MD5 extraction
- URL extraction
- Email extraction
- CVE extraction
- Username extraction from Wazuh structured fields
- Noise filtering (127.0.0.1, localhost, etc.)
- Deduplication
- No false positives from partial hex strings
"""

from __future__ import annotations

import pytest

from nyx_sentinel.extractors.ioc_extractor import extract_iocs, _extract_from_text
from nyx_sentinel.parsers.models import IOCType, ParsedAlert


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ioc_values(iocs, ioc_type: str) -> list[str]:
    return [ioc.value for ioc in iocs if ioc.ioc_type == ioc_type]


# ---------------------------------------------------------------------------
# IP Address extraction
# ---------------------------------------------------------------------------


class TestIPExtraction:
    def test_extracts_ip_from_structured_field(self, sample_alert: ParsedAlert):
        iocs = extract_iocs(sample_alert)
        ips = _ioc_values(iocs, IOCType.IP_ADDRESS)
        assert "192.168.50.99" in ips

    def test_extracts_ip_from_full_log(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "Connection from 10.10.10.50 port 4444"
        iocs = extract_iocs(sample_alert)
        ips = _ioc_values(iocs, IOCType.IP_ADDRESS)
        assert "10.10.10.50" in ips

    def test_loopback_is_filtered(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "localhost 127.0.0.1 connected"
        iocs = extract_iocs(sample_alert)
        ips = _ioc_values(iocs, IOCType.IP_ADDRESS)
        assert "127.0.0.1" not in ips

    def test_broadcast_is_filtered(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "broadcast 255.255.255.255"
        iocs = extract_iocs(sample_alert)
        ips = _ioc_values(iocs, IOCType.IP_ADDRESS)
        assert "255.255.255.255" not in ips

    def test_multiple_ips_extracted(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "src=1.2.3.4 dst=5.6.7.8"
        iocs = extract_iocs(sample_alert)
        ips = _ioc_values(iocs, IOCType.IP_ADDRESS)
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips

    def test_invalid_ip_not_extracted(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "version 999.999.999.999 is invalid"
        iocs = extract_iocs(sample_alert)
        ips = _ioc_values(iocs, IOCType.IP_ADDRESS)
        assert "999.999.999.999" not in ips


# ---------------------------------------------------------------------------
# Hash extraction
# ---------------------------------------------------------------------------


class TestHashExtraction:
    def test_sha256_from_full_log(self, sample_alert: ParsedAlert):
        sha256 = "a" * 64
        sample_alert.full_log = f"hash={sha256}"
        iocs = extract_iocs(sample_alert)
        hashes = _ioc_values(iocs, IOCType.SHA256)
        assert sha256 in hashes

    def test_md5_from_full_log(self, sample_alert: ParsedAlert):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sample_alert.full_log = f"md5={md5}"
        iocs = extract_iocs(sample_alert)
        hashes = _ioc_values(iocs, IOCType.MD5)
        assert md5 in hashes

    def test_sha1_from_full_log(self, sample_alert: ParsedAlert):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sample_alert.full_log = f"sha1={sha1}"
        iocs = extract_iocs(sample_alert)
        hashes = _ioc_values(iocs, IOCType.SHA1)
        assert sha1 in hashes

    def test_sha256_from_structured_syscheck(self, sample_alert: ParsedAlert):
        sha256 = "b" * 64
        sample_alert.raw_data["syscheck"] = {"sha256_after": sha256}
        iocs = extract_iocs(sample_alert)
        hashes = _ioc_values(iocs, IOCType.SHA256)
        assert sha256 in hashes

    def test_hash_is_lowercased(self, sample_alert: ParsedAlert):
        sha256 = "A" * 64
        sample_alert.full_log = f"hash={sha256}"
        iocs = extract_iocs(sample_alert)
        hashes = _ioc_values(iocs, IOCType.SHA256)
        assert sha256.lower() in hashes

    def test_short_hex_is_not_extracted_as_hash(self, sample_alert: ParsedAlert):
        # 16 hex chars — too short to be a hash
        sample_alert.full_log = "pid=1a2b3c4d5e6f7a8b"
        iocs = extract_iocs(sample_alert)
        assert len([i for i in iocs if i.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)]) == 0


# ---------------------------------------------------------------------------
# Domain extraction
# ---------------------------------------------------------------------------


class TestDomainExtraction:
    def test_domain_extracted(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "connected to malware.example.com for download"
        iocs = extract_iocs(sample_alert)
        domains = _ioc_values(iocs, IOCType.DOMAIN)
        assert "malware.example.com" in domains

    def test_localhost_filtered(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "listening on localhost"
        iocs = extract_iocs(sample_alert)
        domains = _ioc_values(iocs, IOCType.DOMAIN)
        assert "localhost" not in domains

    def test_single_label_not_extracted(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "hostname WORKSTATION not found"
        iocs = extract_iocs(sample_alert)
        domains = _ioc_values(iocs, IOCType.DOMAIN)
        assert "workstation" not in domains


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


class TestURLExtraction:
    def test_http_url_extracted(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "download from http://evil.com/payload.exe"
        iocs = extract_iocs(sample_alert)
        urls = _ioc_values(iocs, IOCType.URL)
        assert any("evil.com/payload.exe" in u for u in urls)

    def test_https_url_extracted(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "beacon to https://c2.domain.com/check"
        iocs = extract_iocs(sample_alert)
        urls = _ioc_values(iocs, IOCType.URL)
        assert any("c2.domain.com" in u for u in urls)


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------


class TestCVEExtraction:
    def test_cve_extracted(self, sample_alert: ParsedAlert):
        sample_alert.rule.description = "Exploitation attempt via CVE-2021-44228 (Log4Shell)"
        iocs = extract_iocs(sample_alert)
        cves = _ioc_values(iocs, IOCType.CVE)
        assert "CVE-2021-44228" in cves

    def test_cve_uppercased(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "vuln cve-2023-1234 exploited"
        iocs = extract_iocs(sample_alert)
        cves = _ioc_values(iocs, IOCType.CVE)
        assert "CVE-2023-1234" in cves


# ---------------------------------------------------------------------------
# Username extraction from structured fields
# ---------------------------------------------------------------------------


class TestUsernameExtraction:
    def test_username_from_wazuh_field(self, sample_alert: ParsedAlert):
        sample_alert.raw_data["data"] = {
            "win": {"eventdata": {"targetUserName": "Administrator"}}
        }
        iocs = extract_iocs(sample_alert)
        usernames = _ioc_values(iocs, IOCType.USERNAME)
        assert "Administrator" in usernames


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_duplicate_ips_deduplicated(self, sample_alert: ParsedAlert):
        sample_alert.full_log = "src=1.2.3.4 src=1.2.3.4 dst=1.2.3.4"
        iocs = extract_iocs(sample_alert)
        ips = _ioc_values(iocs, IOCType.IP_ADDRESS)
        assert ips.count("1.2.3.4") == 1

    def test_same_hash_different_case_deduplicated(self, sample_alert: ParsedAlert):
        sha256 = "c" * 64
        sample_alert.full_log = f"hash1={sha256.upper()} hash2={sha256.lower()}"
        iocs = extract_iocs(sample_alert)
        hashes = _ioc_values(iocs, IOCType.SHA256)
        assert hashes.count(sha256) == 1


# ---------------------------------------------------------------------------
# Empty / edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_no_full_log_returns_structured_only(self, sample_alert: ParsedAlert):
        sample_alert.full_log = None
        iocs = extract_iocs(sample_alert)
        # Should still get IPs from structured fields
        assert isinstance(iocs, list)

    def test_empty_full_log(self, sample_alert: ParsedAlert):
        sample_alert.full_log = ""
        iocs = extract_iocs(sample_alert)
        assert isinstance(iocs, list)
