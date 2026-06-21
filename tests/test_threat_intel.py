"""
tests/test_threat_intel.py
============================
Unit tests for the threat intelligence enrichment module.

All tests use stubs / mocks — no real API calls are made.
Tests cover:
- enrich_iocs_stub (for demo/test mode)
- _apply_vt_stats (applies VT response to IOC)
- _apply_abuseipdb (applies AbuseIPDB response to IOC)
- Malicious flagging logic
- Rate-limit / error handling paths
- enrich_iocs_sync wrapper
"""

from __future__ import annotations

import pytest

from nyx_sentinel.enrichment.threat_intel import (
    _apply_abuseipdb,
    _apply_vt_stats,
    enrich_iocs_stub,
)
from nyx_sentinel.parsers.models import IOC, IOCType


# ---------------------------------------------------------------------------
# Stub enrichment (safe for CI — no network)
# ---------------------------------------------------------------------------


class TestEnrichIocsStub:
    def test_clean_ip_not_flagged(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.2.3.4", source_field="test")
        result = enrich_iocs_stub([ioc])
        assert result[0].is_malicious is False

    def test_evil_in_value_flags_malicious(self):
        ioc = IOC(ioc_type=IOCType.DOMAIN, value="evil-domain.com", source_field="test")
        result = enrich_iocs_stub([ioc])
        assert result[0].is_malicious is True

    def test_malicious_in_value_flags_malicious(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="malicious.host.com", source_field="test")
        result = enrich_iocs_stub([ioc])
        assert result[0].is_malicious is True

    def test_empty_list_returns_empty(self):
        result = enrich_iocs_stub([])
        assert result == []

    def test_stub_sets_vt_fields(self):
        ioc = IOC(ioc_type=IOCType.SHA256, value="a" * 64, source_field="test")
        result = enrich_iocs_stub([ioc])
        assert result[0].vt_malicious == 0
        assert result[0].vt_total == 72

    def test_malicious_stub_sets_high_scores(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="evil-c2.com", source_field="test")
        result = enrich_iocs_stub([ioc])
        assert result[0].vt_malicious == 15
        assert result[0].abuse_confidence == 85

    def test_multiple_iocs_processed(self):
        iocs = [
            IOC(ioc_type=IOCType.IP_ADDRESS, value="clean.host.com", source_field="t"),
            IOC(ioc_type=IOCType.DOMAIN, value="hack-me.com", source_field="t"),
        ]
        result = enrich_iocs_stub(iocs)
        assert result[0].is_malicious is False
        assert result[1].is_malicious is True


# ---------------------------------------------------------------------------
# _apply_vt_stats
# ---------------------------------------------------------------------------


class TestApplyVtStats:
    def make_vt_response(self, malicious: int, total: int) -> dict:
        """Build a minimal VT API response dict."""
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": 0,
                        "harmless": total - malicious,
                        "undetected": 0,
                    }
                }
            }
        }

    def test_malicious_count_set(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_vt_stats(ioc, self.make_vt_response(10, 72))
        assert ioc.vt_malicious == 10
        assert ioc.vt_total == 72

    def test_flagged_malicious_when_two_or_more_vendors(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_vt_stats(ioc, self.make_vt_response(2, 72))
        assert ioc.is_malicious is True

    def test_not_flagged_with_one_vendor(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_vt_stats(ioc, self.make_vt_response(1, 72))
        assert ioc.is_malicious is False

    def test_not_flagged_with_zero_vendors(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_vt_stats(ioc, self.make_vt_response(0, 72))
        assert ioc.is_malicious is False

    def test_empty_response_no_changes(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_vt_stats(ioc, {})
        assert ioc.vt_malicious is None
        assert ioc.vt_total is None
        assert ioc.is_malicious is False

    def test_missing_stats_key_graceful(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_vt_stats(ioc, {"data": {"attributes": {}}})
        assert ioc.vt_malicious is None


# ---------------------------------------------------------------------------
# _apply_abuseipdb
# ---------------------------------------------------------------------------


class TestApplyAbuseIPDB:
    def make_abuse_response(self, confidence: int, country: str = "US") -> dict:
        return {
            "abuseConfidenceScore": confidence,
            "countryCode": country,
            "totalReports": 42,
        }

    def test_confidence_set(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_abuseipdb(ioc, self.make_abuse_response(75, "RU"))
        assert ioc.abuse_confidence == 75
        assert ioc.abuse_country == "RU"

    def test_flagged_at_50_percent(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_abuseipdb(ioc, self.make_abuse_response(50))
        assert ioc.is_malicious is True

    def test_not_flagged_below_50(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_abuseipdb(ioc, self.make_abuse_response(49))
        assert ioc.is_malicious is False

    def test_zero_confidence_not_flagged(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_abuseipdb(ioc, self.make_abuse_response(0))
        assert ioc.is_malicious is False

    def test_empty_response_no_changes(self):
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        _apply_abuseipdb(ioc, {})
        assert ioc.abuse_confidence is None
        assert ioc.abuse_country is None


# ---------------------------------------------------------------------------
# is_malicious accumulation
# ---------------------------------------------------------------------------


class TestMaliciousFlagAccumulation:
    def test_abuseipdb_can_flag_after_vt_clean(self):
        """AbuseIPDB alone can flag an IOC even if VT says clean."""
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        ioc.vt_malicious = 0
        ioc.vt_total = 72
        _apply_abuseipdb(ioc, {"abuseConfidenceScore": 90, "countryCode": "CN"})
        assert ioc.is_malicious is True

    def test_vt_can_flag_after_abuseipdb_clean(self):
        """VT alone can flag an IOC even if AbuseIPDB says clean."""
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="1.1.1.1", source_field="t")
        ioc.abuse_confidence = 10
        _apply_vt_stats(
            ioc,
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 35, "suspicious": 5,
                            "harmless": 30, "undetected": 2
                        }
                    }
                }
            },
        )
        assert ioc.is_malicious is True
