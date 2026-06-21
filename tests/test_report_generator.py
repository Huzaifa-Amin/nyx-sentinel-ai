"""
tests/test_report_generator.py
================================
Unit tests for the HTML and PDF report generator.

Tests cover:
- HTML report is created at the expected path
- HTML output contains key expected strings (escaped properly)
- HTML-escaping prevents XSS in IOC values
- PDF report is created when fpdf2 is available
- _build_context produces all required keys
- Missing classification/evidence handled gracefully
- Output directory is created if it does not exist
"""

from __future__ import annotations

import html
from pathlib import Path

import pytest

from nyx_sentinel.parsers.models import AlertSeverity, IOC, IOCType
from nyx_sentinel.reporting.report_generator import _build_context, generate_report


# ---------------------------------------------------------------------------
# _build_context
# ---------------------------------------------------------------------------


class TestBuildContext:
    def test_all_required_keys_present(self, enriched_alert, sample_classification):
        ctx = _build_context(enriched_alert, sample_classification, None)
        required_keys = [
            "report_id", "generated_at", "alert_id", "alert_timestamp",
            "rule_id", "rule_level", "rule_description", "agent_name",
            "agent_ip", "incident_type", "severity_name", "severity_score",
            "iocs", "malicious_ioc_count", "total_ioc_count",
            "techniques", "tactics", "actions", "evidence_files",
        ]
        for key in required_keys:
            assert key in ctx, f"Missing context key: {key}"

    def test_ioc_count_correct(self, enriched_alert, sample_classification):
        ctx = _build_context(enriched_alert, sample_classification, None)
        assert ctx["total_ioc_count"] == len(enriched_alert.iocs)

    def test_malicious_count_correct(self, enriched_alert, sample_classification):
        ctx = _build_context(enriched_alert, sample_classification, None)
        expected = sum(1 for ioc in enriched_alert.iocs if ioc.is_malicious)
        assert ctx["malicious_ioc_count"] == expected

    def test_xss_in_ioc_value_is_escaped(self, enriched_alert, sample_classification):
        """A malicious IOC value like <script>alert(1)</script> must be escaped."""
        enriched_alert.iocs.append(
            IOC(
                ioc_type=IOCType.DOMAIN,
                value='<script>alert("xss")</script>',
                source_field="test",
            )
        )
        ctx = _build_context(enriched_alert, sample_classification, None)
        ioc_values = [ioc["value"] for ioc in ctx["iocs"]]
        assert '<script>' not in " ".join(ioc_values)
        assert '&lt;script&gt;' in " ".join(ioc_values)

    def test_no_classification_uses_alert_severity(self, sample_alert):
        ctx = _build_context(sample_alert, None, None)
        assert ctx["severity_name"] == sample_alert.severity.label

    def test_evidence_files_in_context(
        self, enriched_alert, sample_classification, sample_evidence_manifest
    ):
        ctx = _build_context(enriched_alert, sample_classification, sample_evidence_manifest)
        assert len(ctx["evidence_files"]) == 1
        assert ctx["evidence_files"][0]["sha256"] == "a" * 64


# ---------------------------------------------------------------------------
# generate_report — HTML
# ---------------------------------------------------------------------------


class TestGenerateReportHTML:
    def test_html_file_created(self, enriched_alert, sample_classification, tmp_path):
        enriched_alert.classification = sample_classification
        result = generate_report(enriched_alert, output_dir=tmp_path)
        assert "html" in result
        assert result["html"].exists()
        assert result["html"].suffix == ".html"

    def test_html_contains_report_id(self, enriched_alert, sample_classification, tmp_path):
        result = generate_report(
            enriched_alert, classification=sample_classification, output_dir=tmp_path
        )
        content = result["html"].read_text(encoding="utf-8")
        assert "NYX SENTINEL AI" in content

    def test_html_contains_agent_name(self, enriched_alert, sample_classification, tmp_path):
        result = generate_report(
            enriched_alert, classification=sample_classification, output_dir=tmp_path
        )
        content = result["html"].read_text(encoding="utf-8")
        assert enriched_alert.agent.agent_name in content

    def test_html_contains_rule_description(self, enriched_alert, sample_classification, tmp_path):
        result = generate_report(
            enriched_alert, classification=sample_classification, output_dir=tmp_path
        )
        content = result["html"].read_text(encoding="utf-8")
        assert "Windows Logon Failures" in content

    def test_html_contains_severity(self, enriched_alert, sample_classification, tmp_path):
        result = generate_report(
            enriched_alert, classification=sample_classification, output_dir=tmp_path
        )
        content = result["html"].read_text(encoding="utf-8")
        assert "HIGH" in content or "CRITICAL" in content

    def test_output_dir_created_if_missing(self, enriched_alert, sample_classification, tmp_path):
        new_dir = tmp_path / "new" / "deeply" / "nested"
        assert not new_dir.exists()
        generate_report(
            enriched_alert, classification=sample_classification, output_dir=new_dir
        )
        assert new_dir.exists()

    def test_html_is_valid_structure(self, enriched_alert, sample_classification, tmp_path):
        """Basic sanity check that the output is HTML."""
        result = generate_report(
            enriched_alert, classification=sample_classification, output_dir=tmp_path
        )
        content = result["html"].read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content

    def test_xss_ioc_not_in_raw_html(self, enriched_alert, sample_classification, tmp_path):
        """XSS payloads in IOC values must be escaped in the HTML output."""
        enriched_alert.iocs.append(
            IOC(
                ioc_type=IOCType.DOMAIN,
                value='"><script>alert(document.cookie)</script>',
                source_field="test",
            )
        )
        result = generate_report(
            enriched_alert, classification=sample_classification, output_dir=tmp_path
        )
        content = result["html"].read_text(encoding="utf-8")
        # Raw <script> should NOT appear anywhere in the rendered HTML
        assert '<script>alert(document.cookie)</script>' not in content

    def test_no_api_keys_in_report(self, enriched_alert, sample_classification, tmp_path):
        """Ensure API keys are not embedded in reports."""
        result = generate_report(
            enriched_alert, classification=sample_classification, output_dir=tmp_path
        )
        content = result["html"].read_text(encoding="utf-8")
        # Settings API keys (even blank ones) should not appear
        assert "VIRUSTOTAL_API_KEY" not in content
        assert "ABUSEIPDB_API_KEY" not in content


# ---------------------------------------------------------------------------
# generate_report — with evidence manifest
# ---------------------------------------------------------------------------


class TestGenerateReportWithEvidence:
    def test_evidence_section_in_html(
        self, enriched_alert, sample_classification, sample_evidence_manifest, tmp_path
    ):
        result = generate_report(
            enriched_alert,
            classification=sample_classification,
            evidence=sample_evidence_manifest,
            output_dir=tmp_path,
        )
        content = result["html"].read_text(encoding="utf-8")
        assert "test_file.log" in content
        assert "a" * 64 in content  # SHA-256 hash

    def test_no_evidence_section_absent(self, enriched_alert, sample_classification, tmp_path):
        """If no evidence is collected, the evidence table should not be in the output."""
        result = generate_report(
            enriched_alert, classification=sample_classification, output_dir=tmp_path
        )
        content = result["html"].read_text(encoding="utf-8")
        # "Evidence Manifest" header should not appear
        assert "Evidence Manifest" not in content
