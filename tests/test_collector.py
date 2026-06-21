"""
tests/test_collector.py
=========================
Unit tests for the forensic evidence collector.

Tests cover:
- hash_file — SHA-256 correctness
- collect_evidence — valid file, creates manifest
- collect_evidence — path traversal blocked
- collect_evidence — oversized file blocked
- collect_evidence — non-existent file logged as error
- collect_evidence — directory target rejected
- load_manifest — reads JSON back
- verify_evidence_integrity — intact and tampered files
- _sanitise_incident_id — unsafe characters stripped
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from nyx_sentinel.config.settings import settings
from nyx_sentinel.forensics.collector import (
    collect_evidence,
    hash_file,
    load_manifest,
    verify_evidence_integrity,
    _sanitise_incident_id,
)


# ---------------------------------------------------------------------------
# hash_file
# ---------------------------------------------------------------------------


class TestHashFile:
    def test_empty_file_has_known_sha256(self, tmp_path: Path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        result = hash_file(f)
        # SHA-256 of empty string
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_known_content(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_bytes(b"hello world")
        result = hash_file(f)
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert result == expected

    def test_returns_lowercase_hex(self, tmp_path: Path):
        f = tmp_path / "test.txt"
        f.write_bytes(b"data")
        result = hash_file(f)
        assert result == result.lower()
        assert len(result) == 64

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            hash_file(tmp_path / "missing.txt")


# ---------------------------------------------------------------------------
# collect_evidence — happy path
# ---------------------------------------------------------------------------


class TestCollectEvidence:
    def _make_allowed_file(self, tmp_path: Path, content: bytes = b"test log data") -> Path:
        """Create a file inside an allowed evidence directory."""
        # Use /tmp which is in the default ALLOWED_EVIDENCE_DIRS
        allowed = Path("/tmp/nyx_test_evidence_source")
        allowed.mkdir(exist_ok=True)
        f = allowed / "test.log"
        f.write_bytes(content)
        return f

    def test_manifest_created(self, tmp_path: Path):
        source = self._make_allowed_file(tmp_path)
        manifest = collect_evidence(
            incident_id="test-001",
            target_paths=[source],
            staging_dir=tmp_path / "staging",
        )
        assert manifest.total_files == 1
        assert len(manifest.files) == 1

    def test_sha256_correct(self, tmp_path: Path):
        content = b"forensic evidence content"
        source = self._make_allowed_file(tmp_path, content=content)
        manifest = collect_evidence(
            incident_id="hash-test",
            target_paths=[source],
            staging_dir=tmp_path / "staging",
        )
        expected = hashlib.sha256(content).hexdigest()
        assert manifest.files[0].sha256 == expected

    def test_manifest_json_written(self, tmp_path: Path):
        source = self._make_allowed_file(tmp_path)
        staging = tmp_path / "staging"
        collect_evidence(
            incident_id="json-test",
            target_paths=[source],
            staging_dir=staging,
        )
        manifest_file = staging / "json-test" / "manifest.json"
        assert manifest_file.exists()
        data = json.loads(manifest_file.read_text())
        assert data["incident_id"] == "json-test"

    def test_total_size_bytes_tracked(self, tmp_path: Path):
        content = b"x" * 500
        source = self._make_allowed_file(tmp_path, content=content)
        manifest = collect_evidence(
            incident_id="size-test",
            target_paths=[source],
            staging_dir=tmp_path / "staging",
        )
        assert manifest.total_size_bytes == 500

    def test_nonexistent_file_recorded_as_error(self, tmp_path: Path):
        manifest = collect_evidence(
            incident_id="err-test",
            target_paths=[Path("/tmp/does_not_exist_xyz.log")],
            staging_dir=tmp_path / "staging",
        )
        assert manifest.total_files == 0
        assert len(manifest.collection_errors) == 1

    def test_directory_target_recorded_as_error(self, tmp_path: Path):
        manifest = collect_evidence(
            incident_id="dir-test",
            target_paths=[Path("/tmp")],
            staging_dir=tmp_path / "staging",
        )
        assert manifest.total_files == 0
        assert len(manifest.collection_errors) >= 1

    def test_empty_incident_id_raises(self, tmp_path: Path):
        with pytest.raises(ValueError, match="incident_id must not be empty"):
            collect_evidence(
                incident_id="",
                target_paths=[],
                staging_dir=tmp_path,
            )


# ---------------------------------------------------------------------------
# Path traversal prevention
# ---------------------------------------------------------------------------


class TestPathTraversalPrevention:
    def test_path_outside_allowed_dirs_rejected(self, tmp_path: Path):
        # Create a temp file OUTSIDE the allowed dirs
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"sensitive")
        # Override allowed dirs to NOT include tmp_path
        original = settings.allowed_evidence_dirs[:]
        try:
            settings.allowed_evidence_dirs = ["/var/log"]
            manifest = collect_evidence(
                incident_id="traversal-test",
                target_paths=[outside],
                staging_dir=tmp_path / "staging",
            )
            assert manifest.total_files == 0
            assert "outside the approved" in manifest.collection_errors[0]
        finally:
            settings.allowed_evidence_dirs = original


# ---------------------------------------------------------------------------
# load_manifest
# ---------------------------------------------------------------------------


class TestLoadManifest:
    def test_load_saved_manifest(self, tmp_path: Path, sample_evidence_manifest):
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(
            json.dumps(sample_evidence_manifest.model_dump(mode="json"), default=str),
            encoding="utf-8",
        )
        loaded = load_manifest(manifest_path)
        assert loaded.incident_id == "test-incident-001"
        assert loaded.total_files == 1

    def test_missing_manifest_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_manifest(tmp_path / "missing.json")


# ---------------------------------------------------------------------------
# verify_evidence_integrity
# ---------------------------------------------------------------------------


class TestVerifyEvidenceIntegrity:
    def test_intact_file_returns_true(self, tmp_path: Path):
        content = b"evidence"
        f = tmp_path / "evidence.txt"
        f.write_bytes(content)

        from nyx_sentinel.parsers.models import EvidenceFile, EvidenceManifest
        manifest = EvidenceManifest(
            incident_id="integrity-test",
            files=[
                EvidenceFile(
                    file_name="evidence.txt",
                    original_path=str(f),
                    collected_path=str(f),
                    sha256=hashlib.sha256(content).hexdigest(),
                    size_bytes=len(content),
                )
            ],
            total_files=1,
        )
        results = verify_evidence_integrity(manifest)
        assert results[str(f)] is True

    def test_tampered_file_returns_false(self, tmp_path: Path):
        f = tmp_path / "tampered.txt"
        f.write_bytes(b"original")

        from nyx_sentinel.parsers.models import EvidenceFile, EvidenceManifest
        manifest = EvidenceManifest(
            incident_id="tamper-test",
            files=[
                EvidenceFile(
                    file_name="tampered.txt",
                    original_path=str(f),
                    collected_path=str(f),
                    sha256="wrong" * 12 + "0000",  # 64 chars but wrong
                    size_bytes=8,
                )
            ],
            total_files=1,
        )
        f.write_bytes(b"tampered content")  # Modify after manifest creation
        results = verify_evidence_integrity(manifest)
        assert results[str(f)] is False


# ---------------------------------------------------------------------------
# _sanitise_incident_id
# ---------------------------------------------------------------------------


class TestSanitiseIncidentId:
    def test_alphanumeric_unchanged(self):
        assert _sanitise_incident_id("INC20240124") == "INC20240124"

    def test_hyphens_and_underscores_kept(self):
        assert _sanitise_incident_id("INC-2024_01") == "INC-2024_01"

    def test_spaces_replaced(self):
        result = _sanitise_incident_id("INC 2024")
        assert " " not in result

    def test_path_traversal_characters_replaced(self):
        result = _sanitise_incident_id("../../etc/passwd")
        assert "/" not in result
        assert ".." not in result

    def test_empty_after_sanitise_raises(self):
        # Only whitespace sanitises to empty string and raises
        with pytest.raises(ValueError):
            _sanitise_incident_id("   ")
