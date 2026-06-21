"""Forensic evidence collector with path-traversal prevention and SHA-256 hashing."""
from __future__ import annotations
import hashlib, json, re, shutil, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from loguru import logger
from nyx_sentinel.config.settings import settings
from nyx_sentinel.parsers.models import EvidenceFile, EvidenceManifest


def collect_evidence(incident_id: str, target_paths: list, staging_dir: Optional[Path] = None) -> EvidenceManifest:
    if not incident_id or not incident_id.strip():
        raise ValueError("incident_id must not be empty.")
    safe_id = _sanitise_incident_id(incident_id)
    base = (staging_dir or settings.evidence_base_dir) / safe_id
    base.mkdir(parents=True, exist_ok=True)
    manifest = EvidenceManifest(incident_id=safe_id, collected_at=datetime.now(timezone.utc))
    for raw_path in target_paths:
        result = _collect_single_file(Path(raw_path), base)
        if result.error:
            manifest.collection_errors.append(f"{raw_path}: {result.error}")
            logger.warning("Evidence collection error for '{}': {}", raw_path, result.error)
        else:
            manifest.files.append(result)
            manifest.total_size_bytes += result.size_bytes
            logger.info("Collected '{}' sha256={}...", result.original_path, result.sha256[:16])
    manifest.total_files = len(manifest.files)
    manifest_path = base / "manifest.json"
    manifest_path.write_text(json.dumps(manifest.model_dump(mode="json"), indent=2, default=str), encoding="utf-8")
    logger.info("Manifest written to '{}'. Files: {} Errors: {}", manifest_path, manifest.total_files, len(manifest.collection_errors))
    return manifest


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(manifest_path: Path) -> EvidenceManifest:
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    return EvidenceManifest.model_validate(json.loads(manifest_path.read_text(encoding="utf-8")))


def verify_evidence_integrity(manifest: EvidenceManifest) -> dict[str, bool]:
    results: dict[str, bool] = {}
    for ef in manifest.files:
        collected = Path(ef.collected_path)
        if not collected.exists():
            logger.warning("Evidence file missing: {}", collected)
            results[str(collected)] = False
            continue
        actual = hash_file(collected)
        intact = actual == ef.sha256
        if not intact:
            logger.error("INTEGRITY FAILURE: '{}' expected={} got={}", collected, ef.sha256, actual)
        results[str(collected)] = intact
    return results


def _collect_single_file(source: Path, staging_dir: Path) -> EvidenceFile:
    original_path = str(source)
    try:
        resolved = source.resolve(strict=False)
    except (OSError, ValueError) as exc:
        return EvidenceFile(file_name=source.name, original_path=original_path,
                            collected_path="", sha256="", size_bytes=0, error=f"Path resolution failed: {exc}")
    if not _is_path_allowed(resolved):
        return EvidenceFile(file_name=source.name, original_path=original_path,
                            collected_path="", sha256="", size_bytes=0,
                            error=f"Path '{resolved}' is outside the approved evidence directories.")
    if not resolved.exists():
        return EvidenceFile(file_name=source.name, original_path=original_path,
                            collected_path="", sha256="", size_bytes=0, error="File does not exist.")
    if not resolved.is_file():
        return EvidenceFile(file_name=source.name, original_path=original_path,
                            collected_path="", sha256="", size_bytes=0, error="Target is not a regular file.")
    size_bytes = resolved.stat().st_size
    max_bytes = settings.max_file_size_mb * 1_024 * 1_024
    if size_bytes > max_bytes:
        return EvidenceFile(file_name=source.name, original_path=original_path,
                            collected_path="", sha256="", size_bytes=size_bytes,
                            error=f"File size {size_bytes:,} bytes exceeds {settings.max_file_size_mb} MB limit.")
    dest_name = f"{uuid.uuid4().hex[:8]}_{resolved.name}"
    dest = staging_dir / dest_name
    try:
        shutil.copy2(str(resolved), str(dest))
    except (OSError, shutil.Error) as exc:
        return EvidenceFile(file_name=source.name, original_path=original_path,
                            collected_path="", sha256="", size_bytes=size_bytes, error=f"Copy failed: {exc}")
    try:
        sha256 = hash_file(dest)
    except OSError as exc:
        return EvidenceFile(file_name=source.name, original_path=original_path,
                            collected_path=str(dest), sha256="", size_bytes=size_bytes, error=f"Hash failed: {exc}")
    return EvidenceFile(file_name=dest_name, original_path=original_path,
                        collected_path=str(dest), sha256=sha256,
                        size_bytes=size_bytes, collected_at=datetime.now(timezone.utc))


def _is_path_allowed(resolved: Path) -> bool:
    for allowed in settings.allowed_evidence_dirs:
        try:
            resolved.relative_to(Path(allowed))
            return True
        except ValueError:
            pass
        if str(resolved).lower().startswith(str(allowed).lower()):
            return True
    return False


def _sanitise_incident_id(incident_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "_", incident_id.strip())
    if not safe:
        raise ValueError(f"incident_id '{incident_id}' produced an empty safe name.")
    return safe
