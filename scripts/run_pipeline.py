#!/usr/bin/env python3
"""
scripts/run_pipeline.py
========================
NYX SENTINEL AI — Full Pipeline Runner

Runs all pipeline stages in sequence for one or more alert files:
  1. Parse        — Load and validate raw Wazuh JSON alerts
  2. Extract      — Pull IOCs from each alert
  3. Enrich       — Query VirusTotal + AbuseIPDB (or use stub mode)
  4. Classify     — MITRE ATT&CK mapping and severity scoring
  5. Evidence     — (Optional) Collect forensic artifacts
  6. Report       — Generate HTML + PDF incident reports

Usage
-----
    python scripts/run_pipeline.py data/sample_alerts/brute_force_alert.json
    python scripts/run_pipeline.py data/sample_alerts/ --stub
    python scripts/run_pipeline.py data/sample_alerts/brute_force_alert.json \\
        --evidence /var/log/auth.log --output /tmp/my_reports
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure src/ is on the Python path when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from nyx_sentinel.parsers.alert_parser import parse_alerts_from_file
from nyx_sentinel.extractors.ioc_extractor import extract_iocs
from nyx_sentinel.enrichment.threat_intel import enrich_iocs_stub, enrich_iocs_sync
from nyx_sentinel.analysis.incident_classifier import classify_incident
from nyx_sentinel.forensics.collector import collect_evidence
from nyx_sentinel.reporting.report_generator import generate_report
from nyx_sentinel.config.settings import settings


console = Console()


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nyx-sentinel-pipeline",
        description="NYX SENTINEL AI — Full SOC/DFIR Pipeline Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "alert_paths",
        nargs="+",
        type=Path,
        help="One or more Wazuh JSON alert files or directories containing them.",
    )
    parser.add_argument(
        "--stub",
        action="store_true",
        default=False,
        help="Use stub enrichment (no real API calls). Safe for demos.",
    )
    parser.add_argument(
        "--evidence",
        nargs="*",
        type=Path,
        default=[],
        help="File path(s) to collect as forensic evidence.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=settings.reports_dir,
        help=f"Output directory for reports. Default: {settings.reports_dir}",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress progress output.",
    )
    return parser


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(args: argparse.Namespace) -> int:
    """Execute the full pipeline. Returns 0 on success, 1 on failure."""

    _print_banner()

    # Collect all alert files
    alert_files: list[Path] = []
    for path in args.alert_paths:
        if path.is_dir():
            alert_files.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            alert_files.append(path)
        else:
            console.print(f"[yellow]Warning: '{path}' not found — skipping.[/yellow]")

    if not alert_files:
        console.print("[red]Error: No valid alert files found.[/red]")
        return 1

    console.print(f"\n[cyan]Found {len(alert_files)} alert file(s) to process.[/cyan]\n")
    all_reports: list[dict[str, Path]] = []

    for alert_file in alert_files:
        console.rule(f"[bold cyan]{alert_file.name}[/bold cyan]")
        _process_alert_file(alert_file, args, all_reports)

    # Summary
    _print_summary(all_reports)
    return 0


def _process_alert_file(
    alert_file: Path,
    args: argparse.Namespace,
    all_reports: list,
) -> None:
    """Process one alert file through all pipeline stages."""

    # ── Stage 1: Parse ─────────────────────────────────────────────────────
    _stage("1/6", "Parsing alerts", alert_file.name)
    try:
        alerts = parse_alerts_from_file(alert_file)
    except Exception as exc:
        console.print(f"  [red]Parse failed: {exc}[/red]")
        return

    if not alerts:
        console.print("  [yellow]No valid alerts parsed — skipping file.[/yellow]")
        return

    for alert in alerts:
        console.print(
            f"  ✔ Alert [bold]{alert.alert_id}[/bold] — "
            f"{alert.rule.description[:60]}... "
            f"[{alert.severity.label}]"
        )

    for alert in alerts:
        console.print(f"\n  Processing alert [bold]{alert.alert_id}[/bold]")

        # ── Stage 2: Extract IOCs ───────────────────────────────────────────
        _stage("2/6", "Extracting IOCs")
        alert.iocs = extract_iocs(alert)
        console.print(f"  ✔ {len(alert.iocs)} IOC(s) extracted")

        # ── Stage 3: Enrich ─────────────────────────────────────────────────
        _stage("3/6", "Enriching IOCs", "stub mode" if args.stub else "live APIs")
        if args.stub:
            alert.iocs = enrich_iocs_stub(alert.iocs)
        else:
            if not (settings.virustotal_api_key or settings.abuseipdb_api_key):
                console.print(
                    "  [yellow]⚠ No API keys configured. Switching to stub mode.[/yellow]"
                )
                alert.iocs = enrich_iocs_stub(alert.iocs)
            else:
                alert.iocs = enrich_iocs_sync(alert.iocs)
        malicious = sum(1 for ioc in alert.iocs if ioc.is_malicious)
        console.print(f"  ✔ {malicious} IOC(s) flagged as malicious")

        # ── Stage 4: Classify ────────────────────────────────────────────────
        _stage("4/6", "Classifying incident")
        alert.classification = classify_incident(alert)
        clf = alert.classification
        console.print(
            f"  ✔ [{clf.severity.label}] {clf.incident_type} "
            f"— Score: {clf.severity_score:.0f}/100"
        )
        if clf.mitre_techniques:
            console.print(f"  ✔ MITRE: {', '.join(clf.mitre_techniques[:4])}")

        # ── Stage 5: Evidence ────────────────────────────────────────────────
        _stage("5/6", "Collecting evidence")
        if args.evidence:
            try:
                alert.evidence = collect_evidence(
                    incident_id=clf.incident_id,
                    target_paths=args.evidence,
                )
                console.print(f"  ✔ {alert.evidence.total_files} evidence file(s) collected")
            except Exception as exc:
                console.print(f"  [yellow]Evidence collection error: {exc}[/yellow]")
        else:
            console.print("  ℹ No evidence paths specified — skipping collection")

        # ── Stage 6: Report ──────────────────────────────────────────────────
        _stage("6/6", "Generating reports")
        try:
            report_paths = generate_report(alert, output_dir=args.output)
            all_reports.append(report_paths)
            console.print(f"  ✔ HTML report → {report_paths['html']}")
            if "pdf" in report_paths:
                console.print(f"  ✔ PDF report  → {report_paths['pdf']}")
        except Exception as exc:
            console.print(f"  [red]Report generation failed: {exc}[/red]")


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _print_banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]NYX SENTINEL AI[/bold cyan]\n"
            "[dim]AI-Enhanced SOC & Digital Forensics Incident Response Platform[/dim]",
            border_style="cyan",
        )
    )


def _stage(step: str, description: str, detail: str = "") -> None:
    detail_str = f" [dim]({detail})[/dim]" if detail else ""
    console.print(f"\n  [bold cyan][{step}][/bold cyan] {description}{detail_str}")


def _print_summary(all_reports: list[dict[str, Path]]) -> None:
    console.rule("[bold green]Pipeline Complete[/bold green]")

    if not all_reports:
        console.print("[yellow]No reports were generated.[/yellow]")
        return

    table = Table(
        title="Generated Reports",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#", width=4)
    table.add_column("HTML Report", style="green")
    table.add_column("PDF Report", style="blue")

    for i, report in enumerate(all_reports, 1):
        html_path = str(report.get("html", "—"))
        pdf_path = str(report.get("pdf", "—"))
        table.add_row(str(i), html_path, pdf_path)

    console.print(table)
    console.print(
        f"\n[bold green]✔ {len(all_reports)} report(s) generated successfully.[/bold green]"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = build_arg_parser()
    parsed_args = parser.parse_args()
    sys.exit(run_pipeline(parsed_args))
