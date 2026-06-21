"""HTML and PDF report generation (Jinja2 + fpdf2). XSS-safe — all values escaped."""
from __future__ import annotations
import html as html_module
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4
from jinja2 import Environment, FileSystemLoader, select_autoescape
from loguru import logger
from nyx_sentinel.config.settings import settings
from nyx_sentinel.parsers.models import EvidenceManifest, IncidentClassification, ParsedAlert

try:
    from fpdf import FPDF
    _FPDF_AVAILABLE = True
except ImportError:
    _FPDF_AVAILABLE = False
    logger.warning("fpdf2 not installed — PDF generation skipped.")


def generate_report(alert: ParsedAlert, classification: Optional[IncidentClassification] = None,
                    evidence: Optional[EvidenceManifest] = None, output_dir: Optional[Path] = None) -> dict[str,Path]:
    clf = classification or alert.classification
    evi = evidence or alert.evidence
    out_dir = (output_dir or settings.reports_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    ctx = _build_context(alert, clf, evi)
    html_path = out_dir / f"incident_{ctx['report_id']}.html"
    _write_html(ctx, html_path)
    result: dict[str, Path] = {"html": html_path}
    if _FPDF_AVAILABLE:
        pdf_path = out_dir / f"incident_{ctx['report_id']}.pdf"
        _write_pdf(ctx, pdf_path)
        result["pdf"] = pdf_path
    logger.info("Report generated: {}", html_path)
    return result


def _build_context(alert: ParsedAlert, clf: Optional[IncidentClassification],
                   evi: Optional[EvidenceManifest]) -> dict:
    report_id = str(uuid4())[:8].upper()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    iocs_data = []
    for ioc in alert.iocs[:settings.report_max_iocs]:
        iocs_data.append({"type":_esc(ioc.ioc_type),"value":_esc(ioc.value),"source":_esc(ioc.source_field),
                          "vt_malicious":ioc.vt_malicious,"vt_total":ioc.vt_total,
                          "abuse_confidence":ioc.abuse_confidence,"abuse_country":_esc(ioc.abuse_country or "-"),
                          "is_malicious":ioc.is_malicious,"enrichment_error":_esc(ioc.enrichment_error or "")})
    evidence_data = []
    if evi:
        for f in evi.files:
            evidence_data.append({"file_name":_esc(f.file_name),"original_path":_esc(f.original_path),
                                  "sha256":_esc(f.sha256),"size_kb":round(f.size_bytes/1024,2),
                                  "collected_at":f.collected_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                  "error":_esc(f.error or "")})
    actions=[]; techniques=[]; tactics=[]; incident_type="Unknown"
    severity_name=alert.severity.label; severity_score=0
    severity_css=alert.severity.css_class; summary=""; confidence=0
    if clf:
        actions=[_esc(a) for a in clf.recommended_actions]
        techniques=[_esc(t) for t in clf.mitre_techniques]
        tactics=[_esc(t) for t in clf.mitre_tactics]
        incident_type=_esc(clf.incident_type); severity_name=clf.severity.label
        severity_score=clf.severity_score; severity_css=clf.severity.css_class
        summary=_esc(clf.summary); confidence=int(clf.confidence*100)
    return {"report_id":report_id,"generated_at":generated_at,"alert_id":_esc(alert.alert_id),
            "alert_timestamp":alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "rule_id":_esc(alert.rule.rule_id),"rule_level":alert.rule.level,
            "rule_description":_esc(alert.rule.description),"rule_groups":[_esc(g) for g in alert.rule.groups],
            "agent_name":_esc(alert.agent.agent_name),"agent_id":_esc(alert.agent.agent_id),
            "agent_ip":_esc(alert.agent.agent_ip or "Unknown"),"incident_type":incident_type,
            "severity_name":severity_name,"severity_score":severity_score,"severity_css":severity_css,
            "summary":summary,"confidence":confidence,"iocs":iocs_data,
            "malicious_ioc_count":sum(1 for ioc in alert.iocs if ioc.is_malicious),
            "total_ioc_count":len(alert.iocs),"techniques":techniques,"tactics":tactics,
            "actions":actions,"evidence_files":evidence_data,
            "evidence_errors":[_esc(e) for e in (evi.collection_errors if evi else [])]}


def _write_html(ctx: dict, output_path: Path) -> None:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html","j2"]))
    output_path.write_text(env.get_template("incident_report.html.j2").render(**ctx), encoding="utf-8")
    logger.info("HTML report → {}", output_path)


def _write_pdf(ctx: dict, output_path: Path) -> None:
    if not _FPDF_AVAILABLE: return
    pdf = FPDF(); pdf.set_auto_page_break(auto=True, margin=15); pdf.add_page()
    pdf.set_fill_color(15,15,40); pdf.rect(0,0,210,35,"F")
    pdf.set_text_color(0,200,255); pdf.set_font("Helvetica","B",20)
    pdf.set_xy(10,8); pdf.cell(0,10,"NYX SENTINEL AI",ln=True)
    pdf.set_font("Helvetica","",11); pdf.set_text_color(180,180,180)
    pdf.set_xy(10,20); pdf.cell(0,8,"Incident Report - Confidential",ln=True)
    pdf.set_text_color(0,0,0); pdf.set_xy(10,40)
    _pdf_section(pdf,"Report Information")
    # Sanitise all string values for latin-1 PDF font compatibility
    for k,v in list(ctx.items()):
        if isinstance(v,str): ctx[k]=_pdf_safe(v)
    for lst_key in ("techniques","tactics","actions","rule_groups"):
        ctx[lst_key]=[_pdf_safe(s) for s in ctx.get(lst_key,[])]
    # Deep-sanitise all string values for latin-1 PDF font
    def _deep_safe(obj):
        if isinstance(obj, str): return _pdf_safe(obj)
        if isinstance(obj, list): return [_deep_safe(i) for i in obj]
        if isinstance(obj, dict): return {k: _deep_safe(v) for k,v in obj.items()}
        return obj
    ctx = {k: _deep_safe(v) for k,v in ctx.items()}
    _pdf_kv(pdf,"Report ID",ctx["report_id"]); _pdf_kv(pdf,"Generated",ctx["generated_at"])
    _pdf_kv(pdf,"Alert ID",ctx["alert_id"]); _pdf_kv(pdf,"Alert Time",ctx["alert_timestamp"])
    _pdf_kv(pdf,"Endpoint",f"{ctx['agent_name']} ({ctx['agent_ip']})")
    _pdf_kv(pdf,"Severity",f"{ctx['severity_name']} ({ctx['severity_score']:.0f}/100)")
    _pdf_kv(pdf,"Incident Type",ctx["incident_type"])
    if ctx["summary"]:
        _pdf_section(pdf,"Executive Summary"); pdf.set_font("Helvetica","",9)
        pdf.multi_cell(0,5,ctx["summary"]); pdf.ln(3)
    _pdf_section(pdf,f"Indicators of Compromise ({ctx['total_ioc_count']} total)")
    if ctx["iocs"]:
        _pdf_table(pdf,["Type","Value","VT Det.","Abuse %","Malicious"],
            [[ioc["type"],ioc["value"][:45]+("..." if len(ioc["value"])>45 else ""),
              f"{ioc['vt_malicious']}/{ioc['vt_total']}" if ioc["vt_malicious"] is not None else "-",
              str(ioc["abuse_confidence"]) if ioc["abuse_confidence"] is not None else "-",
              "YES" if ioc["is_malicious"] else "no"] for ioc in ctx["iocs"][:20]],
            [30,75,25,25,25])
    if ctx["techniques"] or ctx["tactics"]:
        _pdf_section(pdf,"MITRE ATT&CK Mapping")
        _pdf_kv(pdf,"Tactics",", ".join(ctx["tactics"]) or "-")
        _pdf_kv(pdf,"Techniques",", ".join(ctx["techniques"]) or "-")
    _pdf_section(pdf,"Recommended Actions"); pdf.set_font("Helvetica","",9)
    for i,action in enumerate(ctx["actions"],1):
        pdf.multi_cell(0,5,f"{i}. {action}"); pdf.ln(1)
    if ctx["evidence_files"]:
        _pdf_section(pdf,f"Evidence Manifest ({len(ctx['evidence_files'])} files)")
        for ef in ctx["evidence_files"]:
            pdf.set_font("Helvetica","B",8); pdf.cell(0,5,ef["file_name"],ln=True)
            pdf.set_font("Helvetica","",8)
            pdf.cell(0,4,f"  SHA-256: {ef['sha256']}",ln=True)
            pdf.cell(0,4,f"  Original: {ef['original_path']}  Size: {ef['size_kb']} KB",ln=True); pdf.ln(2)
    pdf.set_y(-20); pdf.set_font("Helvetica","I",8); pdf.set_text_color(120,120,120)
    pdf.cell(0,5,f"NYX SENTINEL AI | Report {ctx['report_id']} | {ctx['generated_at']} | CONFIDENTIAL",align="C")
    pdf.output(str(output_path)); logger.info("PDF report → {}", output_path)


def _pdf_section(pdf: "FPDF", title: str) -> None:
    pdf.ln(4); pdf.set_fill_color(20,20,60); pdf.set_text_color(0,200,255)
    pdf.set_font("Helvetica","B",11); pdf.cell(0,8,f"  {title}",fill=True,ln=True)
    pdf.set_text_color(0,0,0); pdf.ln(2)


def _pdf_kv(pdf: "FPDF", key: str, value: str) -> None:
    pdf.set_font("Helvetica","B",9); pdf.cell(55,6,f"{key}:",ln=False)
    pdf.set_font("Helvetica","",9); pdf.cell(0,6,value,ln=True)


def _pdf_table(pdf: "FPDF", headers: list, rows: list, col_widths: list) -> None:
    pdf.set_fill_color(40,40,80); pdf.set_text_color(255,255,255); pdf.set_font("Helvetica","B",8)
    for h,w in zip(headers,col_widths): pdf.cell(w,6,h,border=1,fill=True)
    pdf.ln(); pdf.set_text_color(0,0,0); pdf.set_font("Helvetica","",8)
    for i,row in enumerate(rows):
        fill = i%2==0
        if fill: pdf.set_fill_color(240,240,250)
        else: pdf.set_fill_color(255,255,255)
        for cell,width in zip(row,col_widths): pdf.cell(width,5,str(cell),border=1,fill=fill)
        pdf.ln()
    pdf.ln(3)


def _esc(value: str) -> str:
    return html_module.escape(str(value))


def _pdf_safe(text: str) -> str:
    """Replace characters outside latin-1 range for fpdf2 Helvetica compatibility."""
    return text.encode("latin-1", errors="replace").decode("latin-1")
