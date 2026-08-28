"""
ProbeX Engine – report builder.

Produces:
  - ``build_result()``  – assembles a ``ScanResult`` from raw engine output.
  - ``build_json()``    – serialises a ``ScanResult`` to a plain ``dict``.
  - ``build_html()``    – generates a self-contained dark-theme HTML report
                          (inline CSS, collapsible ``<details>`` per finding,
                          severity badges).  Shares the design-token palette
                          with the frontend (Task S5).

Zero FastAPI / SQLModel imports — this module must stay standalone.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any

from engine.models import Finding, ScanResult

# ---------------------------------------------------------------------------
# Design tokens (must stay in sync with frontend/src/tokens.css — Task S5)
# ---------------------------------------------------------------------------
_BG_DEEP = "#0a0e1a"
_BG_CARD = "#111827"
_BG_CARD2 = "#1a2235"
_ACCENT = "#00d4ff"
_ACCENT2 = "#7c3aed"
_TEXT = "#e2e8f0"
_TEXT_MUTED = "#94a3b8"
_BORDER = "#1e293b"

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff3b3b",
    "high": "#ff8c00",
    "medium": "#f5c518",
    "low": "#4ade80",
    "info": "#60a5fa",
}

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


# ---------------------------------------------------------------------------
# build_result
# ---------------------------------------------------------------------------


def build_result(
    scan_id: str,
    target_url: str,
    started_at: datetime,
    endpoints_found: int,
    findings: list[Finding],
    is_example: bool = False,
) -> ScanResult:
    """
    Assemble a ``ScanResult`` from raw engine output.

    Risk score formula::

        risk_score = min(Σ (cvss × confidence × weight) × 10, 100)

    Severity weights: critical=1.0, high=0.75, medium=0.5, low=0.25, info=0.05.
    """
    severity_weights: dict[str, float] = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.5,
        "low": 0.25,
        "info": 0.05,
    }

    raw_score = sum(
        f.cvss_score * f.confidence * severity_weights.get(f.severity, 0.1)
        for f in findings
    )
    risk_score = min(raw_score * 10, 100.0)

    return ScanResult(
        scan_id=scan_id,
        target_url=target_url,
        status="done",
        started_at=started_at,
        finished_at=datetime.utcnow(),
        endpoints_found=endpoints_found,
        findings=findings,
        risk_score=round(risk_score, 2),
        is_example=is_example,
    )


# ---------------------------------------------------------------------------
# build_json
# ---------------------------------------------------------------------------


def build_json(scan_result: ScanResult) -> dict[str, Any]:
    """
    Serialise ``scan_result`` to a plain ``dict`` (JSON-safe).

    All ``datetime`` objects are converted to ISO-8601 strings.  The returned
    dict can be passed directly to ``json.dumps()``.
    """

    def _fmt(dt: datetime | None) -> str | None:
        return dt.isoformat() if dt else None

    def _finding(f: Finding) -> dict[str, Any]:
        return {
            "id": f.id,
            "template_id": f.template_id,
            "title": f.title,
            "severity": f.severity,
            "url": f.url,
            "parameter": f.parameter,
            "payload": f.payload,
            "evidence": f.evidence,
            "cwe": f.cwe,
            "owasp": f.owasp,
            "cvss_score": f.cvss_score,
            "confidence": f.confidence,
            "remediation": f.remediation,
            "ai_remediation": f.ai_remediation,
            "is_example": f.is_example,
        }

    return {
        "scan_id": scan_result.scan_id,
        "target_url": scan_result.target_url,
        "status": scan_result.status,
        "started_at": _fmt(scan_result.started_at),
        "finished_at": _fmt(scan_result.finished_at),
        "endpoints_found": scan_result.endpoints_found,
        "risk_score": scan_result.risk_score,
        "is_example": scan_result.is_example,
        "findings_by_severity": scan_result.findings_by_severity,
        "findings": [_finding(f) for f in scan_result.findings],
    }


# ---------------------------------------------------------------------------
# build_html
# ---------------------------------------------------------------------------

_SEVERITY_BADGE_STYLE = (
    "display:inline-block;padding:2px 10px;border-radius:999px;"
    "font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;"
)


def _severity_badge(severity: str) -> str:
    colour = _SEVERITY_COLORS.get(severity, "#94a3b8")
    bg = colour + "22"
    return (
        f'<span style="{_SEVERITY_BADGE_STYLE}'
        f'color:{colour};background:{bg};border:1px solid {colour}40;">'
        f"{html.escape(severity)}</span>"
    )


def _risk_bar(score: float) -> str:
    """Horizontal risk-score bar (0-100)."""
    clamp = max(0.0, min(100.0, score))
    colour = (
        _SEVERITY_COLORS["critical"] if clamp >= 70
        else _SEVERITY_COLORS["high"] if clamp >= 40
        else _SEVERITY_COLORS["medium"] if clamp >= 20
        else _SEVERITY_COLORS["low"]
    )
    return (
        f'<div style="background:{_BORDER};border-radius:4px;height:10px;width:100%;">'
        f'<div style="background:{colour};width:{clamp:.1f}%;height:100%;border-radius:4px;'
        f'transition:width 0.6s ease;"></div></div>'
    )


def build_html(scan_result: ScanResult) -> str:
    """
    Generate a self-contained dark-theme HTML report for ``scan_result``.

    Features:
    - Inline CSS — no external dependencies, works fully offline.
    - Design tokens match the frontend (``--bg-deep``, ``--accent``).
    - One collapsible ``<details>`` block per finding.
    - Severity badges, risk-score bar, findings-by-severity summary table.
    - Optional "Demo scan" banner when ``scan_result.is_example`` is ``True``.

    Returns
    -------
    str
        Complete, self-contained HTML document as a UTF-8 string.
    """
    e = html.escape  # shorthand

    # Sort findings: critical → info, then by cvss_score descending.
    sorted_findings = sorted(
        scan_result.findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), -f.cvss_score),
    )

    # ---- findings HTML ----
    findings_html_parts: list[str] = []
    for idx, f in enumerate(sorted_findings, 1):
        ai_block = ""
        if f.ai_remediation:
            ai_block = (
                f'<div style="margin-top:12px;padding:10px 14px;'
                f'background:{_BG_DEEP};border-left:3px solid {_ACCENT};border-radius:4px;">'
                f'<p style="margin:0 0 4px;font-size:0.7rem;color:{_ACCENT};'
                f'text-transform:uppercase;letter-spacing:0.08em;">AI Remediation</p>'
                f'<p style="margin:0;color:{_TEXT};font-size:0.85rem;">{e(f.ai_remediation)}</p>'
                f"</div>"
            )

        demo_ribbon = (
            f'<span style="font-size:0.65rem;color:{_ACCENT2};'
            f'border:1px solid {_ACCENT2};padding:1px 6px;border-radius:3px;'
            f'margin-left:8px;vertical-align:middle;">DEMO</span>'
            if f.is_example else ""
        )

        payload_block = ""
        if f.payload:
            payload_block = (
                f'<p style="margin:8px 0 4px;color:{_TEXT_MUTED};font-size:0.78rem;">Payload</p>'
                f'<pre style="background:{_BG_DEEP};padding:8px 12px;border-radius:4px;'
                f'overflow-x:auto;font-size:0.8rem;color:{_ACCENT};margin:0;">'
                f"{e(f.payload)}</pre>"
            )

        findings_html_parts.append(
            f"""
    <details style="background:{_BG_CARD2};border:1px solid {_BORDER};
      border-radius:8px;margin-bottom:10px;overflow:hidden;">
      <summary style="padding:14px 18px;cursor:pointer;list-style:none;
        display:flex;align-items:center;gap:12px;user-select:none;">
        <span style="color:{_TEXT_MUTED};font-size:0.78rem;min-width:24px;">#{idx}</span>
        {_severity_badge(f.severity)}
        <span style="color:{_TEXT};font-weight:600;flex:1;">{e(f.title)}{demo_ribbon}</span>
        <span style="color:{_TEXT_MUTED};font-size:0.78rem;">CVSS {f.cvss_score}</span>
      </summary>
      <div style="padding:0 18px 16px;border-top:1px solid {_BORDER};">
        <table style="width:100%;border-collapse:collapse;margin-top:12px;font-size:0.82rem;">
          <tr>
            <td style="color:{_TEXT_MUTED};padding:4px 0;width:120px;">URL</td>
            <td style="color:{_TEXT};word-break:break-all;">{e(f.url)}</td>
          </tr>
          {"<tr><td style='color:" + _TEXT_MUTED + ";padding:4px 0;'>Parameter</td>"
           "<td style='color:" + _TEXT + ";'>" + e(f.parameter) + "</td></tr>"
           if f.parameter else ""}
          <tr>
            <td style="color:{_TEXT_MUTED};padding:4px 0;">CWE</td>
            <td style="color:{_TEXT};">{e(f.cwe)}</td>
          </tr>
          <tr>
            <td style="color:{_TEXT_MUTED};padding:4px 0;">OWASP</td>
            <td style="color:{_TEXT};">{e(f.owasp)}</td>
          </tr>
          <tr>
            <td style="color:{_TEXT_MUTED};padding:4px 0;">Confidence</td>
            <td style="color:{_TEXT};">{f.confidence:.0%}</td>
          </tr>
        </table>
        {payload_block}
        <p style="margin:12px 0 4px;color:{_TEXT_MUTED};font-size:0.78rem;">Evidence</p>
        <pre style="background:{_BG_DEEP};padding:8px 12px;border-radius:4px;
          overflow-x:auto;font-size:0.78rem;color:{_TEXT};white-space:pre-wrap;margin:0;">{e(f.evidence)}</pre>
        <p style="margin:12px 0 4px;color:{_TEXT_MUTED};font-size:0.78rem;">Remediation</p>
        <p style="color:{_TEXT};font-size:0.85rem;line-height:1.6;margin:0;">{e(f.remediation)}</p>
        {ai_block}
      </div>
    </details>"""
        )

    findings_section = "".join(findings_html_parts) if findings_html_parts else (
        f'<p style="color:{_TEXT_MUTED};text-align:center;padding:40px 0;">'
        "No findings detected in this scan.</p>"
    )

    # ---- findings-by-severity summary ----
    fbs = scan_result.findings_by_severity
    summary_rows = "".join(
        f'<tr><td style="padding:6px 12px;">{_severity_badge(sev)}</td>'
        f'<td style="padding:6px 12px;color:{_TEXT};font-weight:600;">{fbs.get(sev, 0)}</td></tr>'
        for sev in ("critical", "high", "medium", "low", "info")
    )

    # ---- demo banner ----
    demo_banner = (
        f'<div style="background:{_ACCENT2}22;border:1px solid {_ACCENT2};'
        f'border-radius:8px;padding:12px 18px;margin-bottom:20px;color:{_TEXT};'
        f'font-size:0.88rem;">'
        f'⚠️  <strong>Demo Scan</strong> — findings are synthetic, injected by the seed '
        f"script. Real scan results will not carry this banner.</div>"
    ) if scan_result.is_example else ""

    finished = (
        scan_result.finished_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if scan_result.finished_at else "—"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>ProbeX Report — {e(scan_result.target_url)}</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:{_BG_DEEP};color:{_TEXT};font-family:system-ui,-apple-system,
      'Segoe UI',Roboto,sans-serif;line-height:1.5;padding:32px 16px;}}
    a{{color:{_ACCENT};text-decoration:none;}}
    details>summary::-webkit-details-marker{{display:none}}
    details[open]>summary{{border-bottom:1px solid {_BORDER};}}
    details>summary:hover{{background:{_BG_DEEP};}}
    pre{{font-family:'JetBrains Mono','Fira Code',monospace;}}
  </style>
</head>
<body>
  <div style="max-width:900px;margin:0 auto;">

    <!-- Header -->
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:32px;">
      <span style="font-size:1.6rem;font-weight:800;
        background:linear-gradient(135deg,{_ACCENT},{_ACCENT2});
        -webkit-background-clip:text;-webkit-text-fill-color:transparent;">ProbeX</span>
      <span style="color:{_TEXT_MUTED};font-size:0.9rem;">Security Scan Report</span>
    </div>

    {demo_banner}

    <!-- Meta card -->
    <div style="background:{_BG_CARD};border:1px solid {_BORDER};border-radius:12px;
      padding:24px;margin-bottom:24px;">
      <h1 style="font-size:1.1rem;font-weight:600;color:{_TEXT};margin-bottom:16px;">
        Scan Summary</h1>
      <table style="width:100%;border-collapse:collapse;font-size:0.85rem;">
        <tr>
          <td style="color:{_TEXT_MUTED};padding:5px 0;width:160px;">Target</td>
          <td style="color:{_TEXT};word-break:break-all;">{e(scan_result.target_url)}</td>
        </tr>
        <tr>
          <td style="color:{_TEXT_MUTED};padding:5px 0;">Scan ID</td>
          <td style="color:{_TEXT};font-family:monospace;font-size:0.78rem;">{e(scan_result.scan_id)}</td>
        </tr>
        <tr>
          <td style="color:{_TEXT_MUTED};padding:5px 0;">Started</td>
          <td style="color:{_TEXT};">{e(scan_result.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"))}</td>
        </tr>
        <tr>
          <td style="color:{_TEXT_MUTED};padding:5px 0;">Finished</td>
          <td style="color:{_TEXT};">{e(finished)}</td>
        </tr>
        <tr>
          <td style="color:{_TEXT_MUTED};padding:5px 0;">Endpoints</td>
          <td style="color:{_TEXT};">{scan_result.endpoints_found}</td>
        </tr>
        <tr>
          <td style="color:{_TEXT_MUTED};padding:5px 0;">Risk Score</td>
          <td>
            <div style="display:flex;align-items:center;gap:12px;">
              <span style="color:{_TEXT};font-weight:700;font-size:1rem;">
                {scan_result.risk_score:.1f}/100</span>
              <div style="flex:1;">{_risk_bar(scan_result.risk_score)}</div>
            </div>
          </td>
        </tr>
      </table>
    </div>

    <!-- Findings by severity -->
    <div style="background:{_BG_CARD};border:1px solid {_BORDER};border-radius:12px;
      padding:24px;margin-bottom:24px;">
      <h2 style="font-size:1rem;font-weight:600;color:{_TEXT};margin-bottom:16px;">
        Findings by Severity</h2>
      <table style="border-collapse:collapse;">
        {summary_rows}
      </table>
    </div>

    <!-- Findings list -->
    <div style="margin-bottom:40px;">
      <h2 style="font-size:1rem;font-weight:600;color:{_TEXT};margin-bottom:16px;">
        Findings ({len(scan_result.findings)})</h2>
      {findings_section}
    </div>

    <!-- Footer -->
    <p style="text-align:center;color:{_TEXT_MUTED};font-size:0.75rem;">
      Generated by <strong style="color:{_ACCENT};">ProbeX</strong> ·
      {e(scan_result.started_at.strftime("%Y-%m-%d"))}
    </p>
  </div>
</body>
</html>"""
