"""
ProbeX -- Project Proposal PDF Generator
Generates a polished, concise proposal with screenshots embedded.
All text uses only ASCII-safe characters to avoid ReportLab XML parse errors.
"""

import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import Flowable
from reportlab.lib.colors import HexColor
from PIL import Image as PILImage

# ---- Color Palette -----------------------------------------------------------
BG_DEEP    = HexColor("#0a0e1a")
ACCENT     = HexColor("#00d4ff")
ACCENT2    = HexColor("#7c3aed")
WHITE      = HexColor("#ffffff")
LIGHT_GRAY = HexColor("#e2e8f0")
MID_GRAY   = HexColor("#94a3b8")
GREEN      = HexColor("#10b981")
ORANGE     = HexColor("#f59e0b")
RED        = HexColor("#ef4444")
SLATE      = HexColor("#1e293b")
SLATE_DARK = HexColor("#0f172a")

W, H = A4
MARGIN = 18 * mm

IMG_DIR  = r"c:\Users\Chitransh Singh\Desktop\ProbeX\ProbeX\prototype_image"
OUT_PATH = r"c:\Users\Chitransh Singh\Desktop\ProbeX\ProbeX\ProbeX_Proposal.pdf"

SCREENSHOTS = [
    ("Screenshot 2026-09-13 172309.png",
     "Screen 1 -- New Scan Interface: Target URL, scan profile selector, and active detector panel."),
    ("Screenshot 2026-09-13 172328.png",
     "Screen 2 -- Live Scan Progress: Real-time WebSocket terminal, phase tracker, and live findings feed."),
    ("Screenshot 2026-09-13 172416.png",
     "Screen 3 -- Scan Results: Vulnerability cards with CVSS scores, CWE refs, evidence, and Gemini AI guidance."),
    ("Screenshot 2026-09-13 172528.png",
     "Screen 4 -- Scan History and Audit Log: Full audit trail with aggregate stats and severity breakdown."),
]

# ---- Custom Flowables --------------------------------------------------------

class AccentBar(Flowable):
    """Tri-color horizontal accent bar (simulates gradient)."""
    def __init__(self, width, height=3):
        super().__init__()
        self.width = width
        self.height = height

    def draw(self):
        seg = self.width / 3
        for i, col in enumerate([ACCENT2, HexColor("#4f46e5"), ACCENT]):
            self.canv.setFillColor(col)
            self.canv.rect(i * seg, 0, seg + 1, self.height, fill=1, stroke=0)


# ---- Style Factory -----------------------------------------------------------

def S(name, **kw):
    """Shorthand ParagraphStyle constructor."""
    return ParagraphStyle(name, **kw)


def build_styles():
    return {
        "cover_title": S("cover_title", fontSize=38, fontName="Helvetica-Bold",
                          textColor=WHITE, leading=46, alignment=TA_CENTER, spaceAfter=6),
        "cover_sub":   S("cover_sub", fontSize=14, fontName="Helvetica",
                          textColor=ACCENT, leading=20, alignment=TA_CENTER, spaceAfter=4),
        "cover_tag":   S("cover_tag", fontSize=10, fontName="Helvetica",
                          textColor=LIGHT_GRAY, leading=16, alignment=TA_CENTER),
        "cover_meta":  S("cover_meta", fontSize=10, fontName="Helvetica",
                          textColor=MID_GRAY, leading=16, alignment=TA_CENTER),
        "cover_stats": S("cover_stats", fontSize=10, fontName="Helvetica",
                          textColor=LIGHT_GRAY, leading=16, alignment=TA_CENTER),
        "sec_num":     S("sec_num", fontSize=9, fontName="Helvetica-Bold",
                          textColor=ACCENT, leading=12, spaceBefore=2),
        "sec_title":   S("sec_title", fontSize=18, fontName="Helvetica-Bold",
                          textColor=BG_DEEP, leading=24, spaceBefore=2, spaceAfter=6),
        "body":        S("body", fontSize=10.5, fontName="Helvetica",
                          textColor=SLATE, leading=17, alignment=TA_JUSTIFY, spaceAfter=6),
        "body_b":      S("body_b", fontSize=10.5, fontName="Helvetica-Bold",
                          textColor=SLATE_DARK, leading=17, spaceAfter=4),
        "bullet":      S("bullet", fontSize=10, fontName="Helvetica",
                          textColor=SLATE, leading=16, leftIndent=14, spaceAfter=3),
        "caption":     S("caption", fontSize=8.5, fontName="Helvetica-Oblique",
                          textColor=MID_GRAY, leading=12, alignment=TA_CENTER, spaceAfter=6),
        "feat_t":      S("feat_t", fontSize=11, fontName="Helvetica-Bold",
                          textColor=SLATE_DARK, leading=14, spaceAfter=2),
        "feat_b":      S("feat_b", fontSize=9.5, fontName="Helvetica",
                          textColor=HexColor("#334155"), leading=14, spaceAfter=2),
        "tbl_head":    S("tbl_head", fontSize=12, fontName="Helvetica-Bold",
                          textColor=BG_DEEP, leading=16, spaceAfter=5),
        "screen_lbl":  S("screen_lbl", fontSize=9, fontName="Helvetica-Bold",
                          textColor=ACCENT2, leading=12),
    }


# ---- Page Backgrounds --------------------------------------------------------

def cover_background(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(BG_DEEP)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    seg = W / 3
    for i, col in enumerate([ACCENT2, HexColor("#4f46e5"), ACCENT]):
        canvas.setFillColor(col)
        canvas.rect(i * seg, H - 6, seg + 1, 6, fill=1, stroke=0)
    canvas.setFillColor(HexColor("#0d1424"))
    canvas.rect(0, 0, W, 40, fill=1, stroke=0)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MID_GRAY)
    canvas.drawCentredString(W / 2, 14, "Submitted for Project Selection -- 2026")
    canvas.restoreState()


def inner_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(ACCENT)
    canvas.rect(MARGIN, 14 * mm, 30, 2, fill=1, stroke=0)
    canvas.setFillColor(ACCENT2)
    canvas.rect(MARGIN + 32, 14 * mm, 20, 2, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MID_GRAY)
    canvas.drawCentredString(W / 2, 10 * mm,
        "ProbeX -- Dynamic Application Security Testing Scanner  |  Project Proposal")
    canvas.drawRightString(W - MARGIN, 10 * mm, "Page %d" % doc.page)
    canvas.restoreState()


# ---- Helpers -----------------------------------------------------------------

def embed_image(path, max_w, max_h=None):
    try:
        pil = PILImage.open(path)
        iw, ih = pil.size
        scale = max_w / iw
        nh = ih * scale
        if max_h and nh > max_h:
            scale = max_h / ih
            nw = iw * scale
            nh = ih * scale
        else:
            nw = max_w
        return Image(path, width=nw, height=nh)
    except Exception as exc:
        print("  Could not load %s: %s" % (path, exc))
        return None


def feature_card(styles, label, title, desc, accent_col=ACCENT):
    """Left-accented card."""
    content = [
        Paragraph("%s  %s" % (label, title), styles["feat_t"]),
        Paragraph(desc, styles["feat_b"]),
    ]
    inner = Table([[content]], colWidths=[W - 2 * MARGIN - 4])
    inner.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#f8fafc")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("TOPPADDING",    (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    bar = Table([[""]], colWidths=[4])
    bar.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), accent_col),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    outer = Table([[bar, inner]], colWidths=[4, W - 2 * MARGIN - 4], hAlign="LEFT")
    outer.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))
    return outer


def stat_strip(stats):
    """Row of (value, label) stat boxes."""
    cw = (W - 2 * MARGIN) / len(stats)
    cells = []
    for label, val in stats:
        cell = [
            Paragraph(
                '<font color="#00d4ff" size="18"><b>%s</b></font>' % val,
                S("sv", fontSize=18, fontName="Helvetica-Bold", textColor=ACCENT,
                  alignment=TA_CENTER, leading=22)
            ),
            Paragraph(label, S("sl", fontSize=8, fontName="Helvetica",
                                textColor=MID_GRAY, alignment=TA_CENTER, leading=11)),
        ]
        cells.append(cell)
    tbl = Table([cells], colWidths=[cw] * len(stats))
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#f1f5f9")),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("LINEAFTER",     (0, 0), (-2, -1), 0.5, HexColor("#e2e8f0")),
    ]))
    return tbl


# ---- Main builder ------------------------------------------------------------

def build_pdf():
    st = build_styles()
    story = []
    cw = W - 2 * MARGIN  # content width

    # ==========================================================================
    # COVER
    # ==========================================================================
    story.append(Spacer(1, 50 * mm))

    story.append(Paragraph(
        "DAST  --  SECURITY  --  AI-POWERED",
        S("cb", fontSize=9, fontName="Helvetica-Bold", textColor=ACCENT, alignment=TA_CENTER)
    ))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("ProbeX", st["cover_title"]))
    story.append(Paragraph("Dynamic Application Security Testing Scanner", st["cover_sub"]))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(
        "Find real vulnerabilities. Kill false positives. Get AI-powered fixes -- all on localhost.",
        st["cover_tag"]
    ))
    story.append(Spacer(1, 14 * mm))
    story.append(AccentBar(cw))
    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph(
        "7 Detector Classes   |   Real-time WebSocket Stream   |   Zero External Services   |   Gemini AI",
        st["cover_stats"]
    ))
    story.append(Spacer(1, 18 * mm))
    story.append(Paragraph(
        'Submitted by: <b><font color="#e2e8f0">Chitransh Singh</font></b>',
        st["cover_meta"]
    ))
    story.append(Paragraph("Project Proposal   |   Selection Round   |   2026", st["cover_meta"]))
    story.append(PageBreak())

    # ==========================================================================
    # 01 -- PROJECT OBJECTIVE
    # ==========================================================================
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("01", st["sec_num"]))
    story.append(Paragraph("Project Objective", st["sec_title"]))
    story.append(AccentBar(60))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph(
        "ProbeX is a fully-functional, localhost-first <b>Dynamic Application Security Testing (DAST) "
        "scanner</b> built to detect real vulnerabilities in web applications -- without cloud "
        "dependencies, without SaaS subscriptions, and without false-positive noise. It is designed "
        "for developers and security engineers who need actionable, evidence-backed security feedback "
        "during development.",
        st["body"]
    ))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("The tool achieves three concrete goals:", st["body_b"]))

    goals = [
        ("[1]", "Automated vulnerability discovery",
         "An async BFS crawler maps every endpoint, form, and parameter of the target application."),
        ("[2]", "Baseline-differential false-positive defence",
         "Mathematically proves a finding is real before reporting it -- eliminating whole classes of noise."),
        ("[3]", "AI-powered remediation",
         "Gemini generates context-aware, developer-friendly fix guidance beyond generic advice."),
    ]
    for tag, title, desc in goals:
        story.append(Paragraph(
            "%s  <b>%s</b> -- %s" % (tag, title, desc),
            st["bullet"]
        ))
    story.append(Spacer(1, 5 * mm))

    story.append(stat_strip([
        ("Detector Classes", "7"),
        ("Scan Profiles", "2"),
        ("Tests Passing", "81"),
        ("AI Engine", "Gemini"),
    ]))
    story.append(Spacer(1, 8 * mm))

    # ==========================================================================
    # 02 -- PROBLEM STATEMENT
    # ==========================================================================
    story.append(Paragraph("02", st["sec_num"]))
    story.append(Paragraph("Problem Statement", st["sec_title"]))
    story.append(AccentBar(60))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph(
        "Web application vulnerabilities -- XSS, SQL Injection, misconfigured security headers -- "
        "remain the top attack vector in data breaches year after year (OWASP Top 10). "
        "Yet most developers ship code without ever running a security scan. Existing tools fail them in "
        "four ways:",
        st["body"]
    ))
    story.append(Spacer(1, 2 * mm))

    problems = [
        ("[1]", "Cloud-only or subscription-gated",
         "Burp Suite Pro costs $449/year. Most SAST/DAST SaaS platforms require sending "
         "your code or live traffic to external servers."),
        ("[2]", "Drowning in false positives",
         "A scanner that fires on every reflected string is ignored within days. "
         "Engineers need verified, evidence-backed findings -- not a noise machine."),
        ("[3]", "Remediation without context",
         "Generic advice like &quot;use prepared statements&quot; helps a senior engineer but leaves a junior "
         "developer without a clear next step."),
        ("[4]", "Complex to operate",
         "Commercial scanners require multi-hour setup, proxy configuration, and deep "
         "security expertise just to run a first scan."),
    ]
    for tag, title, desc in problems:
        story.append(KeepTogether([
            feature_card(st, tag, title, desc, accent_col=RED),
            Spacer(1, 3 * mm),
        ]))

    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "<b>ProbeX solves all four problems</b> in a single, self-contained, open-source tool "
        "that runs on localhost in under 30 seconds -- no account, no cloud, no configuration.",
        st["body"]
    ))
    story.append(Spacer(1, 8 * mm))

    # ==========================================================================
    # 03 -- KEY FEATURES
    # ==========================================================================
    story.append(Paragraph("03", st["sec_num"]))
    story.append(Paragraph("Key Features", st["sec_title"]))
    story.append(AccentBar(60))
    story.append(Spacer(1, 4 * mm))

    features = [
        ("[BFS]", "Async Crawler with Scope Lock",
         "Concurrent breadth-first search discovers every endpoint, form, and query parameter. "
         "A hard scope lock ensures the crawler never follows links to external domains -- "
         "critical for safe use in local dev environments.",
         ACCENT),
        ("[FP]", "Baseline-Differential False Positive Defence",
         "Every probe is compared against a clean baseline captured before injection. "
         "A pattern must appear NEW in the fuzzed response to count as a signal. "
         "A page that already says &quot;syntax error&quot; in its footer can never be wrongly "
         "flagged as SQL Injection.",
         ACCENT2),
        ("[DET]", "Seven Vulnerability Detector Classes",
         "Reflected XSS (DOM-verified), SQL Injection error-based (20 DB signatures), "
         "Missing Security Headers (CSP, X-Frame-Options, HSTS), Open Redirect, "
         "Path Traversal, SSTI, and SSRF -- each with CWE, OWASP Top 10, and CVSS score.",
         GREEN),
        ("[DOM]", "DOM-Based XSS Verification",
         "Rather than checking if &lt;script&gt; appears in response text (naive -- fires on "
         "escaped output), ProbeX parses the DOM with BeautifulSoup. The nonce must sit inside "
         "an executable script tag or event-handler attribute -- not a text node.",
         ORANGE),
        ("[WS]", "Real-Time WebSocket Progress Stream",
         "Every status change, finding, and log line is broadcast over WebSocket as it happens. "
         "Late-joining clients receive full event replay so a page reload loses nothing.",
         ACCENT),
        ("[AI]", "Gemini AI Remediation Guidance",
         "Each finding is enriched with Gemini-generated, context-specific fix guidance. "
         "The prompt includes the URL, parameter, payload, evidence, and CWE -- so the advice "
         "is tailored, not generic. An offline fallback handles the no-key scenario.",
         ACCENT2),
        ("[RPT]", "Exportable Reports (JSON + HTML)",
         "Every scan produces a machine-readable JSON report and a self-contained dark-theme "
         "HTML report with collapsible finding cards, severity badges, and a risk-score bar.",
         GREEN),
        ("[DB]", "SQLite Persistence and Full Audit Log",
         "All scans and findings persist in local SQLite with timestamps, consent records, "
         "risk scores, and raw evidence. The Scan History view shows aggregate analytics "
         "across every run.",
         ORANGE),
    ]
    for tag, title, desc, col in features:
        story.append(KeepTogether([
            feature_card(st, tag, title, desc, accent_col=col),
            Spacer(1, 3.5 * mm),
        ]))

    story.append(PageBreak())

    # ==========================================================================
    # 04 -- SCREENSHOTS
    # ==========================================================================
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("04", st["sec_num"]))
    story.append(Paragraph("Project Screenshots", st["sec_title"]))
    story.append(AccentBar(60))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "The following screenshots show ProbeX running live against a local vulnerable target. "
        "All interfaces are fully implemented -- this is not a mockup or design concept.",
        st["body"]
    ))
    story.append(Spacer(1, 6 * mm))

    for idx, (fname, caption) in enumerate(SCREENSHOTS, 1):
        img_path = os.path.join(IMG_DIR, fname)
        story.append(Paragraph(
            '<font color="#7c3aed"><b>[ %02d ]</b></font>  <b>%s</b>' % (idx, caption.split("--")[0].strip()),
            st["sec_num"]
        ))
        story.append(Spacer(1, 2 * mm))

        img = embed_image(img_path, max_w=cw, max_h=98 * mm)
        if img:
            framed = Table([[img]], colWidths=[cw])
            framed.setStyle(TableStyle([
                ("BOX",           (0, 0), (-1, -1), 1, HexColor("#e2e8f0")),
                ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#f8fafc")),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 4),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ]))
            story.append(framed)

        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(caption, st["caption"]))
        story.append(Spacer(1, 5 * mm))

        if idx == 2:
            story.append(PageBreak())
            story.append(Spacer(1, 4 * mm))

    # ==========================================================================
    # TECH STACK + CLOSING
    # ==========================================================================
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width=cw, thickness=0.5, color=HexColor("#e2e8f0")))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Technology Stack", st["tbl_head"]))

    stack = [
        ["Layer", "Technology", "Purpose"],
        ["Backend",  "FastAPI + Python 3.12",            "Async REST API and WebSocket server"],
        ["Engine",   "httpx + BeautifulSoup4",           "HTTP client, BFS crawler, DOM parsing"],
        ["Database", "SQLite + SQLModel",                 "Zero-config local persistence"],
        ["Frontend", "React + Vite + TypeScript",         "Real-time dashboard and report viewer"],
        ["AI",       "Gemini API (google-generativeai)",  "Context-aware remediation guidance"],
        ["Testing",  "pytest + respx",                    "81 tests passing (100% green)"],
    ]
    stbl = Table(stack, colWidths=[cw * 0.17, cw * 0.38, cw * 0.45])
    stbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), BG_DEEP),
        ("TEXTCOLOR",     (0, 0), (-1, 0), ACCENT),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1, -1), 9),
        ("TEXTCOLOR",     (0, 1), (-1, -1), SLATE),
        ("TEXTCOLOR",     (0, 1), (0, -1), ACCENT2),
        ("FONTNAME",      (0, 1), (0, -1), "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, HexColor("#f8fafc")]),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, HexColor("#e2e8f0")),
        ("LINEBELOW",     (0, 0), (-1, 0), 1.5, ACCENT),
    ]))
    story.append(stbl)
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph(
        "ProbeX is <b>fully implemented and running</b> -- backend, frontend, all detectors, "
        "AI integration, and 81 passing tests. It is ready for live demonstration on localhost "
        "with a single <font name='Courier' size='9'>python -m uvicorn app.main:app</font> command.",
        st["body"]
    ))

    # ---- Assemble Document ---------------------------------------------------
    doc = SimpleDocTemplate(
        OUT_PATH,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=20 * mm,
        title="ProbeX -- Project Proposal",
        author="Chitransh Singh",
        subject="DAST Scanner -- Selection Round 2026",
    )
    doc.build(
        story,
        onFirstPage=cover_background,
        onLaterPages=inner_page,
    )
    print("\nPDF saved to: %s\n" % OUT_PATH)


if __name__ == "__main__":
    build_pdf()
