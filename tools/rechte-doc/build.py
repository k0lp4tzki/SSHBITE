#!/usr/bin/env python3
"""Builds deliverables/SSHBITE-Minimale-Rechte.md and .pdf from tools/rechte-doc/quelle.md.

The source is a small Markdown subset: '# ' title (+ next line = meta line), '## '/'### ' headings,
paragraphs, '- ' lists, pipe tables, fenced code, '> ' warning boxes, inline **bold** and `code`.
A fenced block with info string 'include' is replaced by the files it lists (paths below deliverables/).
Usage: build.py   (needs reportlab; fonts: Liberation Sans/Mono)
"""
from __future__ import annotations

import re
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (KeepTogether, ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

ROOT = Path(__file__).resolve().parents[2]
SRC = Path(__file__).with_name("quelle.md")
OUT = ROOT / "deliverables"
TITLE = "SSHBITE – Minimale Rechte für den Audit-Account"

FD = Path("/usr/share/fonts/truetype/liberation")
for name, f in (("Sans", "LiberationSans-Regular"), ("Sans-B", "LiberationSans-Bold"),
                ("Sans-I", "LiberationSans-Italic"), ("Sans-BI", "LiberationSans-BoldItalic"),
                ("Mono", "LiberationMono-Regular"), ("Mono-B", "LiberationMono-Bold")):
    pdfmetrics.registerFont(TTFont(name, str(FD / f"{f}.ttf")))
pdfmetrics.registerFontFamily("Sans", normal="Sans", bold="Sans-B", italic="Sans-I", boldItalic="Sans-BI")
pdfmetrics.registerFontFamily("Mono", normal="Mono", bold="Mono-B", italic="Mono", boldItalic="Mono-B")

ACCENT = colors.HexColor("#0f5b66")      # the one accent colour
INK = colors.HexColor("#1f2328")
MUTED = colors.HexColor("#5b636b")
CODEBG = colors.HexColor("#f3f5f7")
RULE = colors.HexColor("#d0d7de")
WARNBG = colors.HexColor("#fbeeea")
WARN = colors.HexColor("#a0341f")

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm
FRAME_W = PAGE_W - 2 * MARGIN

S = {
    "title": ParagraphStyle("title", fontName="Sans-B", fontSize=21, leading=26, textColor=INK, spaceAfter=4),
    "meta": ParagraphStyle("meta", fontName="Sans", fontSize=9.5, leading=13, textColor=MUTED),
    "h2": ParagraphStyle("h2", fontName="Sans-B", fontSize=14, leading=18, textColor=ACCENT, spaceBefore=12,
                         spaceAfter=5),
    "h3": ParagraphStyle("h3", fontName="Sans-B", fontSize=11, leading=14, textColor=INK, spaceBefore=8,
                         spaceAfter=3),
    "body": ParagraphStyle("body", fontName="Sans", fontSize=9.5, leading=13.2, textColor=INK, spaceAfter=5,
                           alignment=TA_LEFT),
    "cell": ParagraphStyle("cell", fontName="Sans", fontSize=8.3, leading=10.6, textColor=INK, splitLongWords=1),
    "cellh": ParagraphStyle("cellh", fontName="Sans-B", fontSize=8.3, leading=10.6, textColor=colors.white),
    "warn": ParagraphStyle("warn", fontName="Sans", fontSize=9.3, leading=12.8, textColor=INK),
    "code": ParagraphStyle("code", fontName="Mono", fontSize=7.6, leading=9.6, textColor=INK),
}
CODE_PT = 7.6
CODE_CHARS = int((FRAME_W - 12) / pdfmetrics.stringWidth("M", "Mono", CODE_PT))


def inline(text: str) -> str:
    """Markdown inline -> reportlab markup: `code`, **bold**, *italic* (bold may span code)."""
    codes: list[str] = []

    def keep(m: re.Match) -> str:
        codes.append(f'<font name="Mono" size="-0.6" color="#0b3f47">{escape(m.group(1))}</font>')
        return f"\x00{len(codes) - 1}\x00"
    p = escape(re.sub(r"`([^`]*)`", keep, text))
    p = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", p)
    p = re.sub(r"(?<![\w*])\*([^*\s][^*]*?)\*(?![\w*])", r"<i>\1</i>", p)
    return re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], p)


def code_block(lines: list[str]) -> Table:
    wrapped: list[str] = []
    for ln in lines:
        ln = ln.replace("\t", "    ")
        while len(ln) > CODE_CHARS:
            wrapped.append(ln[:CODE_CHARS])
            ln = "» " + ln[CODE_CHARS:]
        wrapped.append(ln)
    html = "<br/>".join(escape(w).replace(" ", "&nbsp;") or "&nbsp;" for w in wrapped)
    t = Table([[Paragraph(html, S["code"])]], colWidths=[FRAME_W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), CODEBG), ("BOX", (0, 0), (-1, -1), 0.4, RULE),
                           ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                           ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    return t


def warn_box(text: str) -> Table:
    t = Table([[Paragraph(inline(text), S["warn"])]], colWidths=[FRAME_W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), WARNBG), ("LINEBEFORE", (0, 0), (0, -1), 3.5, WARN),
                           ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    return t


def table(rows: list[list[str]]) -> Table:
    ncol = len(rows[0])
    # column widths: every column at least as wide as its longest unbreakable token (capped), the rest
    # of the frame shared in proportion to the amount of text in the column
    def token_w(cell: str) -> float:
        w = 0.0
        for part in re.split(r"(`[^`]*`)", cell):
            mono = part.startswith("`")
            for tok in part.strip("`").replace("*", "").split():
                w = max(w, pdfmetrics.stringWidth(tok, "Mono" if mono else "Sans-B", 8.3 if not mono else 7.7))
        return w + 9
    mins = [min(max(token_w(r[c]) for r in rows if c < len(r)), FRAME_W * 0.42) for c in range(ncol)]
    if sum(mins) > FRAME_W:
        mins = [m * FRAME_W / sum(mins) for m in mins]
    lens = [sum(len(r[c]) for r in rows if c < len(r)) + 1 for c in range(ncol)]
    rest = FRAME_W - sum(mins)
    widths = [m + rest * n / sum(lens) for m, n in zip(mins, lens)]
    data = [[Paragraph(inline(c).replace('color="#0b3f47"', 'color="#ffffff"') if i == 0 else inline(c),
                       S["cellh"] if i == 0 else S["cell"]) for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1)
    st = [("BACKGROUND", (0, 0), (-1, 0), ACCENT), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 4),
          ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 3),
          ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for i in range(2, len(rows), 2):
        st.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f7f9fa")))
    t.setStyle(TableStyle(st))
    return t


def expand_includes(md: str) -> str:
    def rep(m: re.Match) -> str:
        parts = []
        for rel in m.group(1).split():
            parts.append("```\n" + (OUT / rel).read_text(encoding="utf-8").rstrip("\n") + "\n```")
        return "\n\n".join(parts)
    return re.sub(r"```include\n(.*?)\n```", rep, md, flags=re.S)


def parse(md: str) -> list:
    lines = md.split("\n")
    story: list = []
    i = 0
    para: list[str] = []

    def flush():
        if para:
            story.append(Paragraph(inline(" ".join(para)), S["body"]))
            para.clear()

    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            flush()
            j = i + 1
            while not lines[j].startswith("```"):
                j += 1
            story.append(code_block(lines[i + 1:j]))
            story.append(Spacer(1, 6))
            i = j + 1
            continue
        if ln.startswith("# "):
            flush()
            story.append(Paragraph(inline(ln[2:]), S["title"]))
            story.append(Paragraph(inline(lines[i + 2]) if not lines[i + 1].strip() else inline(lines[i + 1]),
                                   S["meta"]))
            rule = Table([[""]], colWidths=[FRAME_W], rowHeights=[2])
            rule.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 1.6, ACCENT)]))
            story += [Spacer(1, 4), rule, Spacer(1, 6)]
            i += 3 if not lines[i + 1].strip() else 2
            continue
        if ln.startswith("## "):
            flush()
            story.append(Paragraph(inline(ln[3:]), S["h2"]))
        elif ln.startswith("### "):
            flush()
            story.append(Paragraph(inline(ln[4:]), S["h3"]))
        elif ln.startswith("> "):
            flush()
            buf = []
            while i < len(lines) and lines[i].startswith(">"):
                buf.append(lines[i][1:].strip())
                i += 1
            story.append(Spacer(1, 2))
            story.append(warn_box(" ".join(buf)))
            story.append(Spacer(1, 7))
            continue
        elif ln.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-+:?", c) for c in cells):
                    rows.append(cells)
                i += 1
            story.append(table(rows))
            story.append(Spacer(1, 7))
            continue
        elif ln.startswith("- "):
            flush()
            items = []
            while i < len(lines) and (lines[i].startswith("- ") or lines[i].startswith("  ")):
                if lines[i].startswith("- "):
                    items.append(lines[i][2:])
                else:
                    items[-1] += " " + lines[i].strip()
                i += 1
            story.append(ListFlowable([ListItem(Paragraph(inline(t), S["body"]), leftIndent=12, value="•")
                                       for t in items], bulletType="bullet", start="•", leftIndent=12,
                                      bulletFontName="Sans", bulletColor=ACCENT, bulletFontSize=9))
            continue
        elif not ln.strip():
            flush()
        else:
            para.append(ln.strip())
        i += 1
    flush()
    # keep each heading with what follows it
    out: list = []
    k = 0
    while k < len(story):
        f = story[k]
        lead = isinstance(f, Paragraph) and f.style.name == "body" and f.text.rstrip().endswith(":")
        if isinstance(f, Paragraph) and (f.style.name in ("h2", "h3") or lead) and k + 1 < len(story):
            out.append(KeepTogether([f, story[k + 1]]))
            k += 2
            continue
        out.append(f)
        k += 1
    return out


class NumberedCanvas(rl_canvas.Canvas):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._pages = []

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        n = len(self._pages)
        for p in self._pages:
            self.__dict__.update(p)
            self.setFont("Sans", 7.8)
            self.setFillColor(MUTED)
            self.setStrokeColor(RULE)
            self.line(MARGIN, 13 * mm, PAGE_W - MARGIN, 13 * mm)
            self.drawString(MARGIN, 9 * mm, TITLE + " · Version 1.0 · 26.11.2026")
            self.drawRightString(PAGE_W - MARGIN, 9 * mm, f"Seite {self._pageNumber} von {n}")
            super().showPage()
        super().save()


def main() -> None:
    md = expand_includes(SRC.read_text(encoding="utf-8"))
    (OUT / "SSHBITE-Minimale-Rechte.md").write_text(md, encoding="utf-8")
    doc = SimpleDocTemplate(str(OUT / "SSHBITE-Minimale-Rechte.pdf"), pagesize=A4, leftMargin=MARGIN,
                            rightMargin=MARGIN, topMargin=17 * mm, bottomMargin=18 * mm, title=TITLE,
                            author="PACT", subject="sudo- und SSH-Rechte des SSHBITE-Audit-Accounts", lang="de-DE")
    doc.build(parse(md), canvasmaker=NumberedCanvas)
    print("written:", OUT / "SSHBITE-Minimale-Rechte.md", OUT / "SSHBITE-Minimale-Rechte.pdf")


if __name__ == "__main__":
    main()
