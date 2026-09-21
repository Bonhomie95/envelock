"""Render the Envelock runbook to PDF.

A focused Markdown subset renderer rather than a general one: the runbook is the
only input, so this handles exactly what it contains — headings, paragraphs,
fenced code, tables, ordered/unordered lists, blockquotes, rules, and inline
code/bold/italic/links — and nothing else. That keeps it short enough to read.

Design intent: a document someone reads at a terminal at 3am. Generous margins,
a serif body for the prose, a mono face for every command, and code blocks that
are visually unmistakable so the eye finds the next thing to type.
"""

from __future__ import annotations

import html
import pathlib
import re
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

# ── Palette ──────────────────────────────────────────────────────────────────
# Matches the review artifact: cool neutrals with a deep-teal accent, so the two
# documents read as one set.
INK = colors.HexColor("#0f1418")
BODY = colors.HexColor("#242e35")
SLATE = colors.HexColor("#5d6a74")
MUTED = colors.HexColor("#8a959e")
ACCENT = colors.HexColor("#0f646d")
RULE = colors.HexColor("#d6dce0")
CODE_BG = colors.HexColor("#f2f5f6")
CODE_INK = colors.HexColor("#16323a")
WARN_BG = colors.HexColor("#fdf6e7")
WARN_RULE = colors.HexColor("#b58218")

MONO = "Courier"
MONO_B = "Courier-Bold"

styles = getSampleStyleSheet()


def _s(name: str, **kw) -> ParagraphStyle:
    return ParagraphStyle(name, parent=styles["Normal"], **kw)


BODY_S = _s("body", fontName="Times-Roman", fontSize=9.6, leading=14.2,
            textColor=BODY, spaceAfter=7, alignment=TA_LEFT)
H1 = _s("h1", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK,
        spaceBefore=4, spaceAfter=10)
H2 = _s("h2", fontName="Helvetica-Bold", fontSize=14.5, leading=18, textColor=INK,
        spaceBefore=17, spaceAfter=7, keepWithNext=1)
# `keepWithNext`: a heading stranded at the foot of a page with its content
# overleaf is the single most common defect in a generated PDF.
H3 = _s("h3", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=INK,
        spaceBefore=13, spaceAfter=5, keepWithNext=1)
H4 = _s("h4", fontName="Helvetica-Bold", fontSize=9.6, leading=13, textColor=ACCENT,
        spaceBefore=10, spaceAfter=4, keepWithNext=1)
CODE_S = ParagraphStyle("code", fontName=MONO, fontSize=7.7, leading=10.4,
                        textColor=CODE_INK, leftIndent=0, spaceAfter=0)
QUOTE_S = _s("quote", fontName="Times-Roman", fontSize=9.4, leading=13.4,
             textColor=BODY, leftIndent=8, spaceAfter=5)
CELL = _s("cell", fontName="Times-Roman", fontSize=8.3, leading=11.4, textColor=BODY)
CELL_H = _s("cellh", fontName="Helvetica-Bold", fontSize=7.4, leading=10,
            textColor=SLATE)
LIST_S = _s("li", fontName="Times-Roman", fontSize=9.6, leading=14, textColor=BODY,
            spaceAfter=3)

#: Filled from the document's own first H1 at render time. Hardcoding it meant
#: every document rendered with the runbook's name in its running header.
TITLE = "Envelock"


# ── Inline markup ────────────────────────────────────────────────────────────
def inline(text: str) -> str:
    """Markdown inline → ReportLab mini-HTML.

    Code spans are extracted first and re-inserted last, so `**` inside a
    backtick span is never mistaken for bold — which happens constantly in shell
    snippets.
    """
    spans: list[str] = []

    def stash(m: re.Match) -> str:
        spans.append(m.group(1))
        return f"\x00{len(spans) - 1}\x00"

    text = re.sub(r"`([^`]+)`", stash, text)
    text = html.escape(text)

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", text)          # links → label
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<![*\w])\*([^*]+)\*(?!\*)", r"<i>\1</i>", text)
    text = text.replace("→", "&#8594;").replace("←", "&#8592;")
    text = text.replace("—", "&#8212;").replace("–", "&#8211;")
    # ReportLab's built-in Type 1 fonts have no glyph for these, and a missing
    # glyph renders as a solid black box — which reads as a broken document.
    # Substitute characters the base fonts actually carry.
    text = text.replace("☐ ", "").replace("☐", "")
    text = text.replace("⚠️", "!").replace("⚠", "!")
    text = text.replace("✓", "&#8730;").replace("·", "&#183;")

    for i, raw in enumerate(spans):
        code = html.escape(raw)
        text = text.replace(
            f"\x00{i}\x00",
            f'<font face="{MONO}" size="8.4" color="#16323a">{code}</font>',
        )
    return text


def _table(rows: list[list[str]]) -> Table:
    header, *body = rows
    # Markdown has no way to express "a two-column layout" other than a table
    # with an empty header row. Rendering that literally produces a blank grey
    # band, which reads as a defect.
    headerless = not any(c.strip() for c in header)
    if headerless:
        body = rows
        data = [[Paragraph(inline(c), CELL) for c in r] for r in rows]
    else:
        data = [[Paragraph(inline(c), CELL_H) for c in header]]
        data += [[Paragraph(inline(c), CELL) for c in r] for r in body]

    # Column widths from content weight, so a "why" column gets the room it needs.
    #
    # Code spans count for more than their character length: Courier at 8.4pt is
    # noticeably wider than Times at 8.3pt, so a column of environment-variable
    # names measured naively comes out too narrow and wraps mid-identifier.
    ncols = len(header)
    total = 168 * mm

    def weight(cell: str) -> float:
        plain = re.sub(r"`[^`]*`", "", cell)
        code = sum(len(m) for m in re.findall(r"`([^`]+)`", cell))
        return len(plain) + code * 1.45

    weights = []
    for i in range(ncols):
        # The header is bold and must not wrap mid-word either — a narrow numeric
        # column whose heading is "Default" needs room for the heading, not the
        # numbers.
        widest = max((weight(r[i]) for r in rows[1:] if i < len(r)), default=8)
        head = weight(header[i]) * 1.3 if i < len(header) else 0
        weights.append(max(widest, head, 10))
    scale = total / sum(weights)
    widths = [w * scale for w in weights]

    t = Table(data, colWidths=widths, repeatRows=0 if headerless else 1,
              hAlign="LEFT")
    head_bg = colors.white if headerless else colors.HexColor("#eef2f3")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), head_bg),
        ("LINEBELOW", (0, 0), (-1, 0), 0.3 if headerless else 0.7,
         colors.HexColor("#e8edef") if headerless else RULE),
        ("LINEBELOW", (0, 1), (-1, -2), 0.3, colors.HexColor("#e8edef")),
        ("BOX", (0, 0), (-1, -1), 0.5, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
    ]))
    return t


#: Characters with no glyph in ReportLab's built-in Type 1 fonts. Inside a code
#: block they cannot go through `inline()` (Preformatted takes raw text), and an
#: absent glyph renders as a solid black box.
_CODE_SUBSTITUTIONS = {
    "\u2610": "[ ]",   # ballot box — used for checklists
    "\u2611": "[x]",
    "\u2713": "v",      # check mark
    "\u26a0": "!",      # warning sign
    "\u2014": "--",
    "\u2192": "->",
    "\u2190": "<-",
    "\u25b6": ">",
    "\u25c4": "<",
}


def _code_block(lines: list[str]) -> Table:
    """A code block as a single-cell table, so it gets a background and a rail."""
    body = "\n".join(lines) or " "
    for bad, good in _CODE_SUBSTITUTIONS.items():
        body = body.replace(bad, good)
    pre = Preformatted(body, CODE_S)
    t = Table([[pre]], colWidths=[168 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("LINEBEFORE", (0, 0), (0, -1), 2, ACCENT),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return t


def _quote(parts: list[str]) -> Table:
    inner = [Paragraph(inline(p), QUOTE_S) for p in parts]
    t = Table([[inner]], colWidths=[168 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), WARN_BG),
        ("LINEBEFORE", (0, 0), (0, -1), 2, WARN_RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return t


# ── Block parser ─────────────────────────────────────────────────────────────
def build(md: str) -> list:
    flow: list = []
    lines = md.split("\n")
    i = 0
    n = len(lines)
    first_h1_done = False

    def flush_list(items: list[str], ordered: bool) -> None:
        if not items:
            return
        flow.append(ListFlowable(
            [ListItem(Paragraph(inline(t), LIST_S), leftIndent=13) for t in items],
            bulletType="1" if ordered else "bullet",
            bulletFontSize=8,
            bulletColor=ACCENT,
            leftIndent=15,
            spaceAfter=7,
        ))
        items.clear()

    bullets: list[str] = []
    numbers: list[str] = []

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Fenced code
        if stripped.startswith("```"):
            flush_list(bullets, False)
            flush_list(numbers, True)
            i += 1
            block: list[str] = []
            while i < n and not lines[i].strip().startswith("```"):
                # Wrap rather than clip: a truncated command is worse than a
                # wrapped one.
                raw = lines[i].replace("\t", "    ")
                while len(raw) > 96:
                    block.append(raw[:96])
                    raw = "    " + raw[96:]
                block.append(raw)
                i += 1
            i += 1
            flow.append(Spacer(1, 3))
            flow.append(_code_block(block))
            flow.append(Spacer(1, 8))
            continue

        # Table
        is_table = (
            stripped.startswith("|")
            and i + 1 < n
            and re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip())
        )
        if is_table:
            flush_list(bullets, False)
            flush_list(numbers, True)
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                row = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not re.match(r"^[\s:|-]+$", "".join(row)):
                    rows.append(row)
                i += 1
            width = max(len(r) for r in rows)
            rows = [r + [""] * (width - len(r)) for r in rows]
            flow.append(Spacer(1, 3))
            flow.append(_table(rows))
            flow.append(Spacer(1, 9))
            continue

        # Blockquote
        if stripped.startswith(">"):
            flush_list(bullets, False)
            flush_list(numbers, True)
            parts: list[str] = []
            buf: list[str] = []
            while i < n and lines[i].strip().startswith(">"):
                content = lines[i].strip().lstrip(">").strip()
                if not content:
                    if buf:
                        parts.append(" ".join(buf))
                        buf = []
                else:
                    buf.append(content)
                i += 1
            if buf:
                parts.append(" ".join(buf))
            flow.append(Spacer(1, 3))
            flow.append(_quote(parts))
            flow.append(Spacer(1, 8))
            continue

        # Headings
        m = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if m:
            flush_list(bullets, False)
            flush_list(numbers, True)
            level, text = len(m.group(1)), m.group(2)
            text = re.sub(r"\s*\{#.*\}$", "", text)
            if level == 1:
                if first_h1_done:
                    flow.append(PageBreak())
                first_h1_done = True
                flow.append(Paragraph(inline(text), H1))
                flow.append(HRFlowable(width="100%", thickness=1.4, color=INK,
                                       spaceBefore=2, spaceAfter=10))
            elif level == 2:
                flow.append(KeepTogether([
                    Paragraph(inline(text), H2),
                    HRFlowable(width="100%", thickness=0.5, color=RULE,
                               spaceBefore=1, spaceAfter=6),
                ]))
            else:
                flow.append(Paragraph(inline(text), H3 if level == 3 else H4))
            i += 1
            continue

        # Horizontal rule
        if re.match(r"^-{3,}$", stripped):
            flush_list(bullets, False)
            flush_list(numbers, True)
            flow.append(Spacer(1, 4))
            flow.append(HRFlowable(width="100%", thickness=0.5, color=RULE,
                                   spaceAfter=8))
            i += 1
            continue

        # Lists. A markdown list item may wrap over several source lines; without
        # consuming the continuations here, the tail of a long bullet fell out of
        # the list and rendered as a stray paragraph below it.
        def _consume_continuations(start: int) -> tuple[str, int]:
            parts: list[str] = []
            j = start
            while j < n and lines[j].strip() and not re.match(
                r"^\s*([-*]\s|\d+\.\s|#{1,4}\s|```|\||>|-{3,}$)", lines[j]
            ):
                parts.append(lines[j].strip())
                j += 1
            return " ".join(parts), j

        m = re.match(r"^\s*[-*]\s+(.*)$", line)
        if m:
            flush_list(numbers, True)
            rest, i = _consume_continuations(i + 1)
            bullets.append(" ".join(filter(None, [m.group(1), rest])))
            continue
        m = re.match(r"^\s*\d+\.\s+(.*)$", line)
        if m:
            flush_list(bullets, False)
            rest, i = _consume_continuations(i + 1)
            numbers.append(" ".join(filter(None, [m.group(1), rest])))
            continue

        # Blank
        if not stripped:
            flush_list(bullets, False)
            flush_list(numbers, True)
            i += 1
            continue

        # Paragraph — join continuation lines.
        flush_list(bullets, False)
        flush_list(numbers, True)
        para = [stripped]
        i += 1
        while i < n and lines[i].strip() and not re.match(
            r"^\s*([-*]\s|\d+\.\s|#{1,4}\s|```|\||>|-{3,}$)", lines[i]
        ):
            para.append(lines[i].strip())
            i += 1
        flow.append(Paragraph(inline(" ".join(para)), BODY_S))

    flush_list(bullets, False)
    flush_list(numbers, True)
    return flow


def decorate(canvas, doc) -> None:  # noqa: ANN001
    canvas.saveState()
    w, h = A4
    canvas.setFont("Helvetica", 6.8)
    canvas.setFillColor(MUTED)
    canvas.drawString(21 * mm, h - 12 * mm, TITLE.upper())
    canvas.drawRightString(w - 21 * mm, h - 12 * mm, "6 SEPTEMBER 2026")
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(21 * mm, h - 14.5 * mm, w - 21 * mm, h - 14.5 * mm)
    canvas.drawCentredString(w / 2, 12 * mm, str(doc.page))
    canvas.restoreState()


def main() -> int:
    global TITLE
    src, out = sys.argv[1], sys.argv[2]
    md = pathlib.Path(src).read_text(encoding="utf-8")

    first_h1 = re.search(r"^#\s+(.+)$", md, re.MULTILINE)
    if first_h1:
        TITLE = first_h1.group(1).strip()

    doc = BaseDocTemplate(
        out, pagesize=A4,
        leftMargin=21 * mm, rightMargin=21 * mm,
        topMargin=20 * mm, bottomMargin=18 * mm,
        title=TITLE, author="Envelock",
        subject="Launch checklist, operations, incident response",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="body")
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=decorate)])
    doc.build(build(md))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
