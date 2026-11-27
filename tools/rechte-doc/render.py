#!/usr/bin/env python3
"""Renders every page of the PDF to PNG (pypdfium2) for review: render.py PDF OUTDIR PREFIX"""
import sys
from pathlib import Path

import pypdfium2 as pdfium

pdf, out, prefix = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
out.mkdir(parents=True, exist_ok=True)
doc = pdfium.PdfDocument(pdf)
for i in range(len(doc)):
    doc[i].render(scale=110 / 72).to_pil().save(out / f"{prefix}-seite-{i + 1:02d}.png")
print(len(doc), "pages")
