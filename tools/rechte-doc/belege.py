#!/usr/bin/env python3
"""Prints, for every file:line reference in deliverables/SSHBITE-Minimale-Rechte.md (built by build.py), the cited line(s) of the code.

Reference form in the document: `path:N`, `path:N-M`, `path:N, M-K` (inside backticks). Short paths are resolved
below the repository (e.g. privilege.py -> sshbite/privilege.py). Output: deliverables/nachweis/07-belege-geprueft.txt
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "deliverables" / "SSHBITE-Minimale-Rechte.md"
OUT = ROOT / "deliverables" / "nachweis" / "07-belege-geprueft.txt"
REF = re.compile(r"`([A-Za-z0-9_./-]+\.(?:py|md|sh|yaml|yml|toml)):([0-9][0-9 ,–-]*)`")
DIRS = ["", "sshbite/", "sshbite/collector/", "docs/"]


def resolve(p: str) -> Path:
    for d in DIRS:
        f = ROOT / (d + p)
        if f.is_file():
            return f
    raise SystemExit(f"Datei nicht gefunden: {p}")


def main() -> None:
    head = subprocess.run(["git", "-C", str(ROOT), "log", "-1", "--format=%h %ci", "--", "sshbite", "docs",
                           "README.md"], capture_output=True, text=True).stdout.strip()
    out = ["Belegprüfung: jede Datei:Zeile-Angabe aus SSHBITE-Minimale-Rechte.md mit den zitierten Zeilen",
           f"Code-Stand: letzter Commit an sshbite/, docs/, README.md: {head}",
           f"Erzeugt mit: tools/rechte-doc/belege.py", ""]
    n = 0
    for no, text in enumerate(SRC.read_text(encoding="utf-8").splitlines(), 1):
        for m in REF.finditer(text):
            path = resolve(m.group(1))
            lines = path.read_text(encoding="utf-8").splitlines()
            rel = path.relative_to(ROOT)
            out.append(f"=== SSHBITE-Minimale-Rechte.md Zeile {no}: `{m.group(1)}:{m.group(2)}`  ->  {rel}")
            for part in re.split(r"\s*,\s*", m.group(2).strip()):
                a, _, b = part.replace("–", "-").partition("-")
                a, b = int(a), int(b or a)
                if not (1 <= a <= b <= len(lines)):
                    raise SystemExit(f"Zeile außerhalb der Datei: {rel}:{part}")
                for i in range(a, b + 1):
                    out.append(f"  {i:4d} | {lines[i - 1]}")
                n += 1
            out.append("")
    out.append(f"{n} Angaben geprüft.")
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"{n} Angaben -> {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
