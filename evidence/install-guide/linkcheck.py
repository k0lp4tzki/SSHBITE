"""Check every relative link and anchor in README.md and docs/*.md (GitHub slug rules).
Reports: BROKEN (file or anchor missing) and LEGACY (anchor only reachable via an <a id> compatibility anchor)."""
import re, sys, pathlib
root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
files = [root / "README.md", *sorted((root / "docs").glob("*.md"))]

def slug(t):
    t = re.sub(r"<[^>]+>", "", t)
    t = re.sub(r"`", "", t).strip().lower()
    t = re.sub(r"[^\w\- ]", "", t)
    return t.replace(" ", "-")

def anchors(p):
    heads, legacy, seen, fence = set(), set(), {}, False
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence; continue
        if fence: continue
        m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if m:
            s = slug(m.group(2)); n = seen.get(s, 0); seen[s] = n + 1
            heads.add(s if n == 0 else f"{s}-{n}")
        for a in re.findall(r'<a (?:id|name)="([^"]+)"', line):
            legacy.add(a)
    return heads, legacy

cache = {}
bad = legacy_used = total = 0
for f in files:
    fence = False
    for no, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("```"):
            fence = not fence; continue
        if fence: continue
        line_nocode = re.sub(r"`[^`]*`", "", line)
        for target in re.findall(r"\]\(([^)\s]+)\)", line_nocode):
            if re.match(r"^[a-z]+:", target): continue
            total += 1
            path, _, anc = target.partition("#")
            tp = (f.parent / path).resolve() if path else f
            if not tp.exists():
                print(f"BROKEN  {f.relative_to(root)}:{no}  {target}  (file missing)"); bad += 1; continue
            if not anc: continue
            if tp.suffix != ".md":
                print(f"BROKEN  {f.relative_to(root)}:{no}  {target}  (anchor on non-md)"); bad += 1; continue
            if tp not in cache: cache[tp] = anchors(tp)
            heads, leg = cache[tp]
            if anc in heads: continue
            if anc in leg:
                print(f"LEGACY  {f.relative_to(root)}:{no}  {target}"); legacy_used += 1; continue
            print(f"BROKEN  {f.relative_to(root)}:{no}  {target}"); bad += 1
print(f"{total} relative links checked, {bad} broken, {legacy_used} via legacy anchors only")
sys.exit(1 if bad else 0)
