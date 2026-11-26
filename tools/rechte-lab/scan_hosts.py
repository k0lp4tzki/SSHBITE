#!/usr/bin/env python3
"""Lab helper: per-host status, privilege and route of one scan, plus record counts (for chapter 7)."""
import json
import sqlite3
import sys

db, scan = sys.argv[1], int(sys.argv[2])
c = sqlite3.connect(db)
print(f"{'Host':8} {'Status':12} {'Privileg':13} {'Adresse':14} Route / Fehler")
for r in c.execute("""select h.display_name, s.status, s.privilege, s.connect_addr, s.route, s.error, s.partial_reasons
                      from host_scan s join host h on h.id = s.host_id where s.scan_id = ? order by h.display_name""",
                   (scan,)):
    route = " > ".join(x if isinstance(x, str) else str(x.get("name", x)) for x in json.loads(r[4] or "[]"))
    extra = (r[5] or "") + (" " + r[6] if r[6] and r[6] != "[]" else "")
    print(f"{r[0] or '':8} {r[1] or '':12} {r[2] or '':13} {r[3] or '':14} {route} {extra}".rstrip())
for t in ("authorized_entry", "private_key", "account", "edge", "finding"):
    print(t, c.execute(f"select count(*) from {t} where scan_id=?", (scan,)).fetchone()[0])
