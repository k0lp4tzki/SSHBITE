"""After editing sshbite/collector/collect.sh, run this to refresh its B= line."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from sshbite.collector import body_sha_short, with_updated_sha  # noqa: E402

p = pathlib.Path(__file__).resolve().parents[1] / "sshbite" / "collector" / "collect.sh"
t = p.read_text(encoding="utf-8")
n = with_updated_sha(t)
if n != t:
    p.write_text(n, encoding="utf-8")
print("B=" + body_sha_short(n))
