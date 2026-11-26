"""Build hook: the wheel ships the built frontend (spec 3.1). Node is needed only at build time.

`pip wheel .` / `pip install .` runs `npm ci && npm run build` in frontend/ when npm is available, which writes
sshbite/web/static/. Set SSHBITE_SKIP_FRONTEND=1 to package an existing build as it is.
"""

import os
import shutil
import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent


class BuildWithFrontend(build_py):
    def run(self):
        fe = ROOT / "frontend"
        index = ROOT / "sshbite" / "web" / "static" / "index.html"
        if fe.is_dir() and os.environ.get("SSHBITE_SKIP_FRONTEND") != "1":
            npm = shutil.which("npm")
            if npm:
                if not (fe / "node_modules").is_dir():
                    subprocess.run([npm, "ci", "--no-audit", "--no-fund"], cwd=fe, check=True)
                subprocess.run([npm, "run", "build"], cwd=fe, check=True)
            elif not index.is_file():
                raise SystemExit("frontend/ is not built and npm is not available: install Node 22 or build it first")
        super().run()


setup(cmdclass={"build_py": BuildWithFrontend})
