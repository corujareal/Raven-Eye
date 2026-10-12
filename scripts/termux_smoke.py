#!/usr/bin/env python3
"""Report whether this environment has the complete RavenEye runtime."""
from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from raveneye_pkg.doctor import render_doctor, run_doctor


result = run_doctor()
print(render_doctor(result))
if result["environment"]["termux"]:
    print("Termux: browser headless indisponível; verificação cobre o runtime estático.")
sys.exit(0 if result["ok"] else 1)
