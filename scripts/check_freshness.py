"""Fail when the newest replicated checkpoint is older than MAX_AGE_HOURS (default 26).

Sentinel publishes one checkpoint a day; a missing day is a visible failure here.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

STORE = Path(__file__).resolve().parents[1] / "checkpoints"
max_age = timedelta(hours=float(os.environ.get("MAX_AGE_HOURS", "26")))
newest = None
for path in STORE.glob("*/[0-9]*.json"):
    issued = datetime.fromisoformat(json.loads(path.read_text())["document"]["issued_at"])
    newest = issued if newest is None or issued > newest else newest
if newest is None:
    print("FAILED: no checkpoint replicated yet")
    sys.exit(5)
age = datetime.now(UTC) - newest
print(f"newest checkpoint issued {newest.isoformat()} ({age.total_seconds() / 3600:.1f} h ago)")
if age > max_age:
    print(f"FAILED (5): no new checkpoint for more than {max_age.total_seconds() / 3600:.0f} h")
    sys.exit(5)
