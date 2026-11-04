#!/usr/bin/env python3
"""Anchor stored checkpoints in Bitcoin through OpenTimestamps.

Each checkpoint gets a proof next to it, `<sequence>.json.ots`. A new proof is pending: the
calendars commit it to a Bitcoin block within hours, and later runs upgrade it. A complete proof
needs no calendar, no Sentinel and no GitHub to verify.

A calendar being down says nothing about the checkpoints, so nothing here fails the run.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path("checkpoints")
COMPLETE = "BitcoinBlockHeaderAttestation"


def ots(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["ots", *args], capture_output=True, text=True, timeout=180)


def main() -> int:
    for checkpoint in sorted(ROOT.glob("*/[0-9]*.json")):
        proof = checkpoint.with_name(f"{checkpoint.name}.ots")
        if not proof.exists():
            result = ots("stamp", str(checkpoint))
            print(f"{checkpoint}: {'stamped' if result.returncode == 0 else 'not stamped'}")
            continue
        if COMPLETE in ots("info", str(proof)).stdout:
            continue
        ots("upgrade", str(proof))
        proof.with_name(f"{proof.name}.bak").unlink(missing_ok=True)
        state = "complete" if COMPLETE in ots("info", str(proof)).stdout else "pending"
        print(f"{proof}: {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
