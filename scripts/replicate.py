"""Copy Sentinel's public audit checkpoint log into this repository, append-only.

Run on a schedule by .github/workflows/replicate.yml. The source server is not trusted:

* the whole downloaded log is verified with the pinned verifier (verifier/), the pinned
  issuer keys (config/issuer-keys.txt) and the TSA trust anchor: every record's digest,
  Ed25519 signature and RFC3161 token, sequences without gaps, every record chained to
  the previous one;
* every checkpoint already stored here must come back unchanged (same digest); a changed
  or withdrawn checkpoint is reported as a HISTORY REWRITE and nothing is overwritten;
* new checkpoints must continue the stored chain; only then are they written, one file
  per checkpoint, under checkpoints/<issuer fingerprint>/<sequence>.json.

Exit codes: 0 ok, 2 source unreachable or not a checkpoint log, 3 verification failed,
4 history rewrite. Freshness is checked separately (scripts/check_freshness.py).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "checkpoints"
LOG_PATH = "/.well-known/sentinel-audit-checkpoints.json"
LIST_FORMAT = "sentinel-audit-checkpoints/1"


def fail(code: int, message: str) -> None:
    print(f"FAILED ({code}): {message}")
    sys.exit(code)


def pinned_keys() -> set[str]:
    lines = (ROOT / "config" / "issuer-keys.txt").read_text().splitlines()
    return {line.split("#", 1)[0].strip().lower() for line in lines if line.split("#", 1)[0].strip()}


def fetch(base_url: str) -> dict:
    request = urllib.request.Request(
        base_url.rstrip("/") + LOG_PATH, headers={"User-Agent": "sentinel-checkpoint-replicator"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = json.load(response)
    except Exception as exc:
        fail(2, f"cannot download the log: {type(exc).__name__}: {exc}")
    if not isinstance(data, dict) or data.get("format") != LIST_FORMAT:
        fail(2, "the response is not a sentinel-audit-checkpoints/1 document")
    return data


def verify(log: dict) -> None:
    keys = pinned_keys()
    with tempfile.TemporaryDirectory() as tmp:
        log_file, key_file = Path(tmp) / "log.json", Path(tmp) / "keys.txt"
        log_file.write_text(json.dumps(log))
        key_file.write_text("\n".join(sorted(keys)) + "\n")
        result = subprocess.run(
            [sys.executable, str(ROOT / "verifier" / "sentinel_verify.py"),
             "--checkpoints", str(log_file), "--trusted-keys", str(key_file),
             "--trust-anchors", str(ROOT / "verifier" / "tsa-trust-anchors.pem")],
            capture_output=True, text=True, check=False,
        )
    print(result.stdout[-3000:])
    if result.returncode != 0:
        fail(3, f"the verifier rejected the log (exit {result.returncode})")


def series_dir(public_key_hex: str) -> Path:
    fingerprint = hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]
    return STORE / fingerprint


def main() -> int:
    base_url = os.environ.get("SENTINEL_BASE_URL", "").strip()
    if not base_url.startswith("https://"):
        fail(2, "SENTINEL_BASE_URL (repository variable) must be an https:// URL")
    log = fetch(base_url)
    records = [r for r in log.get("checkpoints", []) if isinstance(r, dict)]
    if not records:
        fail(2, "the log is empty")
    keys = {str(r.get("public_key_hex", "")).lower() for r in records}
    if len(keys) != 1 or not keys <= pinned_keys():
        fail(3, "the log is not signed by exactly one pinned issuer key")
    verify(log)

    series = series_dir(keys.pop())
    stored = {int(p.stem): json.loads(p.read_text()) for p in series.glob("[0-9]*.json")}
    by_sequence = {int(r["sequence"]): r for r in records}
    # Published history must come back unchanged.
    for sequence, old in sorted(stored.items()):
        new = by_sequence.get(sequence)
        if new is None:
            fail(4, f"HISTORY REWRITE: published checkpoint #{sequence} was withdrawn")
        if new.get("digest_sha256") != old.get("digest_sha256") or new != old:
            fail(4, f"HISTORY REWRITE: published checkpoint #{sequence} changed")
    last = max(stored) if stored else 0
    added = [by_sequence[s] for s in sorted(by_sequence) if s > last]
    if added and stored:
        first = added[0]
        if int(first["sequence"]) != last + 1 or (
            first["document"].get("previous_digest_sha256") != stored[last]["digest_sha256"]
        ):
            fail(4, f"checkpoint #{first['sequence']} does not continue the stored chain")
    if not stored and min(by_sequence) != 1:
        fail(3, "first replication needs the complete log starting at #1")

    series.mkdir(parents=True, exist_ok=True)
    for record in added:
        path = series / f"{int(record['sequence']):06d}.json"
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    newest = by_sequence[max(by_sequence)]["document"]
    status = {
        "source": base_url,
        "series": series.name,
        "latest_sequence": max(by_sequence),
        "latest_issued_at": newest.get("issued_at"),
        "latest_totals": newest.get("totals"),
        "replicated_at": datetime.now(UTC).isoformat(),
    }
    if added:
        (series / "STATUS.json").write_text(json.dumps(status, indent=2) + "\n")
    print(f"OK: {len(added)} new checkpoint(s); stored up to #{max(by_sequence)} in {series.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
