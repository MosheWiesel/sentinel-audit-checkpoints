# Sentinel audit checkpoints — independent replica

Sentinel (a forensic web-evidence platform) publishes one **audit checkpoint** a day at
`/.well-known/sentinel-audit-checkpoints.json`: a document that lists the Merkle roots of
its audit-log anchor batches, is chained to the previous checkpoint by SHA-256, signed with
the issuer's Ed25519 key and timestamped by an RFC 3161 Time-Stamp Authority.

This repository keeps an **independent, append-only copy** of that log. Its own GitHub
Actions workflow pulls the log every six hours; the Sentinel server has no credentials for
this repository and cannot write to it.

## What the workflow guarantees

| Check | On failure |
|---|---|
| Every record: digest, issuer signature (pinned key, `config/issuer-keys.txt`), RFC 3161 token (`verifier/tsa-trust-anchors.pem`), no sequence gaps, chain intact — using the pinned verifier in `verifier/` | run fails, nothing stored |
| Every checkpoint stored here comes back unchanged | **HISTORY REWRITE** — run fails, nothing overwritten |
| New checkpoints continue the stored chain | run fails |
| A new checkpoint at least every 26 hours | run fails (overdue) |

Every failure opens (or updates) an issue labelled `replication-failure` and the failed run
notifies the repository owner; the issue closes on the next healthy run. The default branch
is protected against force-pushes and deletion, so stored history cannot be rewritten
without that being visible.

## Anchored in Bitcoin

Each stored checkpoint gets an [OpenTimestamps](https://opentimestamps.org) proof,
`<sequence>.json.ots`. Once a proof is complete, it shows the checkpoint existed by the time of
that Bitcoin block, with no need to trust Sentinel, GitHub or a timestamp authority:

    pip install opentimestamps-client
    ots verify checkpoints/<fingerprint>/000001.json.ots

A new proof is pending for some hours until the calendars commit it to a block; later runs
complete it. `ots verify` needs a local Bitcoin node, or use a proof explorer such as
<https://opentimestamps.org>. A failed stamp does not fail the run, and the next run tries again.

## Layout

- `checkpoints/<issuer key fingerprint>/<sequence>.json` — one file per checkpoint, exactly
  as published (each issuer key is its own series).
- `checkpoints/<fingerprint>/STATUS.json` — the latest replicated sequence and totals.
- `verifier/sentinel_verify.py` — pinned copy of the Sentinel offline verifier
  (SHA-256 `2f04925b421a13ccc440b7629e68e0941a08b7427e7d79c45cfad56d80c0f665`);
  `verifier/tsa-trust-anchors.pem` — FreeTSA, DigiCert and Sectigo timestamping roots
  (SHA-256 `1c3a47ee7f5caf80d1f1837d2292bdc5e8bf157b97324494599aa9c89890ffb6`; per-certificate fingerprints inside the file).

## Verify it yourself

```sh
python3 -m pip install cryptography==49.0.0 asn1crypto==1.5.1
python3 - <<'PY'
import glob, json
records = [json.load(open(p)) for p in sorted(glob.glob("checkpoints/*/[0-9]*.json"))]
json.dump({"format": "sentinel-audit-checkpoints/1", "checkpoints": records}, open("log.json", "w"))
PY
python3 verifier/sentinel_verify.py --checkpoints log.json \
  --trusted-keys config/issuer-keys.txt --trust-anchors verifier/tsa-trust-anchors.pem
```

To check a Case Pack against this copy, add the pack: `sentinel_verify.py pack.zip
--checkpoints log.json ...` — the checkpoints inside the pack must be the ones stored here.

## Operations

- Source URL: `config/source-url.txt` (the site's https origin; a repository variable
  `SENTINEL_BASE_URL` overrides it). The operator updates it when the site's address
  changes, as a normal commit; a wrong URL can only make runs fail (visible), never
  rewrite stored history.
- New issuer key (for example a new production server): add it to
  `config/issuer-keys.txt` in a reviewed commit; it starts its own series.
