#!/usr/bin/env python3
"""Sentinel Offline Verifier — Court-Proof Case Pack Verification.

Single-command offline verification of Case Pack exports.

Usage:
    python scripts/sentinel_verify.py casepack.zip \
        [--public-key <ed25519-hex>]... [--trusted-keys keys.txt] \
        [--trust-anchors tsa-ca.pem]

Without --public-key/--trusted-keys the Ed25519 signature only proves the
package is internally consistent: the signing key is read from the package
itself, so anyone can re-sign an altered package. Supply the issuing Sentinel
instance's public key to authenticate the signer. Likewise, without
--trust-anchors the RFC3161 token signatures are verified against the TSA
certificate embedded in the token, but that certificate is not anchored.

The verifier is self-contained (no Sentinel imports) and fails closed when a
required cryptographic library is missing.

Case Pack 1.2 ("evidence-tree/1" layout, see docs/CASE_PACK_FORMAT.md): each
evidence file is read only from its manifest export_path, which must be a
contained relative path under evidence/; undeclared files, duplicate paths and
inconsistent media-index / crawl-map / network-log / screenshot records fail.
Case Pack 1.3 adds structural checks of the WARC network archive (every
record's WARC-Block-Digest / WARC-Payload-Digest recomputed), HAR, MHTML, PDF
and page-metadata files. Older packs keep the legacy media/ rules.

Exit codes:
    0 = All checks passed
    1 = Generic failure (bad ZIP, missing files)
    2 = Tamper detected (hash mismatch, bad signature)
    3 = Audit chain gap or sequence violation
    4 = RFC3161 timestamp invalid
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath


# ── ANSI Colors ──
class C:
    OK = "\033[92m"
    FAIL = "\033[91m"
    WARN = "\033[93m"
    INFO = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""
    exit_code: int = 0  # 0=pass, 1=generic, 2=tamper, 3=chain, 4=tsa
    warning: bool = False  # passed, but with a limitation the reader must know about


@dataclass
class VerificationReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def worst_exit_code(self) -> int:
        codes = [c.exit_code for c in self.checks if not c.passed]
        return max(codes) if codes else 0

    def print_report(self):
        print(f"\n{C.BOLD}{'='*60}{C.END}")
        print(f"{C.BOLD}  Sentinel Case Pack — Verification Report{C.END}")
        print(f"{'='*60}\n")

        for check in self.checks:
            icon = f"{C.OK}✅{C.END}" if check.passed else f"{C.FAIL}❌{C.END}"
            suffix = f" {C.WARN}(warning){C.END}" if check.passed and check.warning else ""
            print(f"  {icon} {check.name}{suffix}")
            if check.detail:
                # Indent detail lines
                for line in check.detail.split("\n"):
                    print(f"       {line}")

        print(f"\n{'='*60}")
        if self.all_passed and any(c.warning for c in self.checks):
            print(f"  {C.OK}{C.BOLD}ALL CHECKS PASSED{C.END} {C.WARN}WITH WARNINGS{C.END}")
            for check in self.checks:
                if check.warning:
                    print(f"  {C.WARN}- {check.name}: see details above{C.END}")
        elif self.all_passed:
            print(f"  {C.OK}{C.BOLD}ALL CHECKS PASSED{C.END}")
        else:
            failed = [c for c in self.checks if not c.passed]
            print(f"  {C.FAIL}{C.BOLD}{len(failed)} CHECK(S) FAILED{C.END}")
        print(f"{'='*60}\n")


def safe_extract_archive(
    archive: zipfile.ZipFile,
    destination: str,
    *,
    max_files: int = 5000,
    max_uncompressed_bytes: int = 500 * 1024 * 1024,
    max_ratio: int = 200,
) -> None:
    """Extract a bounded archive without traversal, links, or ZIP bombs."""
    entries = archive.infolist()
    if len(entries) > max_files:
        raise ValueError("ZIP contains too many entries")
    destination_path = Path(destination).resolve()
    total_size = 0
    seen = set()
    for entry in entries:
        normalized = entry.filename.replace("\\", "/")
        path = PurePosixPath(normalized)
        if not normalized or normalized.startswith("/") or path.is_absolute() or ".." in path.parts:
            raise ValueError("ZIP contains an unsafe path")
        canonical = path.as_posix()
        if canonical in seen:
            raise ValueError("ZIP contains duplicate paths")
        seen.add(canonical)
        mode = (entry.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ValueError("ZIP symbolic links are not allowed")
        if entry.flag_bits & 0x1:
            raise ValueError("Encrypted ZIP entries are not supported")
        total_size += entry.file_size
        if total_size > max_uncompressed_bytes:
            raise ValueError("ZIP expands beyond the allowed size")
        if entry.file_size > 1024 * 1024 and entry.file_size / max(1, entry.compress_size) > max_ratio:
            raise ValueError("ZIP compression ratio exceeds the safety limit")
        target = (destination_path / Path(*path.parts)).resolve()
        if target != destination_path and destination_path not in target.parents:
            raise ValueError("ZIP contains an unsafe path")
        if entry.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(entry, "r") as source, target.open("wb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)


def check_zip_integrity(zip_path: str) -> CheckResult:
    """Verify ZIP can be opened and is not corrupt."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            bad = zf.testzip()
            if bad:
                return CheckResult(
                    "ZIP Integrity", False,
                    f"Corrupt entry: {bad}", exit_code=2
                )
            names = zf.namelist()
            return CheckResult(
                "ZIP Integrity", True,
                f"{len(names)} entries"
            )
    except (zipfile.BadZipFile, Exception) as e:
        return CheckResult("ZIP Integrity", False, str(e), exit_code=1)


def check_required_files(extract_dir: str) -> CheckResult:
    """Check that required files exist in the archive."""
    required = ["manifest.json", "audit_chain.json"]
    missing = [f for f in required if not os.path.exists(os.path.join(extract_dir, f))]
    if missing:
        return CheckResult(
            "Required Files", False,
            f"Missing: {', '.join(missing)}", exit_code=1
        )
    return CheckResult("Required Files", True, "manifest.json, audit_chain.json present")


def check_package_format(extract_dir: str) -> CheckResult:
    """Validate explicit (>=1.1) package metadata while accepting legacy v1.0 packages."""
    manifest_path = os.path.join(extract_dir, "manifest.json")
    metadata_path = os.path.join(extract_dir, "package_metadata.json")
    try:
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
    except Exception as exc:
        return CheckResult("Package Format", False, f"Cannot read manifest: {exc}", exit_code=1)
    version = str(
        manifest.get("package_format_version")
        or manifest.get("manifest_version")
        or "1.0"
    )
    if not version.startswith("1."):
        return CheckResult(
            "Package Format",
            False,
            f"Unsupported package format version: {version}",
            exit_code=1,
        )
    if not os.path.exists(metadata_path):
        return CheckResult(
            "Package Format",
            True,
            f"Legacy Sentinel package format {version}; package_metadata.json was introduced in 1.1",
        )
    try:
        with open(metadata_path, encoding="utf-8") as handle:
            metadata = json.load(handle)
    except Exception as exc:
        return CheckResult(
            "Package Format", False, f"Cannot read package metadata: {exc}", exit_code=1
        )
    if metadata.get("package_format") != "sentinel-case-pack":
        return CheckResult(
            "Package Format", False, "Unexpected package format identifier", exit_code=2
        )
    if str(metadata.get("package_format_version")) != version:
        return CheckResult(
            "Package Format", False, "Package format version mismatch", exit_code=2
        )
    if metadata.get("event_id") != manifest.get("event_id"):
        return CheckResult(
            "Package Format", False, "Package event identifier mismatch", exit_code=2
        )
    layout = manifest.get("evidence_layout")
    if layout is not None and layout not in SUPPORTED_EVIDENCE_LAYOUTS:
        return CheckResult(
            "Package Format", False, f"Unsupported evidence layout: {layout}", exit_code=1
        )
    if "evidence_layout" in metadata and metadata.get("evidence_layout") != layout:
        return CheckResult(
            "Package Format", False, "Package evidence layout mismatch", exit_code=2
        )
    detail = f"sentinel-case-pack/{version}"
    if layout:
        detail += f" ({layout})"
    return CheckResult("Package Format", True, detail)


def _load_json(path: str):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _load_manifest(extract_dir: str) -> dict:
    return _load_json(os.path.join(extract_dir, "manifest.json"))


def _load_package_metadata(extract_dir: str) -> dict:
    path = os.path.join(extract_dir, "package_metadata.json")
    if not os.path.exists(path):
        return {}
    try:
        data = _load_json(path)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _expects_evidence_file(item: dict) -> bool:
    """Items that failed capture or were never stored have no file to verify."""
    return str(item.get("state") or "").upper() != "FAILED" and bool(item.get("storage_path", True))


SUPPORTED_EVIDENCE_LAYOUTS = {"evidence-tree/1"}
# Top-level files a Case Pack may contain besides the evidence tree.
PACKAGE_FILES = {
    "manifest.json", "audit_chain.json", "package_metadata.json", "worm_proof.json",
    "report.pdf", "timestamps.json",
}


def _uses_evidence_tree(manifest: dict) -> bool:
    """Case Pack 1.2 tree layout: declared, or implied by any export_path (no mixing)."""
    if manifest.get("evidence_layout") is not None:
        return True
    return any(
        isinstance(item, dict) and item.get("export_path")
        for item in manifest.get("evidence_items") or []
    )


def resolve_export_path(extract_dir: str, export_path) -> str:
    """Resolve a manifest export_path to a regular file inside evidence/.

    Rejects anything that is not a plain relative POSIX path below evidence/
    (absolute paths, '..', '.', empty segments, backslashes, drive letters,
    NUL) and anything that resolves - including via links - outside the
    extraction directory. Raises ValueError with the reason.
    """
    if not isinstance(export_path, str) or not export_path or len(export_path) > 512:
        raise ValueError("invalid export_path")
    if any(ch in export_path for ch in ("\\", "\x00", ":")):
        raise ValueError("unsafe export_path")
    segments = export_path.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise ValueError("unsafe export_path")
    path = PurePosixPath(export_path)
    if path.is_absolute() or len(path.parts) < 2 or path.parts[0] != "evidence":
        raise ValueError("export_path outside evidence/")
    base = Path(extract_dir).resolve()
    unresolved = base.joinpath(*path.parts)
    target = unresolved.resolve()
    if base not in target.parents:
        raise ValueError("export_path escapes the package")
    if unresolved.is_symlink() or not target.is_file():
        raise ValueError("evidence file missing")
    return str(target)


def _sha256_file(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(8192 * 1024):
            sha256.update(chunk)
    return sha256.hexdigest()


def _unreferenced_files(extract_dir: str, referenced: set[str]) -> list[str]:
    extra = []
    for root, _dirs, files in os.walk(extract_dir):
        for filename in files:
            arcname = os.path.relpath(os.path.join(root, filename), extract_dir).replace(os.sep, "/")
            if arcname in PACKAGE_FILES or arcname.startswith("timestamp_tokens/"):
                continue
            if arcname not in referenced:
                extra.append(arcname)
    return sorted(extra)


def check_manifest_hashes(extract_dir: str) -> CheckResult:
    """Verify SHA-256 of each evidence file against manifest.

    Fails closed: an evidence item without a hash, or a file missing from media/
    while the package declares evidence files as included, is a failure.
    """
    try:
        manifest = _load_manifest(extract_dir)
    except Exception as e:
        return CheckResult("Manifest Hashes", False, f"Cannot read manifest: {e}", exit_code=1)

    evidence_items = manifest.get("evidence_items", [])
    if not evidence_items:
        return CheckResult("Manifest Hashes", True, "No evidence items to verify")

    metadata = _load_package_metadata(extract_dir)
    if _uses_evidence_tree(manifest):
        return _check_tree_hashes(extract_dir, manifest, evidence_items, metadata)
    media_dir = os.path.join(extract_dir, "media")
    media_files = sorted(os.listdir(media_dir)) if os.path.isdir(media_dir) else []
    declared = metadata.get("evidence_files_included")
    # Legacy packages (< 1.2) do not declare inclusion; infer it from media/.
    files_included = bool(media_files) if declared is None else bool(declared)

    mismatches = []
    missing = []
    verified = 0
    skipped_failed = 0

    for item in evidence_items:
        item_id = str(item.get("id", "unknown"))
        if not _expects_evidence_file(item):
            skipped_failed += 1
            continue
        expected_hash = item.get("file_hash_sha256")
        if not expected_hash:
            mismatches.append(f"{item_id}: evidence item has no SHA-256 hash")
            continue
        if not files_included:
            continue

        candidates = [name for name in media_files if name == item_id or name.startswith(item_id + ".")]
        if not candidates:
            missing.append(f"{item_id}: evidence file missing from media/")
            continue

        sha256 = hashlib.sha256()
        with open(os.path.join(media_dir, candidates[0]), "rb") as f:
            while chunk := f.read(8192 * 1024):
                sha256.update(chunk)
        actual = sha256.hexdigest()

        if actual != expected_hash:
            mismatches.append(f"{item_id}: expected={expected_hash[:16]}... got={actual[:16]}...")
        else:
            verified += 1

    problems = mismatches + missing
    if problems:
        return CheckResult(
            "Manifest Hashes", False,
            f"{len(problems)} problem(s):\n" + "\n".join(problems),
            exit_code=2
        )
    if not files_included:
        return CheckResult(
            "Manifest Hashes", True,
            "WARNING: evidence files are not included in this package; "
            "only metadata hashes are present and file contents were not verified",
            warning=True,
        )
    detail = f"{verified} file(s) verified"
    if skipped_failed:
        detail += f", {skipped_failed} failed-capture item(s) without files"
    return CheckResult("Manifest Hashes", True, detail)


def _check_tree_hashes(extract_dir: str, manifest: dict, evidence_items: list, metadata: dict) -> CheckResult:
    """Case Pack 1.2: every stored item at its exact, contained export_path."""
    declared = metadata.get("evidence_files_included")
    files_included = True if declared is None else bool(declared)
    problems: list[str] = []
    referenced: set[str] = set()
    verified = 0
    skipped_failed = 0
    for item in evidence_items:
        item_id = str(item.get("id", "unknown"))
        if not _expects_evidence_file(item):
            skipped_failed += 1
            continue
        expected_hash = item.get("file_hash_sha256")
        if not expected_hash:
            problems.append(f"{item_id}: evidence item has no SHA-256 hash")
            continue
        export_path = item.get("export_path")
        if not export_path:
            problems.append(f"{item_id}: evidence item has no export_path")
            continue
        if export_path in referenced:
            problems.append(f"{item_id}: export_path {export_path} is declared twice")
            continue
        referenced.add(export_path)
        if not files_included:
            continue
        try:
            path = resolve_export_path(extract_dir, export_path)
        except ValueError as exc:
            problems.append(f"{item_id}: {exc} ({str(export_path)[:120]})")
            continue
        actual = _sha256_file(path)
        if actual != expected_hash:
            problems.append(f"{item_id}: expected={expected_hash[:16]}... got={actual[:16]}...")
        else:
            verified += 1
    if files_included:
        for extra in _unreferenced_files(extract_dir, referenced):
            problems.append(f"{extra}: file is not declared in the manifest")
    if problems:
        return CheckResult(
            "Manifest Hashes", False,
            f"{len(problems)} problem(s):\n" + "\n".join(problems[:50]),
            exit_code=2,
        )
    if not files_included:
        return CheckResult(
            "Manifest Hashes", True,
            "WARNING: evidence files are not included in this package; "
            "only metadata hashes are present and file contents were not verified",
            warning=True,
        )
    detail = f"{verified} file(s) verified at their declared export paths"
    if skipped_failed:
        detail += f", {skipped_failed} failed-capture item(s) without files"
    return CheckResult("Manifest Hashes", True, detail)


def _png_dimensions(data: bytes):
    if len(data) < 24 or not data.startswith(b"\x89PNG\r\n\x1a\n") or data[12:16] != b"IHDR":
        return None
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


INDEX_TYPES = {"MEDIA_INDEX", "CRAWL_MAP", "SCREENSHOT", "HTTP_TRANSACTION_JSON"}
MEDIA_TYPES = {"IMAGE", "VIDEO", "AUDIO", "DOCUMENT"}


def check_capture_indexes(extract_dir: str) -> CheckResult:
    """Case Pack 1.2: media index, crawl map, network log and screenshots are
    well-formed and every evidence reference in them matches the manifest."""
    name = "Capture Indexes"
    try:
        manifest = _load_manifest(extract_dir)
    except Exception as e:
        return CheckResult(name, False, f"Cannot read manifest: {e}", exit_code=1)
    items = [i for i in manifest.get("evidence_items") or [] if isinstance(i, dict)]
    special = [i for i in items if i.get("type") in INDEX_TYPES and _expects_evidence_file(i)]
    if not special:
        return CheckResult(name, True, "No full-capture indexes in this package")
    if not _uses_evidence_tree(manifest):
        return CheckResult(
            name, False, "Full-capture artifacts require the evidence-tree layout", exit_code=2
        )
    metadata = _load_package_metadata(extract_dir)
    if metadata.get("evidence_files_included") is False:
        return CheckResult(
            name, True,
            "WARNING: evidence files are not included; indexes were not verified",
            warning=True,
        )
    by_id = {str(i.get("id")): i for i in items}
    problems: list[str] = []
    indexed_media: set[str] = set()
    counts = {"MEDIA_INDEX": 0, "CRAWL_MAP": 0, "SCREENSHOT": 0, "HTTP_TRANSACTION_JSON": 0}

    def ref_ok(label: str, evidence_id, sha256=None) -> None:
        ref = by_id.get(str(evidence_id))
        if ref is None:
            problems.append(f"{label}: references unknown evidence {str(evidence_id)[:40]}")
        elif sha256 and ref.get("file_hash_sha256") != sha256:
            problems.append(f"{label}: hash for {evidence_id} differs from the manifest")

    for item in special:
        item_id = str(item.get("id"))
        kind = item.get("type")
        try:
            path = resolve_export_path(extract_dir, item.get("export_path"))
        except ValueError as exc:
            problems.append(f"{item_id}: {exc}")
            continue
        if os.path.getsize(path) > 64 * 1024 * 1024:
            problems.append(f"{item_id}: index file too large to verify")
            continue
        with open(path, "rb") as handle:
            data = handle.read()
        counts[kind] += 1
        if kind == "SCREENSHOT":
            dims = _png_dimensions(data)
            meta = item.get("capture_metadata") or {}
            if dims is None:
                problems.append(f"{item_id}: screenshot is not a PNG image")
            elif meta.get("width") is not None and (meta.get("width"), meta.get("height")) != dims:
                problems.append(f"{item_id}: screenshot dimensions differ from capture metadata")
            continue
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            problems.append(f"{item_id}: {kind} is not valid JSON ({exc})")
            continue
        if not isinstance(document, dict):
            problems.append(f"{item_id}: {kind} must be a JSON object")
            continue
        if kind == "MEDIA_INDEX":
            entries = document.get("items")
            if not isinstance(entries, list):
                problems.append(f"{item_id}: media index has no items list")
                continue
            for position, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    problems.append(f"{item_id}: media index entry {position} is not an object")
                    continue
                evidence_id = entry.get("evidence_id")
                if entry.get("status") == "captured" and not evidence_id:
                    problems.append(f"{item_id}: captured media entry {position} has no evidence_id")
                if evidence_id:
                    if not entry.get("sha256"):
                        problems.append(f"{item_id}: media entry {position} has no sha256")
                    ref_ok(f"media index entry {position}", evidence_id, entry.get("sha256"))
                    indexed_media.add(str(evidence_id))
        elif kind == "CRAWL_MAP":
            pages = document.get("pages")
            if not isinstance(pages, list) or not pages:
                problems.append(f"{item_id}: crawl map has no pages")
                continue
            for position, page in enumerate(pages):
                for evidence_id in (page.get("evidence_ids") or []) if isinstance(page, dict) else []:
                    ref_ok(f"crawl map page {position}", evidence_id)
        elif kind == "HTTP_TRANSACTION_JSON":
            for position, txn in enumerate(document.get("asset_downloads") or []):
                if isinstance(txn, dict) and txn.get("evidence_id"):
                    ref_ok(
                        f"network log download {position}",
                        txn["evidence_id"],
                        txn.get("response_body_sha256"),
                    )
    if counts["MEDIA_INDEX"]:
        for item in items:
            if (
                item.get("type") in MEDIA_TYPES
                and (item.get("capture_metadata") or {}).get("relation")
                and str(item.get("id")) not in indexed_media
            ):
                problems.append(f"{item.get('id')}: captured media item missing from media index")
    if problems:
        return CheckResult(
            name, False, f"{len(problems)} problem(s):\n" + "\n".join(problems[:50]), exit_code=2
        )
    return CheckResult(
        name, True,
        f"{counts['MEDIA_INDEX']} media index, {counts['CRAWL_MAP']} crawl map, "
        f"{counts['HTTP_TRANSACTION_JSON']} network log, {counts['SCREENSHOT']} screenshot(s) "
        "consistent with the manifest",
    )


ARCHIVE_TYPES = {"WARC_ARCHIVE", "HAR_ARCHIVE", "MHTML_SNAPSHOT", "PAGE_PDF", "PAGE_METADATA"}
WARC_MAX_RECORD_BYTES = 512 * 1024 * 1024
WARC_MAX_RECORDS = 200_000
JSON_ARTIFACT_MAX_BYTES = 256 * 1024 * 1024


def _iter_gzip_members(path: str):
    """Yield the decompressed bytes of each gzip member (one WARC record each).

    Decompression is bounded per member, so a crafted archive cannot expand
    without limit in memory.
    """
    chunk_size = 1024 * 1024
    with open(path, "rb") as handle:
        buffer = b""
        while True:
            if not buffer:
                buffer = handle.read(chunk_size)
                if not buffer:
                    return
            decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
            output = bytearray()
            while True:
                output += decompressor.decompress(buffer, WARC_MAX_RECORD_BYTES + 1 - len(output))
                if len(output) > WARC_MAX_RECORD_BYTES:
                    raise ValueError("WARC record larger than the verifier limit")
                if decompressor.eof:
                    buffer = decompressor.unused_data
                    break
                buffer = decompressor.unconsumed_tail
                if not buffer:
                    buffer = handle.read(chunk_size)
                    if not buffer:
                        raise ValueError("truncated gzip member")
            yield bytes(output)


def _check_warc_digest(value, data: bytes) -> bool | None:
    """True/False for a recomputed labelled digest, None for an unknown algorithm."""
    if not value or ":" not in value:
        return None
    algorithm, _, encoded = value.partition(":")
    algorithm = algorithm.strip().lower().replace("-", "")
    if algorithm not in {"sha1", "sha256", "sha512"}:
        return None
    digest = hashlib.new(algorithm, data).digest()
    encoded = encoded.strip()
    return encoded in {base64.b32encode(digest).decode("ascii"), digest.hex()}


def verify_warc_file(path: str) -> tuple[dict, list[str]]:
    """Parse a gzip-per-record WARC and recompute every record digest.

    Returns (stats, problems). Self-contained: no warcio needed to verify.
    """
    stats = {"records": 0, "response": 0, "request": 0, "warcinfo": 0, "truncated": 0,
             "digests_checked": 0}
    problems: list[str] = []
    try:
        for position, member in enumerate(_iter_gzip_members(path)):
            if position >= WARC_MAX_RECORDS:
                problems.append("too many WARC records")
                break
            head_end = member.find(b"\r\n\r\n")
            if head_end < 0:
                problems.append(f"record {position}: no WARC header terminator")
                continue
            lines = member[:head_end].decode("utf-8", errors="replace").split("\r\n")
            if lines[0] not in {"WARC/1.1", "WARC/1.0"}:
                problems.append(f"record {position}: not a WARC/1.x record")
                continue
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, sep, value = line.partition(":")
                if sep:
                    headers[name.strip().lower()] = value.strip()
            try:
                length = int(headers.get("content-length", ""))
            except ValueError:
                problems.append(f"record {position}: invalid Content-Length")
                continue
            block = member[head_end + 4: head_end + 4 + length]
            if len(block) != length or member[head_end + 4 + length:] != b"\r\n\r\n":
                problems.append(f"record {position}: block length does not match Content-Length")
                continue
            kind = headers.get("warc-type", "")
            for required in ("warc-record-id", "warc-date", "warc-type"):
                if not headers.get(required):
                    problems.append(f"record {position}: missing {required}")
            if position == 0 and kind != "warcinfo":
                problems.append("first WARC record is not warcinfo")
            if kind in {"response", "request"} and not headers.get("warc-target-uri"):
                problems.append(f"record {position}: {kind} without WARC-Target-URI")
            stats["records"] += 1
            if kind in {"response", "request", "warcinfo"}:
                stats[kind] += 1
            if headers.get("warc-truncated"):
                stats["truncated"] += 1
            block_ok = _check_warc_digest(headers.get("warc-block-digest"), block)
            if block_ok is False:
                problems.append(f"record {position}: WARC-Block-Digest mismatch")
            elif block_ok:
                stats["digests_checked"] += 1
            if kind in {"response", "request"} and headers.get("warc-payload-digest"):
                split = block.find(b"\r\n\r\n")
                payload = block[split + 4:] if split >= 0 else b""
                payload_ok = _check_warc_digest(headers.get("warc-payload-digest"), payload)
                if payload_ok is False:
                    problems.append(f"record {position}: WARC-Payload-Digest mismatch")
                elif payload_ok:
                    stats["digests_checked"] += 1
            elif kind == "response":
                problems.append(f"record {position}: response without WARC-Payload-Digest")
    except (OSError, ValueError, zlib.error) as exc:
        problems.append(f"WARC is not a valid gzip-per-record archive ({exc})")
    if stats["records"] == 0 and not problems:
        problems.append("WARC contains no records")
    return stats, problems


def check_capture_archives(extract_dir: str) -> CheckResult:
    """Case Pack 1.3: WARC/HAR network archive, MHTML, PDF and page metadata are
    well-formed; WARC record digests recompute; counts match capture metadata."""
    name = "Capture Archives"
    try:
        manifest = _load_manifest(extract_dir)
    except Exception as e:
        return CheckResult(name, False, f"Cannot read manifest: {e}", exit_code=1)
    items = [
        i for i in manifest.get("evidence_items") or []
        if isinstance(i, dict) and i.get("type") in ARCHIVE_TYPES and _expects_evidence_file(i)
    ]
    if not items:
        return CheckResult(name, True, "No network archive / page copies in this package")
    if not _uses_evidence_tree(manifest):
        return CheckResult(name, False, "Page archives require the evidence-tree layout", exit_code=2)
    if _load_package_metadata(extract_dir).get("evidence_files_included") is False:
        return CheckResult(name, True, "WARNING: evidence files are not included; archives were not verified",
                           warning=True)
    problems: list[str] = []
    notes: list[str] = []
    for item in items:
        item_id = str(item.get("id"))
        kind = item.get("type")
        meta = item.get("capture_metadata") or {}
        try:
            path = resolve_export_path(extract_dir, item.get("export_path"))
        except ValueError as exc:
            problems.append(f"{item_id}: {exc}")
            continue
        size = os.path.getsize(path)
        if kind == "WARC_ARCHIVE":
            stats, warc_problems = verify_warc_file(path)
            problems.extend(f"{item_id}: {problem}" for problem in warc_problems[:20])
            if meta.get("records") is not None and meta.get("records") != stats["records"]:
                problems.append(f"{item_id}: WARC has {stats['records']} records, capture metadata says {meta.get('records')}")
            notes.append(f"WARC {stats['records']} records ({stats['response']} responses, "
                         f"{stats['truncated']} truncated, {stats['digests_checked']} digests recomputed)")
            continue
        if kind == "PAGE_PDF":
            with open(path, "rb") as handle:
                head = handle.read(8)
                handle.seek(max(0, size - 2048))
                tail = handle.read()
            if not head.startswith(b"%PDF-") or b"%%EOF" not in tail:
                problems.append(f"{item_id}: page PDF is not a complete PDF document")
            else:
                notes.append("PDF ok")
            continue
        if kind == "MHTML_SNAPSHOT":
            with open(path, "rb") as handle:
                head = handle.read(64 * 1024).lower()
            if b"mime-version:" not in head or b"multipart/related" not in head:
                problems.append(f"{item_id}: MHTML snapshot has no multipart/related MIME header")
            else:
                notes.append("MHTML ok")
            continue
        if size > JSON_ARTIFACT_MAX_BYTES:
            problems.append(f"{item_id}: {kind} too large to verify")
            continue
        try:
            with open(path, "rb") as handle:
                document = json.loads(handle.read().decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            problems.append(f"{item_id}: {kind} is not valid JSON ({str(exc)[:80]})")
            continue
        if kind == "HAR_ARCHIVE":
            entries = (document.get("log") or {}).get("entries") if isinstance(document, dict) else None
            if not isinstance(entries, list):
                problems.append(f"{item_id}: HAR has no log.entries list")
            elif meta.get("entries") is not None and meta.get("entries") != len(entries):
                problems.append(f"{item_id}: HAR has {len(entries)} entries, capture metadata says {meta.get('entries')}")
            else:
                notes.append(f"HAR {len(entries)} entries")
        elif kind == "PAGE_METADATA":
            if not isinstance(document, dict) or document.get("format") != "sentinel-page-metadata/1":
                problems.append(f"{item_id}: page metadata has an unknown format")
            else:
                notes.append("page metadata ok")
    if problems:
        return CheckResult(name, False, f"{len(problems)} problem(s):\n" + "\n".join(problems[:50]), exit_code=2)
    return CheckResult(name, True, "; ".join(notes))


def _manifest_payload_bytes(manifest: dict) -> bytes:
    manifest_for_hash = dict(manifest)
    manifest_for_hash.pop("signature", None)
    return json.dumps(manifest_for_hash, indent=2, sort_keys=True, default=str).encode("utf-8")


def _compute_casepack_payload_hash(extract_dir: str, manifest: dict) -> str:
    records = []
    for root, _dirs, files in os.walk(extract_dir):
        for filename in files:
            path = os.path.join(root, filename)
            arcname = os.path.relpath(path, extract_dir).replace(os.sep, "/")
            if arcname.startswith("timestamp_tokens/") or arcname == "timestamps.json":
                continue
            if arcname == "manifest.json":
                content = _manifest_payload_bytes(manifest)
            else:
                with open(path, "rb") as f:
                    content = f.read()
            records.append({
                "path": arcname,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            })
    canonical = json.dumps(
        sorted(records, key=lambda r: r["path"]),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _normalize_key_hex(value: str) -> str:
    return value.strip().lower().removeprefix("0x")


def load_trusted_keys(public_keys: list[str] | None, trusted_keys_file: str | None) -> set[str]:
    """Collect pinned Ed25519 public keys (64 hex chars each)."""
    keys = {_normalize_key_hex(k) for k in (public_keys or []) if k and k.strip()}
    if trusted_keys_file:
        with open(trusted_keys_file, encoding="utf-8") as handle:
            for line in handle:
                line = line.split("#", 1)[0].strip()
                if line:
                    keys.add(_normalize_key_hex(line))
    for key in keys:
        if len(key) != 64 or any(ch not in "0123456789abcdef" for ch in key):
            raise ValueError(f"Invalid Ed25519 public key (expected 64 hex chars): {key[:20]}...")
    return keys


def check_signature(
    zip_path: str,
    extract_dir: str,
    allow_unsigned: bool = False,
    trusted_keys: set[str] | None = None,
) -> CheckResult:
    """Verify Ed25519 signature over the canonical Case Pack payload hash.

    With trusted_keys, the signer must be one of the pinned keys. Without them
    the key embedded in the manifest is used and the result carries a warning,
    because a self-asserted key does not authenticate who signed the package.
    """
    try:
        manifest = _load_manifest(extract_dir)
    except Exception as e:
        return CheckResult("Ed25519 Signature", False, f"Cannot read manifest: {e}", exit_code=1)

    sig_block = manifest.get("signature")
    if not sig_block or not isinstance(sig_block, dict):
        if allow_unsigned:
            return CheckResult(
                "Ed25519 Signature", True,
                "WARNING: no signature in manifest (unsigned bundle, allowed by --allow-unsigned)",
                warning=True,
            )
        return CheckResult(
            "Ed25519 Signature", False,
            "No signature in manifest (unsigned bundle). Use --allow-unsigned to accept.",
            exit_code=2
        )

    sig_hex = sig_block.get("signature_hex")
    pub_hex = sig_block.get("public_key_hex")
    payload_hash_hex = sig_block.get("payload_hash_hex")
    signed_subject = sig_block.get("signed_subject")
    if not sig_hex or not pub_hex:
        return CheckResult(
            "Ed25519 Signature", False,
            "Signature block present but missing signature_hex or public_key_hex",
            exit_code=2
        )

    if signed_subject != "casepack_payload_hash" or not payload_hash_hex:
        return CheckResult(
            "Ed25519 Signature", False,
            "Signature block must identify signed_subject=casepack_payload_hash and payload_hash_hex",
            exit_code=2
        )

    recomputed_payload_hash = _compute_casepack_payload_hash(extract_dir, manifest)
    if recomputed_payload_hash != payload_hash_hex:
        return CheckResult(
            "Ed25519 Signature", False,
            f"payload_hash mismatch: computed={recomputed_payload_hash[:16]}... vs signed={payload_hash_hex[:16]}...",
            exit_code=2
        )

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return CheckResult(
            "Ed25519 Signature", False,
            "The 'cryptography' package is required to verify signatures (pip install cryptography)",
            exit_code=1,
        )

    try:
        pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub_key.verify(bytes.fromhex(sig_hex), bytes.fromhex(recomputed_payload_hash))
    except Exception as e:
        return CheckResult("Ed25519 Signature", False, f"INVALID: {e}", exit_code=2)

    fingerprint = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:16]
    if trusted_keys:
        if _normalize_key_hex(pub_hex) not in trusted_keys:
            return CheckResult(
                "Ed25519 Signature", False,
                f"UNTRUSTED SIGNER: package was signed by key {pub_hex[:16]}... "
                f"(fingerprint {fingerprint}), which is not one of the "
                f"{len(trusted_keys)} trusted Sentinel key(s)",
                exit_code=2,
            )
        return CheckResult(
            "Ed25519 Signature", True,
            f"Valid signature by trusted key {pub_hex[:16]}... (fingerprint {fingerprint})"
        )
    return CheckResult(
        "Ed25519 Signature", True,
        f"Valid payload hash signature (pubkey: {pub_hex[:16]}...)\n"
        "WARNING: signer NOT authenticated - the public key comes from the package itself. "
        "Re-run with --public-key <issuer key> to bind the package to its issuing Sentinel instance.",
        warning=True,
    )


GENESIS_HASH = "0" * 64
AUDIT_HASH_EXCLUDE_FIELDS = frozenset({"prev_hash", "entry_hash"})


def _canonical_json(obj: dict, exclude_fields=AUDIT_HASH_EXCLUDE_FIELDS) -> bytes:
    """Byte-identical to src.core.canonical_json.canonical_json for JSON-decoded input.

    JSON-decoded values are already plain dict/list/str/int/float/bool/None, so
    Sentinel's type coercion (datetime/UUID) is the identity here. Kept inline so
    the verifier never depends on the Sentinel source tree being importable.
    """
    filtered = {str(k): v for k, v in obj.items() if k not in exclude_fields}
    return json.dumps(
        filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _chain_hash(prev_hash: str, data: bytes) -> str:
    hasher = hashlib.sha256()
    hasher.update(prev_hash.encode("utf-8"))
    hasher.update(data)
    return hasher.hexdigest()


def _entry_sequence(entry: dict) -> int:
    full = entry.get("full_entry") or {}
    return int(full.get("sequence_number", entry.get("sequence", 0)) or 0)


def check_audit_chain(extract_dir: str) -> CheckResult:
    """Verify audit hash-chain integrity offline and bind it to the signed manifest."""
    chain_path = os.path.join(extract_dir, "audit_chain.json")
    try:
        chain_data = _load_json(chain_path)
    except Exception as e:
        return CheckResult("Audit Chain", False, f"Cannot read audit_chain.json: {e}", exit_code=1)

    entries = chain_data.get("entries", []) if isinstance(chain_data, dict) else []
    if not entries:
        return CheckResult(
            "Audit Chain", False,
            "No audit entries found — expected at least one",
            exit_code=3
        )

    entries = sorted(entries, key=_entry_sequence)

    first = entries[0]
    genesis_seq = _entry_sequence(first)
    if genesis_seq != 1:
        return CheckResult(
            "Audit Chain", False,
            f"Genesis sequence is {genesis_seq}, expected 1", exit_code=3
        )
    if first.get("prev_hash", "") != GENESIS_HASH:
        return CheckResult("Audit Chain", False, "Genesis prev_hash mismatch", exit_code=3)

    prev_hash = GENESIS_HASH
    prev_seq = 0
    for entry in entries:
        full_entry = entry.get("full_entry")
        stored_hash = entry.get("entry_hash", "")
        seq = _entry_sequence(entry)
        if not isinstance(full_entry, dict) or not full_entry:
            return CheckResult(
                "Audit Chain", False,
                f"Entry at seq {seq} has no full_entry; hash cannot be recomputed", exit_code=3
            )
        if entry.get("prev_hash", "") != prev_hash:
            return CheckResult(
                "Audit Chain", False,
                f"Broken link at seq {seq}: prev_hash mismatch", exit_code=3
            )
        computed = _chain_hash(prev_hash, _canonical_json(full_entry))
        if computed != stored_hash:
            return CheckResult(
                "Audit Chain", False,
                f"Hash mismatch at seq {seq}: computed={computed[:16]}... stored={stored_hash[:16]}...",
                exit_code=3
            )
        if seq != prev_seq + 1:
            return CheckResult(
                "Audit Chain", False, f"Sequence gap: {seq} follows {prev_seq}", exit_code=3
            )
        prev_seq = seq
        prev_hash = stored_hash

    # Bind audit_chain.json to the (signed) manifest so the chain cannot be swapped.
    try:
        manifest = _load_manifest(extract_dir)
    except Exception as e:
        return CheckResult("Audit Chain", False, f"Cannot read manifest: {e}", exit_code=1)
    final_hash = manifest.get("audit_final_hash")
    if final_hash and final_hash != prev_hash:
        return CheckResult(
            "Audit Chain", False,
            "audit_chain.json final hash does not match manifest.audit_final_hash", exit_code=3
        )
    expected_length = manifest.get("audit_chain_length")
    if isinstance(expected_length, int) and expected_length != len(entries):
        return CheckResult(
            "Audit Chain", False,
            f"audit_chain.json has {len(entries)} entries, manifest declares {expected_length}",
            exit_code=3,
        )
    manifest_hashes = [
        e.get("entry_hash") for e in manifest.get("audit_entries") or [] if isinstance(e, dict)
    ]
    if manifest_hashes and manifest_hashes != [e.get("entry_hash") for e in entries]:
        return CheckResult(
            "Audit Chain", False,
            "audit_chain.json entries differ from manifest.audit_entries", exit_code=3
        )
    if not final_hash:
        return CheckResult(
            "Audit Chain", True,
            f"{len(entries)} entries verified, chain intact\n"
            "WARNING: manifest has no audit_final_hash; chain is not bound to the manifest",
            warning=True,
        )
    return CheckResult(
        "Audit Chain", True,
        f"{len(entries)} entries verified, chain intact and bound to manifest"
    )


def _load_pem_certificates(path: str) -> list:
    from cryptography import x509

    with open(path, "rb") as handle:
        return x509.load_pem_x509_certificates(handle.read())


_EC_SIG_HASH = {
    "sha1_ecdsa": "sha1", "sha224_ecdsa": "sha224", "sha256_ecdsa": "sha256",
    "sha384_ecdsa": "sha384", "sha512_ecdsa": "sha512",
}
_RSA_SIG_HASH = {
    "sha1_rsa": "sha1", "sha224_rsa": "sha224", "sha256_rsa": "sha256",
    "sha384_rsa": "sha384", "sha512_rsa": "sha512",
}


def verify_timestamp_token(token_der: bytes, expected_imprint: bytes, anchors: list | None = None):
    """Cryptographically verify an RFC3161 TimeStampToken.

    Checks: SignedData/TSTInfo structure, message imprint, signed-attribute
    message digest, the TSA's CMS signature, the signer certificate's
    timeStamping EKU and validity at genTime, and - when anchors are given -
    a certificate path from the signer to a trust anchor.

    Returns (ok, detail, info) where info has gen_time / tsa / anchored.
    """
    from asn1crypto import cms, tsp
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID

    info: dict = {"anchored": False}
    content_info = cms.ContentInfo.load(token_der)
    if content_info["content_type"].native != "signed_data":
        return False, "token is not CMS SignedData", info
    signed_data = content_info["content"]
    encap = signed_data["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        return False, "token does not encapsulate a TSTInfo", info
    tst_der = encap["content"].contents
    tst_info = tsp.TSTInfo.load(tst_der)
    info["gen_time"] = tst_info["gen_time"].native
    tsa_name = tst_info["tsa"]
    info["tsa"] = None
    if tsa_name.native:
        info["tsa"] = (
            tsa_name.chosen.human_friendly
            if tsa_name.name == "directory_name"
            else str(tsa_name.native)
        )

    imprint = tst_info["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].native != "sha256":
        return False, "message imprint is not SHA-256", info
    if imprint["hashed_message"].native != expected_imprint:
        return False, "message imprint does not match the timestamped hash", info

    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) != 1:
        return False, f"expected exactly one SignerInfo, found {len(signer_infos)}", info
    signer = signer_infos[0]
    digest_name = signer["digest_algorithm"]["algorithm"].native
    signed_attrs = signer["signed_attrs"]
    if not signed_attrs:
        return False, "SignerInfo has no signed attributes", info
    message_digest = None
    content_type = None
    for attr in signed_attrs:
        if attr["type"].native == "message_digest":
            message_digest = attr["values"][0].native
        elif attr["type"].native == "content_type":
            content_type = attr["values"][0].native
    if content_type != "tst_info":
        return False, "signed content-type attribute is not id-ct-TSTInfo", info
    if message_digest != hashlib.new(digest_name, tst_der).digest():
        return False, "signed message-digest attribute does not match TSTInfo", info

    certificates = [c.chosen for c in (signed_data["certificates"] or []) if c.name == "certificate"]
    anchor_certs = list(anchors or [])
    sid = signer["sid"]

    def matches_sid(cert) -> bool:
        if sid.name == "issuer_and_serial_number":
            return (
                cert.issuer == sid.chosen["issuer"]
                and cert.serial_number == sid.chosen["serial_number"].native
            )
        return cert.key_identifier == sid.chosen.native

    signer_asn1 = next((c for c in certificates if matches_sid(c)), None)
    if signer_asn1 is None:
        return False, "TSA signer certificate is not embedded in the token", info
    signer_cert = x509.load_der_x509_certificate(signer_asn1.dump())
    embedded = [x509.load_der_x509_certificate(c.dump()) for c in certificates]

    signed_bytes = b"\x31" + signed_attrs.dump()[1:]  # [0] IMPLICIT -> SET OF for signing
    signature = signer["signature"].native
    sig_alg = signer["signature_algorithm"]["algorithm"].native
    public_key = signer_cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if sig_alg == "rsassa_pss":
                params = signer["signature_algorithm"]["parameters"]
                pss_hash = getattr(hashes, params["hash_algorithm"]["algorithm"].native.upper())()
                public_key.verify(
                    signature, signed_bytes,
                    padding.PSS(mgf=padding.MGF1(pss_hash), salt_length=params["salt_length"].native),
                    pss_hash,
                )
            else:
                hash_name = _RSA_SIG_HASH.get(sig_alg, digest_name)
                public_key.verify(
                    signature, signed_bytes, padding.PKCS1v15(), getattr(hashes, hash_name.upper())()
                )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            hash_name = _EC_SIG_HASH.get(sig_alg, digest_name)
            public_key.verify(signature, signed_bytes, ec.ECDSA(getattr(hashes, hash_name.upper())()))
        else:
            return False, f"unsupported TSA key type {type(public_key).__name__}", info
    except InvalidSignature:
        return False, "TSA signature is INVALID", info

    try:
        eku = signer_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False, "TSA certificate lacks the timeStamping extended key usage", info
    if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
        return False, "TSA certificate is not authorised for timeStamping", info
    gen_time = info["gen_time"]
    if not (signer_cert.not_valid_before_utc <= gen_time <= signer_cert.not_valid_after_utc):
        return False, "genTime is outside the TSA certificate validity period", info
    info["tsa"] = info["tsa"] or signer_cert.subject.rfc4514_string()

    if anchor_certs:
        pool = embedded + anchor_certs
        current = signer_cert
        for _depth in range(8):
            if any(current == anchor for anchor in anchor_certs):
                info["anchored"] = True
                break
            issuer = None
            for candidate in pool:
                if candidate.subject != current.issuer or candidate == current:
                    continue
                try:
                    current.verify_directly_issued_by(candidate)
                except Exception:
                    continue
                issuer = candidate
                break
            if issuer is None:
                break
            current = issuer
        if not info["anchored"]:
            return False, "TSA certificate does not chain to a supplied trust anchor", info
    return True, "signature valid", info


def _merkle_leaf(entry_hash_hex: str) -> bytes:
    data = bytes.fromhex(entry_hash_hex)
    if len(data) != 32:
        raise ValueError("entry hash is not 32 bytes")
    return hashlib.sha256(b"\x00" + data).digest()


def merkle_root_from_path(entry_hash_hex: str, path: list) -> bytes:
    """Fold a sentinel-merkle-v1 inclusion path (leaf = H(0x00||h), node = H(0x01||l||r))."""
    current = _merkle_leaf(entry_hash_hex)
    for step in path:
        if not isinstance(step, dict):
            raise ValueError("Merkle path step is not an object")
        sibling = bytes.fromhex(str(step.get("hash", "")))
        if len(sibling) != 32:
            raise ValueError("Merkle path hash is not 32 bytes")
        if step.get("position") == "left":
            current = hashlib.sha256(b"\x01" + sibling + current).digest()
        elif step.get("position") == "right":
            current = hashlib.sha256(b"\x01" + current + sibling).digest()
        else:
            raise ValueError(f"unknown Merkle path position {step.get('position')!r}")
    return current


def check_audit_entry_timestamps(extract_dir: str, anchors: list | None):
    """Verify per-entry audit timestamp proofs in audit_chain.json.

    Returns (verified_entries, total_entries, failures, notes). Two proof forms:
    a batch anchor (``timestamp_proof`` + ``timestamp_anchors``: the entry hash
    folds up its Merkle path to a root that a verified RFC3161 token covers) and
    the legacy per-entry ``timestamp_token_base64`` whose imprint is the entry
    hash. Entries without a proof are reported, not failed: the worker anchors
    on a schedule and the package-level timestamp still covers them.
    """
    chain_path = os.path.join(extract_dir, "audit_chain.json")
    if not os.path.exists(chain_path):
        return 0, 0, [], []  # case packages carry audit chains inside each event package
    try:
        chain = _load_json(chain_path)
    except Exception as e:
        return 0, 0, [f"audit timestamps: cannot read audit_chain.json: {e}"], []
    entries = chain.get("entries", []) if isinstance(chain, dict) else []
    anchors_section = chain.get("timestamp_anchors") if isinstance(chain, dict) else None
    anchors_section = anchors_section if isinstance(anchors_section, dict) else {}
    failures: list[str] = []
    notes: list[str] = []
    batch_results: dict[str, tuple[bool, str, dict]] = {}
    verified = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        seq = entry.get("sequence")
        entry_hash = str(entry.get("entry_hash") or "")
        proof = entry.get("timestamp_proof")
        legacy = entry.get("timestamp_token_base64")
        try:
            if proof is not None:
                if not isinstance(proof, dict):
                    raise ValueError("timestamp_proof is not an object")
                batch_id = str(proof.get("batch_id") or "")
                batch = anchors_section.get(batch_id)
                if not isinstance(batch, dict):
                    raise ValueError(f"anchor batch {batch_id or '?'} is missing")
                if batch.get("tree_alg") != "sentinel-merkle-v1":
                    raise ValueError(f"unsupported tree algorithm {batch.get('tree_alg')!r}")
                root_hex = str(batch.get("merkle_root") or "").lower()
                if merkle_root_from_path(entry_hash, proof.get("path") or []).hex() != root_hex:
                    raise ValueError("Merkle path does not lead to the timestamped root")
                if batch_id not in batch_results:
                    token_der = base64.b64decode(str(batch.get("token_base64") or ""), validate=True)
                    batch_results[batch_id] = verify_timestamp_token(
                        token_der, bytes.fromhex(root_hex), anchors
                    )
                ok, detail, _info = batch_results[batch_id]
                if not ok:
                    raise ValueError(f"anchor batch token: {detail}")
                verified += 1
            elif legacy:
                token_der = base64.b64decode(str(legacy), validate=True)
                ok, detail, _info = verify_timestamp_token(
                    token_der, bytes.fromhex(entry_hash), anchors
                )
                if not ok:
                    raise ValueError(f"per-entry token: {detail}")
                verified += 1
        except Exception as e:
            failures.append(f"audit entry seq {seq}: {e}")
    unproven = len(entries) - verified - len(failures)
    if entries:
        notes.append(
            f"audit entries: {verified}/{len(entries)} carry a verified RFC3161 proof"
            + (f" ({len(batch_results)} batch anchor(s))" if batch_results else "")
            + (f"; {unproven} not yet anchored when exported" if unproven > 0 else "")
        )
    return verified, len(entries), failures, notes


def check_rfc3161_tokens(
    extract_dir: str,
    trust_anchors: str | None = None,
    allow_no_timestamps: bool = False,
) -> CheckResult:
    """Verify RFC3161 timestamp tokens and bind them to signed package content."""
    name = "RFC3161 Timestamps"
    timestamps_path = os.path.join(extract_dir, "timestamps.json")
    tokens = []
    if os.path.exists(timestamps_path):
        try:
            ts_data = _load_json(timestamps_path)
        except Exception as e:
            return CheckResult(name, False, f"Cannot read timestamps.json: {e}", exit_code=1)
        tokens = ts_data.get("tokens", []) if isinstance(ts_data, dict) else []

    try:
        import asn1crypto  # noqa: F401
        import cryptography  # noqa: F401
    except ImportError:
        return CheckResult(
            name, False,
            "The 'asn1crypto' and 'cryptography' packages are required to verify timestamps",
            exit_code=1,
        )

    anchors = None
    if trust_anchors:
        try:
            anchors = _load_pem_certificates(trust_anchors)
        except Exception as e:
            return CheckResult(name, False, f"Cannot load trust anchors: {e}", exit_code=1)

    # Audit-entry proofs are checked even when the package-level token is absent:
    # a proof that is present must be valid.
    _entry_verified, _entry_total, entry_failures, entry_notes = check_audit_entry_timestamps(
        extract_dir, anchors
    )
    if entry_failures:
        return CheckResult(
            name, False,
            f"{len(entry_failures)} audit timestamp failure(s):\n" + "\n".join(entry_failures),
            exit_code=4,
        )

    if not tokens:
        if allow_no_timestamps:
            return CheckResult(
                name, True,
                "WARNING: no package-level RFC3161 timestamp in bundle (allowed by "
                "--allow-no-timestamps)" + "".join("\n" + note for note in entry_notes),
                warning=True,
            )
        return CheckResult(
            name, False,
            "No RFC3161 timestamp tokens in bundle. Use --allow-no-timestamps to accept.",
            exit_code=4,
        )

    try:
        manifest = _load_manifest(extract_dir)
    except Exception as e:
        return CheckResult(name, False, f"Cannot read manifest: {e}", exit_code=1)
    signature = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else {}
    bound_values = {
        "audit_chain_final_hash": manifest.get("audit_final_hash"),
        "casepack_payload_hash": signature.get("payload_hash_hex")
        or _compute_casepack_payload_hash(extract_dir, manifest),
    }

    verified = 0
    bound = 0
    failures = []
    notes = list(entry_notes)
    for token_info in tokens:
        subject = token_info.get("subject", "unknown")
        sha256_hex = str(token_info.get("sha256_hex") or "").lower()
        token_file = str(token_info.get("token_file") or "")
        normalized = PurePosixPath(token_file.replace("\\", "/"))
        if not token_file or normalized.is_absolute() or ".." in normalized.parts:
            failures.append(f"{subject}: invalid token_file path")
            continue
        token_path = os.path.join(extract_dir, *normalized.parts)
        if not os.path.isfile(token_path):
            failures.append(f"{subject}: token file missing ({token_file})")
            continue
        if len(sha256_hex) != 64:
            failures.append(f"{subject}: no valid sha256_hex in timestamps.json")
            continue

        if subject in bound_values:
            expected = bound_values[subject]
            if not expected or sha256_hex != str(expected).lower():
                failures.append(f"{subject}: timestamped hash does not match the signed package")
                continue
        else:
            notes.append(f"{subject}: legacy subject, not bound to signed content")

        with open(token_path, "rb") as f:
            token_der = f.read()
        try:
            ok, detail, info = verify_timestamp_token(token_der, bytes.fromhex(sha256_hex), anchors)
        except Exception as e:
            failures.append(f"{subject}: cannot parse token: {e}")
            continue
        if not ok:
            failures.append(f"{subject}: {detail}")
            continue
        verified += 1
        if subject in bound_values:
            bound += 1
        notes.append(f"{subject}: {info.get('gen_time')} by {info.get('tsa')}")

    if failures:
        return CheckResult(
            name, False,
            f"{len(failures)} failure(s):\n" + "\n".join(failures),
            exit_code=4
        )
    if bound == 0 and not allow_no_timestamps:
        return CheckResult(
            name, False,
            "No timestamp is bound to the signed package (audit_chain_final_hash or "
            "casepack_payload_hash)\n" + "\n".join(notes),
            exit_code=4,
        )
    detail = f"{verified} token(s) cryptographically verified, {bound} bound to signed content"
    if notes:
        detail += "\n" + "\n".join(notes)
    if anchors is None:
        return CheckResult(
            name, True,
            detail + "\nWARNING: TSA certificate not anchored; supply --trust-anchors to "
            "authenticate the timestamp authority",
            warning=True,
        )
    return CheckResult(name, True, detail + "\nTSA certificate chains to a supplied trust anchor")


CHECKPOINT_FORMAT = "sentinel-audit-checkpoint/1"
CHECKPOINT_LIST_FORMAT = "sentinel-audit-checkpoints/1"


def _checkpoint_bytes(document: dict) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _load_anchor_file(trust_anchors: str | None):
    return _load_pem_certificates(trust_anchors) if trust_anchors else None


def verify_checkpoint_record(record, trusted_keys: set[str], anchors):
    """One public audit checkpoint: digest, issuer signature and RFC3161 token.

    The issuer signs the 32-byte SHA-256 digest of the canonical document and the
    TSA timestamps the same digest. Returns (ok, detail, document, warning).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(record, dict) or not isinstance(record.get("document"), dict):
        return False, "malformed checkpoint record", None, False
    document = record["document"]
    if document.get("format") != CHECKPOINT_FORMAT:
        return False, f"unsupported format {document.get('format')!r}", None, False
    digest = hashlib.sha256(_checkpoint_bytes(document)).digest()
    if digest.hex() != str(record.get("digest_sha256") or "").lower():
        return False, "digest does not match the document", None, False
    key_hex = _normalize_key_hex(str(record.get("public_key_hex") or ""))
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
            bytes.fromhex(str(record.get("signature_hex") or "")), digest
        )
    except Exception:
        return False, "issuer signature is invalid", None, False
    if trusted_keys and key_hex not in trusted_keys:
        return False, f"signed by untrusted key {key_hex[:16]}...", None, False
    try:
        token_der = base64.b64decode(str(record.get("timestamp_token_base64") or ""), validate=True)
    except Exception:
        return False, "timestamp token is not valid base64", None, False
    ok, detail, info = verify_timestamp_token(token_der, digest, anchors)
    if not ok:
        return False, f"timestamp: {detail}", None, False
    when = info.get("gen_time") if isinstance(info, dict) else None
    detail = f"signed and timestamped{f' at {when}' if when else ''}"
    return True, detail, document, not trusted_keys


def check_public_checkpoints(
    extract_dir: str, trusted_keys: set[str], trust_anchors: str | None = None
) -> CheckResult:
    """Every audit anchor batch that cites a public checkpoint is listed in it, unchanged."""
    name = "Public Audit Checkpoints"
    chain_path = os.path.join(extract_dir, "audit_chain.json")
    if not os.path.exists(chain_path):
        return CheckResult(name, True, "not applicable (no audit_chain.json)")
    try:
        chain = _load_json(chain_path)
        anchors = _load_anchor_file(trust_anchors)
    except Exception as e:
        return CheckResult(name, False, f"Cannot read inputs: {e}", exit_code=1)
    batches = chain.get("timestamp_anchors") if isinstance(chain, dict) else None
    batches = batches if isinstance(batches, dict) else {}
    records = chain.get("public_checkpoints") if isinstance(chain, dict) else None
    records = records if isinstance(records, list) else []
    if not batches:
        return CheckResult(name, True, "no audit anchor batches in this package")

    failures: list[str] = []
    documents: dict[int, dict] = {}
    unpinned = False
    for record in records:
        ok, detail, document, warn = verify_checkpoint_record(record, trusted_keys, anchors)
        if not ok:
            seq = record.get("sequence") if isinstance(record, dict) else "?"
            failures.append(f"checkpoint {seq}: {detail}")
            continue
        documents[int(document.get("sequence"))] = document
        unpinned = unpinned or warn
    published, pending = 0, 0
    for batch_id, batch in batches.items():
        sequence = batch.get("checkpoint_sequence") if isinstance(batch, dict) else None
        if sequence is None:
            pending += 1
            continue
        document = documents.get(sequence)
        if document is None:
            failures.append(f"batch {batch_id}: checkpoint {sequence} is missing or invalid")
            continue
        listed = next(
            (b for b in document.get("batches", []) if isinstance(b, dict)
             and b.get("batch_id") == batch_id),
            None,
        )
        try:
            token_sha = hashlib.sha256(
                base64.b64decode(str(batch.get("token_base64") or ""), validate=True)
            ).hexdigest()
        except Exception:
            token_sha = None
        if (
            listed is None
            or listed.get("merkle_root") != batch.get("merkle_root")
            or listed.get("leaf_count") != batch.get("leaf_count")
            or listed.get("timestamp_token_sha256") != token_sha
        ):
            failures.append(f"batch {batch_id}: differs from public checkpoint {sequence}")
            continue
        published += 1
    if failures:
        return CheckResult(
            name, False, f"{len(failures)} problem(s):\n" + "\n".join(failures), exit_code=3
        )
    detail = (
        f"{published}/{len(batches)} audit anchor batch(es) listed in signed, timestamped "
        f"public checkpoint(s) {', '.join(f'#{n}' for n in sorted(documents)) or '-'}"
    )
    if pending:
        detail += (
            f"\n{pending} batch(es) were not yet in a public checkpoint when exported; compare "
            "with the issuer's log at /.well-known/sentinel-audit-checkpoints.json"
        )
    if unpinned:
        detail += "\nWARNING: checkpoint signer not pinned - re-run with --public-key <issuer key>"
    return CheckResult(name, True, detail, warning=bool(pending) or unpinned)


def verify_checkpoint_log(path: str, trusted_keys: set[str], trust_anchors: str | None):
    """A downloaded public checkpoint log: every record valid and the chain unbroken.

    Returns (CheckResult, {sequence: digest}).
    """
    name = "Public Audit Checkpoint Log"
    try:
        data = _load_json(path)
        anchors = _load_anchor_file(trust_anchors)
    except Exception as e:
        return CheckResult(name, False, f"Cannot read inputs: {e}", exit_code=1), {}
    if not isinstance(data, dict) or data.get("format") != CHECKPOINT_LIST_FORMAT:
        return CheckResult(name, False, "not a sentinel-audit-checkpoints/1 file", exit_code=1), {}
    records = [r for r in data.get("checkpoints", []) if isinstance(r, dict)]
    records.sort(key=lambda r: r.get("sequence") or 0)
    if not records:
        return CheckResult(name, True, "the log is empty", warning=True), {}
    failures: list[str] = []
    digests: dict[int, str] = {}
    previous: tuple[int, str] | None = None
    unpinned = False
    last_document = None
    for record in records:
        ok, detail, document, warn = verify_checkpoint_record(record, trusted_keys, anchors)
        if not ok:
            failures.append(f"checkpoint {record.get('sequence')}: {detail}")
            previous = None
            continue
        unpinned = unpinned or warn
        sequence = int(document.get("sequence"))
        if previous is not None:
            if sequence != previous[0] + 1:
                failures.append(f"checkpoint {sequence}: gap after {previous[0]}")
            elif document.get("previous_digest_sha256") != previous[1]:
                failures.append(f"checkpoint {sequence}: does not chain to {previous[0]}")
        elif sequence == 1 and document.get("previous_digest_sha256") is not None:
            failures.append("checkpoint 1: must not have a predecessor")
        previous = (sequence, record["digest_sha256"])
        digests[sequence] = record["digest_sha256"]
        last_document = document
    if failures:
        return CheckResult(
            name, False, f"{len(failures)} problem(s):\n" + "\n".join(failures), exit_code=3
        ), digests
    first, last = min(digests), max(digests)
    totals = (last_document or {}).get("totals") or {}
    detail = (
        f"{len(digests)} checkpoint(s) #{first}..#{last}, each signed and timestamped, chain "
        f"intact{' (partial log)' if first > 1 else ''}; last issued "
        f"{(last_document or {}).get('issued_at')}, covering {totals.get('entries', '?')} audit "
        f"entries in {totals.get('batches', '?')} batch(es)"
    )
    if unpinned:
        detail += "\nWARNING: checkpoint signer not pinned - re-run with --public-key <issuer key>"
    return CheckResult(name, True, detail, warning=unpinned), digests


def check_pack_against_log(zip_path: str, log_digests: dict[int, str]) -> CheckResult:
    """The checkpoints inside an event Case Pack are the ones in the public log."""
    name = "Case Pack vs Public Log"
    try:
        with zipfile.ZipFile(zip_path) as archive:
            if "audit_chain.json" not in archive.namelist():
                return CheckResult(name, True, "not applicable (no audit_chain.json at top level)")
            chain = json.loads(archive.read("audit_chain.json"))
    except Exception as e:
        return CheckResult(name, False, f"Cannot read audit_chain.json: {e}", exit_code=1)
    records = chain.get("public_checkpoints") if isinstance(chain, dict) else None
    records = records if isinstance(records, list) else []
    mismatched = []
    missing = []
    for record in records:
        sequence = record.get("sequence") if isinstance(record, dict) else None
        if sequence not in log_digests:
            missing.append(str(sequence))
        elif log_digests[sequence] != str(record.get("digest_sha256") or "").lower():
            mismatched.append(str(sequence))
    if mismatched:
        return CheckResult(
            name, False,
            "checkpoint(s) in the pack differ from the public log: #" + ", #".join(mismatched),
            exit_code=3,
        )
    detail = f"{len(records) - len(missing)} checkpoint(s) in the pack match the public log"
    if missing:
        detail += f"; not in the supplied log: #{', #'.join(missing)}"
    return CheckResult(name, True, detail, warning=bool(missing))


def check_worm_proof(extract_dir: str, allow_no_worm: bool = False) -> CheckResult:
    """Verify worm_proof.json covers every stored evidence item in COMPLIANCE mode."""
    worm_path = os.path.join(extract_dir, "worm_proof.json")
    if not os.path.exists(worm_path):
        if allow_no_worm:
            return CheckResult(
                "WORM Proof", True,
                "WARNING: no worm_proof.json (allowed by --allow-no-worm)",
                warning=True,
            )
        return CheckResult(
            "WORM Proof", False,
            "No worm_proof.json found. Use --allow-no-worm to accept.",
            exit_code=2
        )

    try:
        worm_data = _load_json(worm_path)
        manifest = _load_manifest(extract_dir)
    except Exception as e:
        return CheckResult("WORM Proof", False, f"Cannot read files: {e}", exit_code=1)

    if isinstance(worm_data, list):
        worm_items = worm_data
    elif isinstance(worm_data, dict):
        worm_items = worm_data.get("items", [])
    else:
        return CheckResult("WORM Proof", False, "worm_proof.json must be a list", exit_code=2)

    evidence_map = {
        str(item.get("id")): item
        for item in manifest.get("evidence_items", [])
        if _expects_evidence_file(item)
    }
    if not worm_items and not evidence_map:
        return CheckResult("WORM Proof", True, "No stored evidence items")

    issues = []
    compliance_count = 0
    covered = set()

    for wi in worm_items:
        eid = str(wi.get("evidence_id") or "")
        label = eid or wi.get("object_key") or "unknown"
        missing = [
            field for field in ("bucket", "object_key", "version_id", "etag", "size")
            if wi.get(field) in (None, "")
        ]
        if missing:
            issues.append(f"{label}: missing {', '.join(missing)}")

        if eid and eid in evidence_map:
            covered.add(eid)
            worm_hash = wi.get("file_hash_sha256")
            manifest_hash = evidence_map[eid].get("file_hash_sha256")
            if worm_hash and manifest_hash and worm_hash != manifest_hash:
                issues.append(f"{eid}: hash mismatch worm vs manifest")

        mode = str(wi.get("retention_mode") or "").upper()
        if "COMPLIANCE" in mode:
            compliance_count += 1
        elif mode:
            issues.append(f"{label}: retention mode is {mode}, expected COMPLIANCE")
        else:
            issues.append(f"{label}: no retention mode recorded")

    uncovered = sorted(set(evidence_map) - covered)
    for eid in uncovered:
        issues.append(f"{eid}: no WORM proof for stored evidence item")

    if issues:
        return CheckResult(
            "WORM Proof", False,
            "\n".join(issues), exit_code=2
        )

    return CheckResult(
        "WORM Proof", True,
        f"{len(worm_items)} item(s), {compliance_count} in COMPLIANCE mode, "
        f"all {len(evidence_map)} stored evidence item(s) covered"
    )


def verify_event_package(zip_path: str, args, trusted_keys: set[str]) -> VerificationReport:
    """All checks for one event Case Pack (1.0-1.3)."""
    report = VerificationReport()

    # 1. ZIP Integrity
    result = check_zip_integrity(zip_path)
    report.checks.append(result)
    if not result.passed:
        return report

    # 2. Extract and verify
    with tempfile.TemporaryDirectory(prefix="sentinel_verify_") as tmpdir:
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                safe_extract_archive(zf, tmpdir)
        except (zipfile.BadZipFile, ValueError) as exc:
            report.checks.append(
                CheckResult("ZIP Safe Extraction", False, str(exc), exit_code=1)
            )
            return report

        required = check_required_files(tmpdir)
        report.checks.append(required)
        if not required.passed:
            return report

        # Explicit package version, with legacy compatibility.
        report.checks.append(check_package_format(tmpdir))

        # Manifest hash verification
        report.checks.append(check_manifest_hashes(tmpdir))

        # Case Pack 1.2 media index / crawl map / network log / screenshots
        report.checks.append(check_capture_indexes(tmpdir))

        # Case Pack 1.3 WARC / HAR / MHTML / PDF / page metadata
        report.checks.append(check_capture_archives(tmpdir))

        # Ed25519 Signature (strict by default)
        report.checks.append(
            check_signature(
                zip_path, tmpdir,
                allow_unsigned=args.allow_unsigned,
                trusted_keys=trusted_keys,
            )
        )

        # Audit chain
        report.checks.append(check_audit_chain(tmpdir))

        # RFC3161 timestamps (strict by default)
        report.checks.append(
            check_rfc3161_tokens(
                tmpdir, args.trust_anchors, allow_no_timestamps=args.allow_no_timestamps
            )
        )

        # WORM proof (strict by default)
        report.checks.append(
            check_public_checkpoints(tmpdir, trusted_keys, trust_anchors=args.trust_anchors)
        )
        report.checks.append(check_worm_proof(tmpdir, allow_no_worm=args.allow_no_worm))

    return report



CASE_BUNDLE_FORMAT = "sentinel-case-bundle"
CASE_PACKAGE_FILES = {
    "manifest.json", "package_metadata.json", "timeline.json", "report.pdf", "timestamps.json",
}
CASE_MAX_UNCOMPRESSED_BYTES = 8 * 1024 * 1024 * 1024
_UUID_CHARS = set("0123456789abcdef-")


def _archive_manifest(zip_path: str):
    """manifest.json of an archive without extracting it, or None."""
    try:
        with zipfile.ZipFile(zip_path) as zf:
            info = zf.getinfo("manifest.json")
            if info.file_size > 64 * 1024 * 1024:
                return None
            return json.loads(zf.read(info))
    except Exception:
        return None


def check_case_manifest(extract_dir: str):
    """Case package (sentinel-case-bundle/2.x): declared event packages, hashes, no extras."""
    name = "Case Manifest"
    try:
        manifest = _load_manifest(extract_dir)
        metadata = _load_json(os.path.join(extract_dir, "package_metadata.json"))
    except Exception as e:
        return CheckResult(name, False, f"Cannot read case manifest/metadata: {e}", exit_code=1), []
    version = str(manifest.get("package_format_version") or "")
    if manifest.get("package_format") != CASE_BUNDLE_FORMAT or not version.startswith("2."):
        return CheckResult(name, False, f"Unsupported case package format {version!r}",
                           exit_code=1), []
    case_id = (manifest.get("case") or {}).get("id") if isinstance(manifest.get("case"), dict) else None
    for key, expected in (("package_format", CASE_BUNDLE_FORMAT), ("package_scope", "case"),
                          ("package_format_version", version), ("case_id", case_id)):
        if metadata.get(key) != expected:
            return CheckResult(name, False, f"package_metadata.json {key} does not match the manifest",
                               exit_code=2), []
    events = manifest.get("events")
    if not isinstance(events, list) or not events:
        return CheckResult(name, False, "Case manifest declares no event packages", exit_code=1), []
    declared: set[str] = set()
    for item in events:
        if not isinstance(item, dict):
            return CheckResult(name, False, "Malformed event entry", exit_code=2), []
        event_id = str(item.get("event_id") or "").lower()
        if not event_id or not set(event_id) <= _UUID_CHARS:
            return CheckResult(name, False, f"Invalid event id {event_id!r}", exit_code=2), []
        expected_path = f"events/{event_id}.zip"
        if item.get("path") != expected_path or expected_path in declared:
            return CheckResult(name, False, f"Event {event_id}: unexpected or duplicate path",
                               exit_code=2), []
        declared.add(expected_path)
        path = os.path.join(extract_dir, "events", f"{event_id}.zip")
        if not os.path.isfile(path) or os.path.islink(path):
            return CheckResult(name, False, f"Event {event_id}: package file missing",
                               exit_code=2), []
        if _sha256_file(path) != str(item.get("sha256") or "").lower() or os.path.getsize(path) != item.get("size"):
            return CheckResult(name, False, f"Event {event_id}: package hash or size mismatch",
                               exit_code=2), []
    extras = []
    for root, _dirs, files in os.walk(extract_dir):
        for filename in files:
            rel = os.path.relpath(os.path.join(root, filename), extract_dir).replace(os.sep, "/")
            if rel in CASE_PACKAGE_FILES or rel in declared or rel.startswith("timestamp_tokens/"):
                continue
            extras.append(rel)
    if extras:
        return CheckResult(name, False, "Files not declared in the case manifest: "
                           + ", ".join(sorted(extras)[:10]), exit_code=2), []
    return CheckResult(
        name, True, f"case {case_id}: {len(events)} event package(s) declared and hash-verified"
    ), events


def _summarize_event(event_id: str, nested: VerificationReport) -> CheckResult:
    failed = [c for c in nested.checks if not c.passed]
    warned = [c for c in nested.checks if c.passed and c.warning]
    if failed:
        detail = "\n".join(f"{c.name}: {c.detail.splitlines()[0] if c.detail else 'failed'}"
                           for c in failed)
        return CheckResult(f"Event {event_id}", False, detail, exit_code=nested.worst_exit_code)
    detail = f"{len(nested.checks)} checks passed"
    if warned:
        detail += " (warnings: " + ", ".join(c.name for c in warned) + ")"
    return CheckResult(f"Event {event_id}", True, detail, warning=bool(warned))


def verify_case_package(zip_path: str, args, trusted_keys: set[str]) -> VerificationReport:
    """A case package: a signed, timestamped manifest over complete event Case Packs.

    The case manifest, its signature and payload timestamp are verified first;
    then every nested event package gets the full event verification. Each
    nested package must declare the event id and payload hash the case manifest
    records, and be signed by the same key as the case manifest.
    """
    report = VerificationReport()
    result = check_zip_integrity(zip_path)
    report.checks.append(result)
    if not result.passed:
        return report
    with tempfile.TemporaryDirectory(prefix="sentinel_verify_case_") as tmpdir:
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                safe_extract_archive(zf, tmpdir, max_uncompressed_bytes=CASE_MAX_UNCOMPRESSED_BYTES)
        except (zipfile.BadZipFile, ValueError) as exc:
            report.checks.append(CheckResult("ZIP Safe Extraction", False, str(exc), exit_code=1))
            return report
        manifest_check, events = check_case_manifest(tmpdir)
        report.checks.append(manifest_check)
        if not manifest_check.passed:
            return report
        report.checks.append(
            check_signature(zip_path, tmpdir, allow_unsigned=args.allow_unsigned,
                            trusted_keys=trusted_keys)
        )
        report.checks.append(
            check_rfc3161_tokens(tmpdir, args.trust_anchors,
                                 allow_no_timestamps=args.allow_no_timestamps)
        )
        case_signature = _load_manifest(tmpdir).get("signature") or {}
        case_signer = _normalize_key_hex(str(case_signature.get("public_key_hex") or ""))
        for item in events:
            event_id = str(item["event_id"]).lower()
            nested_path = os.path.join(tmpdir, "events", f"{event_id}.zip")
            nested_manifest = _archive_manifest(nested_path) or {}
            nested_signature = nested_manifest.get("signature") or {}
            problems = []
            if str(nested_manifest.get("event_id") or "").lower() != event_id:
                problems.append("event id differs from the case manifest")
            declared_hash = item.get("payload_hash_hex")
            if declared_hash and nested_signature.get("payload_hash_hex") != declared_hash:
                problems.append("signed payload hash differs from the case manifest")
            nested_signer = _normalize_key_hex(str(nested_signature.get("public_key_hex") or ""))
            if case_signer and nested_signer and nested_signer != case_signer:
                problems.append("signed by a different key than the case manifest")
            if problems:
                report.checks.append(CheckResult(f"Event {event_id}", False, "; ".join(problems),
                                                 exit_code=2))
                continue
            report.checks.append(
                _summarize_event(event_id, verify_event_package(nested_path, args, trusted_keys))
            )
    return report


def verify_package(zip_path: str, args, trusted_keys: set[str]) -> VerificationReport:
    manifest = _archive_manifest(zip_path)
    if isinstance(manifest, dict) and manifest.get("package_scope") == "case":
        return verify_case_package(zip_path, args, trusted_keys)
    return verify_event_package(zip_path, args, trusted_keys)


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Offline Verifier — Court-Proof Case Pack Verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("zip_path", nargs="?", help="Path to the Case Pack ZIP file")
    parser.add_argument(
        "--checkpoints",
        default=None,
        help="Downloaded public audit checkpoint log (/.well-known/sentinel-audit-checkpoints.json)"
        "; verified on its own and, with a Case Pack, compared with the pack's checkpoints",
    )
    parser.add_argument(
        "--public-key", "-k",
        action="append",
        default=[],
        help="Trusted Ed25519 public key (hex) of the issuing Sentinel instance; repeatable",
    )
    parser.add_argument(
        "--trusted-keys",
        default=None,
        help="File with trusted Ed25519 public keys, one hex key per line",
    )
    parser.add_argument(
        "--trust-anchors", "-t",
        help="PEM file with trusted TSA root/intermediate certificates",
        default=None
    )
    parser.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="Accept bundles without Ed25519 signature",
    )
    parser.add_argument(
        "--allow-no-worm",
        action="store_true",
        help="Accept bundles without worm_proof.json",
    )
    parser.add_argument(
        "--allow-no-timestamps",
        action="store_true",
        help="Accept bundles without RFC3161 timestamps bound to the signed content",
    )
    args = parser.parse_args()

    zip_path = args.zip_path
    if not zip_path and not args.checkpoints:
        parser.error("give a Case Pack ZIP, --checkpoints, or both")
    for path in (zip_path, args.checkpoints):
        if path and not os.path.exists(path):
            print(f"{C.FAIL}File not found: {path}{C.END}")
            sys.exit(1)

    try:
        trusted_keys = load_trusted_keys(args.public_key, args.trusted_keys)
    except (OSError, ValueError) as exc:
        print(f"{C.FAIL}Invalid trusted key input: {exc}{C.END}")
        sys.exit(1)

    report = verify_package(zip_path, args, trusted_keys) if zip_path else VerificationReport()
    if args.checkpoints:
        log_check, log_digests = verify_checkpoint_log(
            args.checkpoints, trusted_keys, args.trust_anchors
        )
        report.checks.append(log_check)
        if zip_path and log_check.passed:
            report.checks.append(check_pack_against_log(zip_path, log_digests))
    report.print_report()
    sys.exit(report.worst_exit_code)

if __name__ == "__main__":
    main()
