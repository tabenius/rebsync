#!/usr/bin/env python3
"""P0: encrypted restic S3 layer-store evacuation with independently verified restore.

Runs on two different machines; this tool intentionally does not initialize,
prune, delete or reconfigure a remote restic repository. Receipt is PRIVATE:
it reveals the source machine's original filesystem paths and file names.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

SCHEMA = "rbq.s3-layer-recovery.v1"


def fail(message: str) -> None:
    raise RuntimeError(message)


def private_env() -> None:
    repository = os.environ.get("RESTIC_REPOSITORY", "")
    if not repository.startswith("s3:https://"):
        fail("RESTIC_REPOSITORY must be an existing s3:https:// repository (R2 or S3)")
    if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get("AWS_SECRET_ACCESS_KEY"):
        fail("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be supplied outside Git")
    if os.environ.get("RESTIC_PASSWORD") or os.environ.get("RESTIC_PASSWORD_COMMAND"):
        fail("Use RESTIC_PASSWORD_FILE; inline/command password sources are intentionally refused")
    password = os.environ.get("RESTIC_PASSWORD_FILE", "")
    if not password:
        fail("RESTIC_PASSWORD_FILE must refer to an independently recoverable owner-only file")
    path = Path(password)
    if path.is_symlink() or not path.is_file():
        fail("RESTIC_PASSWORD_FILE must be a regular non-symlink file")
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            fail("RESTIC_PASSWORD_FILE must not grant group/other access (chmod 600)")
    if not path.read_bytes().strip():
        fail("RESTIC_PASSWORD_FILE is empty")
    if not shutil.which("restic"):
        fail("restic is required in PATH")


def run(args: list[str], *, capture: bool = False) -> str:
    result = subprocess.run(
        args, text=True, stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None, check=False,
    )
    if result.returncode:
        # Avoid exposing potentially secret repository URLs in subprocess diagnostics.
        fail(f"{args[0]} {args[1] if len(args) > 1 else ''} failed (exit {result.returncode})")
    return result.stdout if capture else ""


def tree(path: Path) -> list[dict[str, object]]:
    """Hash every file; reject symlinks, special files, empty stores, escaping paths."""
    if path.is_symlink() or not path.is_dir():
        fail("storage root must be an existing directory, not a symlink")
    entries = []
    for root, dirs, files in os.walk(path, followlinks=False):
        root_path = Path(root)
        for name in dirs:
            child = root_path / name
            if child.is_symlink():
                fail("storage root contains a symlinked directory; refusing ambiguous recovery")
        for name in files:
            child = root_path / name
            if child.is_symlink() or not child.is_file():
                fail("storage root contains a symlink or non-regular file")
            digest = hashlib.sha256()
            size = 0
            with child.open("rb") as handle:
                while block := handle.read(1024 * 1024):
                    digest.update(block)
                    size += len(block)
            entries.append({
                "path": child.relative_to(path).as_posix(),
                "bytes": size,
                "sha256": digest.hexdigest(),
            })
    entries.sort(key=lambda item: str(item["path"]))
    if not entries or not any("/snapshots/" in "/" + str(item["path"]) for item in entries):
        fail("no Rebeqah layer snapshot manifests found; publish owner layers before backup")
    return entries


def fsck(path: Path) -> None:
    rbq = shutil.which("rbq")
    if not rbq:
        fail("rbq CLI must be installed to verify recovered owner-layer structure")
    run([rbq, "--storage-root", str(path), "storage", "fsck"])


def snapshot_id(output: str) -> str:
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if value.get("message_type") == "summary":
            token = value.get("snapshot_id")
            if isinstance(token, str) and len(token) == 64 and all(c in "0123456789abcdef" for c in token):
                return token
    fail("restic did not return an unambiguous complete 64-character snapshot ID")


def write_receipt(path: Path, payload: dict[str, object]) -> None:
    if path.is_symlink() or path.exists():
        fail("receipt already exists; never overwrite prior recovery evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, sort_keys=True, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def backup(args: argparse.Namespace) -> None:
    source = args.storage_root.resolve(strict=True)
    receipt = args.receipt
    if receipt.exists() or receipt.is_symlink():
        fail("receipt must be a new path")
    before = tree(source)
    fsck(source)
    if not args.apply:
        print(json.dumps({"status": "preflight-only", "files": len(before),
                          "bytes": sum(x["bytes"] for x in before),
                          "next": "repeat with --apply to upload encrypted objects"}))
        return
    private_env()
    # Restic encrypts client-side before uploading; this is NOT a plaintext S3 ObjectStorage adapter.
    tag = "rbq-m1-layer-store"
    output = run(["restic", "--json", "backup", "--tag", tag, "--", str(source)], capture=True)
    identifier = snapshot_id(output)
    after = tree(source)
    if before != after:
        fail("source objects changed during backup: no recovery receipt is issued")
    run(["restic", "cat", "snapshot", identifier], capture=True)
    if not args.skip_read_data:
        run(["restic", "check", "--read-data"])
    payload = {
        "schema": SCHEMA, "status": "remote-snapshot-verified-not-restored",
        "snapshot_id": identifier, "source_path": str(source),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "entries": before,
        "verification": {"source_fsck": True, "restic_read_data": not args.skip_read_data,
                         "independent_restore": False},
    }
    write_receipt(receipt, payload)
    print(json.dumps({"status": payload["status"], "snapshot_id": identifier,
                      "files": len(before), "read_data": not args.skip_read_data,
                      "receipt": str(receipt)}))


def restore(args: argparse.Namespace) -> None:
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    if receipt.get("schema") != SCHEMA or receipt.get("status") != "remote-snapshot-verified-not-restored":
        fail("invalid or unsupported receipt")
    identifier = receipt.get("snapshot_id")
    source = Path(receipt.get("source_path", ""))
    if (not isinstance(identifier, str) or len(identifier) != 64
            or any(c not in "0123456789abcdef" for c in identifier)):
        fail("invalid snapshot identifier")
    if not source.is_absolute() or str(source) in ("", "/"):
        fail("invalid source path")
    entries = receipt.get("entries")
    if not isinstance(entries, list) or not entries:
        fail("receipt has no file manifest")
    if args.into.is_symlink() or args.into.exists():
        fail("restore destination exists; refusing any overwrite")
    if not args.apply:
        print(json.dumps({"status": "preflight-only", "snapshot_id": identifier,
                          "expected_files": len(entries), "destination": str(args.into)}))
        return
    private_env()
    if not shutil.which("rbq"):
        fail("rbq must be installed on the independent recovery machine")
    parent = args.into.parent.resolve(strict=True)
    scratch = Path(tempfile.mkdtemp(prefix=".rbq-restic-verify-", dir=parent))
    try:
        run(["restic", "restore", identifier, "--target", str(scratch)])
        restored_root = scratch / source.relative_to("/")
        if tree(restored_root) != entries:
            fail("restored bytes do not match the owner-side receipt; destination not published")
        fsck(restored_root)
        # Only after byte-for-byte validation and rbq structural verification.
        scratch.rename(args.into)
        print(json.dumps({
            "status": "independently-restored-structurally-verified",
            "snapshot_id": identifier, "files": len(entries),
            "restored_storage_root": str(args.into / source.relative_to("/")),
            "owner_format_validation": "run application-specific validators before claiming owner recovery",
        }))
    except BaseException:
        shutil.rmtree(scratch)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("backup", help="producer: back up the existing rbq object store")
    prepare.add_argument("--storage-root", type=Path, required=True)
    prepare.add_argument("--receipt", type=Path, required=True)
    prepare.add_argument("--apply", action="store_true")
    prepare.add_argument("--skip-read-data", action="store_true",
                         help="skip slow remote data check; report this limitation honestly")
    recovery = sub.add_parser("restore", help="independent machine: restore and verify exact bytes")
    recovery.add_argument("--receipt", type=Path, required=True)
    recovery.add_argument("--into", type=Path, required=True)
    recovery.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        (backup if args.command == "backup" else restore)(args)
        return 0
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as e:
        print(f"rbq-s3-recovery: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
