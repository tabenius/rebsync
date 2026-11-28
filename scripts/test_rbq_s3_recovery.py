"""Offline tests for the P0 encrypted-S3 recovery operator contract.

These mock restic and rbq process boundaries: passing does not establish that
S3 credentials, remote encryption or a real independent device worked.
"""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("rbq-s3-recovery.py")
spec = importlib.util.spec_from_file_location("rbq_s3_recovery", SCRIPT)
recovery = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = recovery
spec.loader.exec_module(recovery)


class RecoveryContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "hostA" / ".rbq" / "objects"
        self.source.mkdir(parents=True)
        self.data = self.source / "git" / "v1" / "snapshots" / "local" / "sample.json"
        self.data.parent.mkdir(parents=True)
        self.data.write_bytes(b'{"synthetic":true}')
        self.args = type("Args", (), {})()

    def test_empty_and_symlinked_storage_rejected(self):
        self.assertEqual(len(recovery.tree(self.source)), 1)
        self.data.unlink()
        with self.assertRaisesRegex(RuntimeError, "no Rebeqah layer"):
            recovery.tree(self.source)
        self.data.symlink_to(self.source / "missing")
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            recovery.tree(self.source)

    def test_exact_digest_and_size_are_recorded(self):
        entries = recovery.tree(self.source)
        self.assertEqual(entries[0]["path"], "git/v1/snapshots/local/sample.json")
        self.assertEqual(entries[0]["bytes"], len(self.data.read_bytes()))
        self.assertEqual(len(entries[0]["sha256"]), 64)

    def test_receipt_never_overwrites_and_is_private(self):
        receipt = self.root / "private" / "receipt.json"
        recovery.write_receipt(receipt, {"schema": recovery.SCHEMA})
        self.assertTrue(receipt.is_file())
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            recovery.write_receipt(receipt, {"new": True})
        if sys.platform != "win32":
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)

    def test_snapshot_id_requires_complete_restic_summary(self):
        identity = "a" * 64
        result = recovery.snapshot_id(
            '{"message_type":"status","snapshot_id":"b"}\n'
            + json.dumps({"message_type": "summary", "snapshot_id": identity})
        )
        self.assertEqual(result, identity)
        for report in ("", '{"message_type":"summary","snapshot_id":"short"}'):
            with self.assertRaisesRegex(RuntimeError, "snapshot ID"):
                recovery.snapshot_id(report)

    def test_backup_preflight_does_not_contact_cloud(self):
        args = type("Args", (), {
            "storage_root": self.source, "receipt": self.root / "receipt.json",
            "apply": False, "skip_read_data": False,
        })()
        with patch.object(recovery, "fsck") as check, patch.object(recovery, "private_env") as secrets:
            recovery.backup(args)
            check.assert_called_once()
            secrets.assert_not_called()
        self.assertFalse(args.receipt.exists())

    def test_independent_restore_checks_bytes_and_only_then_publishes(self):
        receipt = self.root / "receipt.json"
        snapshot = "a" * 64
        source = self.source
        recovery.write_receipt(receipt, {
            "schema": recovery.SCHEMA,
            "status": "remote-snapshot-verified-not-restored",
            "source_path": str(source),
            "snapshot_id": snapshot,
            "entries": recovery.tree(source),
        })
        args = type("Args", (), {
            "receipt": receipt, "into": self.root / "independent-restored", "apply": True,
        })()
        def fake_restic(argv, *, capture=False):
            self.assertEqual(argv[:2], ["restic", "restore"])
            stage = Path(argv[-1])
            destination = stage / source.relative_to("/")
            destination.parent.mkdir(parents=True)
            shutil.copytree(source, destination)
            return ""
        with patch.object(recovery, "private_env"), patch.object(recovery.shutil, "which", return_value="/usr/bin/rbq"), patch.object(recovery, "run", side_effect=fake_rest), patch.object(recovery, "fsck") as owner:
            recovery.restore(args)
            owner.assert_called_once()
        self.assertEqual(
            (args.into / source.relative_to("/") / self.data.relative_to(source)).read_bytes(),
            self.data.read_bytes(),
        )
        with patch.object(recovery, "private_env"):
            with self.assertRaisesRegex(RuntimeError, "destination exists"):
                recovery.restore(args)

    def test_tampered_recovery_rejected_without_publication(self):
        receipt = self.root / "receipt.json"
        recovery.write_receipt(receipt, {
            "schema": recovery.SCHEMA,
            "status": "remote-snapshot-verified-not-restored",
            "source_path": str(self.source),
            "snapshot_id": "a" * 64,
            "entries": recovery.tree(self.source),
        })
        args = type("Args", (), {
            "receipt": receipt, "into": self.root / "recovery", "apply": True,
        })()
        def tamper(argv, *, capture=False):
            stage = Path(argv[-1])
            destination = stage / self.source.relative_to("/")
            destination.parent.mkdir(parents=True)
            shutil.copytree(self.source, destination)
            (destination / self.data.relative_to(self.source)).write_bytes(b"tampered")
            return ""
        with patch.object(recovery, "private_env"), patch.object(recovery.shutil, "which", return_value="/usr/bin/rbq"), patch.object(recovery, "run", side_effect=tamper), patch.object(recovery, "fsck"):
            with self.assertRaisesRegex(RuntimeError, "do not match"):
                recovery.restore(args)
        self.assertFalse(args.into.exists())


if __name__ == "__main__":
    unittest.main()
