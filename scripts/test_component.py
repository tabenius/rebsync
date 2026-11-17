"""Refusal tests using the real, supplied ragbaz-common component schema."""

import argparse
import copy
import json
from pathlib import Path
import unittest

from jsonschema import ValidationError

from validate_component import validate


class ComponentTests(unittest.TestCase):
    def setUp(self):
        self.manifest = copy.deepcopy(MANIFEST)

    def test_current_manifest(self):
        validate(self.manifest, SCHEMA, "0.1.0")

    def test_all_dependency_kinds(self):
        for kind in ["install", "runtime", "build", "debug"]:
            self.manifest["dependencies"][0]["kind"] = kind
            validate(self.manifest, SCHEMA, "0.1.0")

    def test_unknown_kind(self):
        self.manifest["dependencies"][0]["kind"] = "development"
        with self.assertRaises(ValidationError):
            validate(self.manifest, SCHEMA, "0.1.0")

    def test_missing_kind(self):
        del self.manifest["dependencies"][0]["kind"]
        with self.assertRaises(ValidationError):
            validate(self.manifest, SCHEMA, "0.1.0")

    def test_repository_pins_do_not_belong_in_edges(self):
        self.manifest["dependencies"][0]["repository"] = "tabenius/frog"
        with self.assertRaises(ValidationError):
            validate(self.manifest, SCHEMA, "0.1.0")

    def test_duplicate_edge(self):
        self.manifest["dependencies"].append(self.manifest["dependencies"][0])
        with self.assertRaises(ValueError):
            validate(self.manifest, SCHEMA, "0.1.0")

    def test_self_dependency(self):
        self.manifest["dependencies"][0]["componentId"] = self.manifest["identity"]["id"]
        with self.assertRaises(ValueError):
            validate(self.manifest, SCHEMA, "0.1.0")

    def test_version_drift(self):
        with self.assertRaises(ValueError):
            validate(self.manifest, SCHEMA, "0.2.0")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, required=True)
    args = parser.parse_args()
    SCHEMA = json.loads(args.schema.read_text())
    MANIFEST = json.loads(
        (Path(__file__).resolve().parents[1] / "ragbaz.component.json").read_text()
    )
    unittest.main(argv=[__file__])
