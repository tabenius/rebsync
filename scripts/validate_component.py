#!/usr/bin/env python3
"""Validate the component against an explicitly supplied ragbaz-common schema.

Requires jsonschema. No network access or Frog database writes are performed.
"""

import argparse
import json
from pathlib import Path
import tomllib

from jsonschema import Draft202012Validator


def validate(manifest, schema, version):
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(manifest)
    if manifest["identity"].get("version") != version:
        raise ValueError("component version must match workspace.package.version")
    edges = [(edge["componentId"], edge["kind"]) for edge in manifest["dependencies"]]
    if len(edges) != len(set(edges)):
        raise ValueError("duplicate component dependency edge")
    if any(component == manifest["identity"]["id"] for component, _ in edges):
        raise ValueError("component must not depend on itself")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "ragbaz.component.json").read_text())
    schema = json.loads(args.schema.read_text())
    cargo = tomllib.loads((root / "Cargo.toml").read_text())
    validate(manifest, schema, cargo["workspace"]["package"]["version"])
    print("Component manifest and typed dependencies are valid.")


if __name__ == "__main__":
    main()
