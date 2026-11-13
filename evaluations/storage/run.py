#!/usr/bin/env python3
"""Run the isolated local-only probes; save evidence, never contact a provider."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resume", action="store_true", help="skip matching completed probe results")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    manifest = directory / "Cargo.toml"
    environment = dict(os.environ)
    environment.setdefault("CARGO_BUILD_JOBS", "2")
    environment.setdefault("CARGO_TARGET_DIR", str(directory / "target"))
    results = directory / "results"
    results.mkdir(exist_ok=True)
    subprocess.run(["cargo", "fmt", "--manifest-path", str(manifest), "--all", "--check"], check=True, env=environment)
    for feature, binary, source in [
        ("object-store", "object-store-probe", "object_store_probe.rs"),
        ("opendal", "opendal-probe", "opendal_probe.rs"),
    ]:
        digest = hashlib.sha256((directory / "src" / source).read_bytes() + manifest.read_bytes() + (directory / "Cargo.lock").read_bytes()).hexdigest()
        output = results / (feature + ".json")
        if args.resume and output.exists() and json.loads(output.read_text()).get("probe_inputs_sha256") == digest:
            print(f"Already completed, unchanged: {binary}", flush=True)
            continue
        print(f"Running local-only semantic probe: {binary}", flush=True)
        process = subprocess.run(
            ["cargo", "run", "--locked", "--manifest-path", str(manifest), "--features", feature, "--bin", binary],
            env=environment, text=True, stdout=subprocess.PIPE, check=True,
        )
        report = json.loads(process.stdout)
        report["probe_inputs_sha256"] = digest
        report["rustc"] = subprocess.check_output(["rustc", "--version"], text=True).strip()
        temporary = output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        temporary.replace(output)
        print(json.dumps(report, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
