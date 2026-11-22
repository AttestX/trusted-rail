#!/usr/bin/env python3
"""Feature unification must not silently widen the proved evaluator profile."""
import json
import subprocess
import sys

APPROVED_FEATURES = {
    "regorus": {"no_std"},
    "serde_json": {"alloc", "default", "raw_value", "std"},
}


def check(metadata):
    for name, approved in APPROVED_FEATURES.items():
        ids = {p["id"] for p in metadata["packages"] if p["name"] == name}
        if len(ids) != 1:
            raise SystemExit(f"exactly one {name} version is required")
        nodes = [n for n in metadata["resolve"]["nodes"] if n["id"] in ids]
        if len(nodes) != 1 or set(nodes[0]["features"]) != approved:
            raise SystemExit(f"unapproved {name} features: {nodes}")


if __name__ == "__main__":
    manifest = sys.argv[1] if len(sys.argv) > 1 else "Cargo.toml"
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--all-features", "--format-version=1",
        "--manifest-path", manifest,
    ]))
    check(metadata)
    print("Regorus and serde_json deterministic feature profiles verified")
