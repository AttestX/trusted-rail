#!/usr/bin/env python3
"""Feature unification must not silently widen the proved evaluator profile."""
import json
from pathlib import Path
import subprocess
import sys
import tomllib

# Downstream users run this same audit against their complete resolved graph.
with (Path(__file__).resolve().parents[1] / "Cargo.toml").open("rb") as manifest:
    regorus = tomllib.load(manifest)["dependencies"]["regorus"]
APPROVED_REGORUS_VERSION = regorus["version"].removeprefix("=")
APPROVED_REGORUS_SOURCE = f"git+{regorus['git']}?rev={regorus['rev']}#{regorus['rev']}"

APPROVED_FEATURES = {
    "regorus": {"no_std"},
    "serde_json": {"alloc", "default", "raw_value", "std"},
}
# These do not change our codec: every object is explicitly sorted and no
# decoder disables serde_json's default recursion limit. Both combinations
# are covered by native tests and the native/MIPS differential corpus.
OPTIONAL_FEATURES = {"serde_json": {"indexmap", "preserve_order", "unbounded_depth"}}


def check(metadata):
    for name, approved in APPROVED_FEATURES.items():
        ids = {p["id"] for p in metadata["packages"] if p["name"] == name}
        if len(ids) != 1:
            raise SystemExit(f"exactly one {name} version is required")
        if name == "regorus":
            package = next(p for p in metadata["packages"] if p["id"] in ids)
            if (package.get("version") != APPROVED_REGORUS_VERSION
                    or package.get("source") != APPROVED_REGORUS_SOURCE):
                raise SystemExit("Regorus must use Rail's pinned portability patch")
        nodes = [n for n in metadata["resolve"]["nodes"] if n["id"] in ids]
        actual = set(nodes[0]["features"]) if len(nodes) == 1 else set()
        if len(nodes) != 1 or not approved <= actual <= approved | OPTIONAL_FEATURES.get(name, set()):
            raise SystemExit(f"unapproved {name} features: {nodes}")


if __name__ == "__main__":
    manifest = sys.argv[1] if len(sys.argv) > 1 else "Cargo.toml"
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--all-features", "--format-version=1",
        "--manifest-path", manifest,
    ]))
    check(metadata)
    print("Regorus and serde_json deterministic feature profiles verified")
