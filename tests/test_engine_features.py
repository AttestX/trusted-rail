"""Run with python3 -O too: optimization must not disable this build gate."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "engine_features", Path(__file__).parents[1] / "scripts/check_engine_features.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class EngineFeaturesTest(unittest.TestCase):
    def setUp(self):
        self.metadata = {
            "packages": [{"name": name, "id": name} for name in audit.APPROVED_FEATURES],
            "resolve": {"nodes": [
                {"id": name, "features": sorted(features)}
                for name, features in audit.APPROVED_FEATURES.items()
            ]},
        }
        self.metadata["packages"][0].update({
            "version": audit.APPROVED_REGORUS_VERSION,
            "source": audit.APPROVED_REGORUS_SOURCE,
        })

    def test_approved_features(self):
        audit.check(self.metadata)

    def test_audited_object_order_and_parser_features(self):
        for extra in [
            ["indexmap", "preserve_order"],
            ["unbounded_depth"],
            ["indexmap", "preserve_order", "unbounded_depth"],
        ]:
            changed = copy.deepcopy(self.metadata)
            changed["resolve"]["nodes"][1]["features"].extend(extra)
            audit.check(changed)

    def test_feature_unification_is_rejected(self):
        for name, feature in [
            ("regorus", "full-opa"),
            ("serde_json", "arbitrary_precision"),
            ("serde_json", "float_roundtrip"),
            ("serde_json", "unknown-future-feature"),
        ]:
            with self.subTest(name=name, feature=feature):
                changed = copy.deepcopy(self.metadata)
                next(n for n in changed["resolve"]["nodes"] if n["id"] == name)["features"].append(feature)
                with self.assertRaises(SystemExit):
                    audit.check(changed)

    def test_unpatched_or_changed_evaluator_is_rejected(self):
        for field, value in [
            ("version", "0.14.0"),
            ("source", "registry+https://github.com/rust-lang/crates.io-index"),
            ("source", audit.APPROVED_REGORUS_SOURCE[:-1] + "x"),
        ]:
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(self.metadata)
                changed["packages"][0][field] = value
                with self.assertRaises(SystemExit):
                    audit.check(changed)

    def test_missing_or_duplicate_packages_and_nodes_are_rejected(self):
        for name in audit.APPROVED_FEATURES:
            for collection in ["packages", "nodes"]:
                for duplicate in [False, True]:
                    with self.subTest(name=name, collection=collection, duplicate=duplicate):
                        changed = copy.deepcopy(self.metadata)
                        items = changed["packages"] if collection == "packages" else changed["resolve"]["nodes"]
                        if duplicate:
                            extra = next(item.copy() for item in items if item["id"] == name)
                            if collection == "packages":
                                extra["id"] += "-other-version"
                            items.append(extra)
                        else:
                            items[:] = [item for item in items if item["id"] != name]
                        with self.assertRaises(SystemExit):
                            audit.check(changed)
