"""Deterministic admission tests; never benchmark the host."""
import copy
import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location("observer", pathlib.Path(__file__).with_name("observe-workflows.py"))
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


def document():
    sample = {"plain_ns": 20, "observation": {"complete": True, "total_ns": 20,
        "stages": [{"stage": stage, "calls": 1, "inclusive_ns": 1, "self_ns": 1}
                   for stage in OBSERVER.STAGES]}}
    return {"schema": "benchmark.workflow-observation.v1", "samples": 1,
            "stages": OBSERVER.STAGES.copy(),
            "rows": [{"id": row, "arms": {arm: [copy.deepcopy(sample)] for arm in arms}}
                     for row, arms in OBSERVER.ROWS.items()]}


class Admission(unittest.TestCase):
    def test_complete_inventory(self):
        OBSERVER.validate(document(), 1)
        summary = OBSERVER.summarize([{"observations": document()}] * 3)
        self.assertEqual(len(summary), 30)
        self.assertTrue(all(row["count"] == 3 and row["stdev_ns"] == 0 for row in summary))

    def test_incomplete_inventory(self):
        for change in (lambda d: d["rows"].pop(),
                       lambda d: d["rows"].append(copy.deepcopy(d["rows"][0])),
                       lambda d: d["stages"].reverse(),
                       lambda d: d["rows"][0]["arms"].pop("cold"),
                       lambda d: d["rows"][0]["arms"]["cold"].clear()):
            with self.subTest(change=change):
                value = document()
                change(value)
                with self.assertRaises(ValueError):
                    OBSERVER.validate(value, 1)

    def test_invalid_measurements(self):
        for field, replacement in (("plain_ns", None), ("plain_ns", True),
                                   ("complete", False), ("total_ns", True),
                                   ("total_ns", 0), ("self_ns", 2), ("calls", -1)):
            with self.subTest(field=field, replacement=replacement):
                value = document()
                sample = value["rows"][0]["arms"]["cold"][0]
                target = sample if field == "plain_ns" else sample["observation"]
                if field in ("self_ns", "calls"):
                    target = target["stages"][0]
                target[field] = replacement
                with self.assertRaises(ValueError):
                    OBSERVER.validate(value, 1)

    def test_quiet_host_requires_actual_facts(self):
        host = {"cpu_count": 4, "load_average": [0.5, 0.6, 0.7],
                "available_memory": {"bytes": 2048}}
        self.assertTrue(OBSERVER.quiet(host, 0.25, 1024))
        for patch in ({"cpu_count": True}, {"load_average": [False, 0, 0]},
                      {"load_average": [0, 0, 2]}, {"load_average": None},
                      {"available_memory": {"bytes": 100}},
                      {"available_memory": {"bytes": True}}, {"available_memory": {}}):
            self.assertFalse(OBSERVER.quiet(dict(host, **patch), 0.25, 1024))


if __name__ == "__main__":
    unittest.main()
