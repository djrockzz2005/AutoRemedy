from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


def load_module(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


MODULE = load_module(str(Path("/home/guru/Dev/MITHack/services/anomaly-detector/app/main.py")), "anomaly_detector_main")


class AnomalyDetectorTests(unittest.TestCase):
    def test_should_retrain_after_interval(self) -> None:
        self.assertTrue(MODULE.should_retrain(current_size=30, last_size=20, minimum_size=20))
        self.assertFalse(MODULE.should_retrain(current_size=24, last_size=20, minimum_size=20))

    def test_rule_based_classify_fallback(self) -> None:
        sample = {
            "error_rate": 0.8,
            "availability": 0.7,
            "latency_p95": 0.1,
            "restarts": 0,
            "loki_errors": 0,
        }
        self.assertEqual(MODULE.rule_based_classify(sample), "availability_regression")


if __name__ == "__main__":
    unittest.main()
