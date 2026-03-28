from __future__ import annotations

import unittest

from tests._helpers import load_module


MODULE = load_module("services/shared/tracing.py", "shared_tracing_main")


class TracingTests(unittest.TestCase):
    def test_child_trace_headers_preserve_trace_and_set_parent(self) -> None:
        root = MODULE.set_trace_context("trace-1", "span-root", "")
        child = MODULE.child_trace_headers()

        self.assertEqual(root["x-trace-id"], child["x-trace-id"])
        self.assertEqual(child["x-parent-span-id"], "span-root")
        self.assertNotEqual(child["x-span-id"], "span-root")


if __name__ == "__main__":
    unittest.main()
