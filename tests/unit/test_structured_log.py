"""Unit tests for tuntop.structured_log - the structured logging layer.

Pure stdlib, no Windows calls.
"""
import json
import threading
import time
import unittest

from tuntop.structured_log import (
    LogRing, LogRecord, Severity, DEBUG, INFO, WARNING, ERROR,
)


class TestSeverity(unittest.TestCase):
    def test_values(self):
        self.assertEqual(DEBUG, 10)
        self.assertEqual(INFO, 20)
        self.assertEqual(WARNING, 30)
        self.assertEqual(ERROR, 40)

    def test_ordering(self):
        self.assertTrue(DEBUG < INFO < WARNING < ERROR)


class TestLogRecord(unittest.TestCase):
    def test_basic_format(self):
        r = LogRecord(INFO, "ROUTING", "default route installed")
        s = r.format()
        self.assertIn("INFO", s)
        self.assertIn("ROUTING", s)
        self.assertIn("default route installed", s)

    def test_format_with_state(self):
        r = LogRecord(INFO, "TUNNEL", "connected", state="RUNNING")
        s = r.format()
        self.assertIn("[RUNNING]", s)

    def test_format_ascii_mode(self):
        r = LogRecord(INFO, "DNS", "resolver switched")
        s = r.format(use_unicode=False)
        self.assertIn("INFO", s)
        self.assertIn("DNS", s)

    def test_to_dict(self):
        r = LogRecord(WARNING, "HEALTH", "probe failed",
                      state="DEGRADED", details="timeout after 5s")
        d = r.to_dict()
        self.assertEqual(d["severity"], "WARN")
        self.assertEqual(d["component"], "HEALTH")
        self.assertEqual(d["message"], "probe failed")
        self.assertEqual(d["state"], "DEGRADED")
        self.assertEqual(d["details"], "timeout after 5s")
        self.assertIn("ts", d)
        self.assertIn("ts_human", d)

    def test_to_dict_minimal(self):
        r = LogRecord(DEBUG, "TEST", "debug msg")
        d = r.to_dict()
        self.assertNotIn("state", d)
        self.assertNotIn("details", d)

    def test_ts_is_epoch(self):
        before = time.time()
        r = LogRecord(INFO, "X", "y")
        after = time.time()
        self.assertGreaterEqual(r.ts, before)
        self.assertLessEqual(r.ts, after)


class TestLogRing(unittest.TestCase):
    def test_log_and_recent(self):
        ring = LogRing(capacity=50)
        ring.log(INFO, "A", "first")
        ring.log(INFO, "B", "second")
        ring.log(INFO, "C", "third")
        recs = ring.recent()
        self.assertEqual(len(recs), 3)
        self.assertEqual(recs[0].message, "first")
        self.assertEqual(recs[2].message, "third")

    def test_capacity(self):
        ring = LogRing(capacity=5)
        for i in range(10):
            ring.log(INFO, "T", f"msg {i}")
        self.assertEqual(len(ring), 5)
        recs = ring.recent()
        self.assertEqual(recs[0].message, "msg 5")
        self.assertEqual(recs[4].message, "msg 9")

    def test_recent_n(self):
        ring = LogRing(capacity=100)
        for i in range(20):
            ring.log(INFO, "T", f"msg {i}")
        last5 = ring.recent(5)
        self.assertEqual(len(last5), 5)
        self.assertEqual(last5[0].message, "msg 15")

    def test_format_recent(self):
        ring = LogRing(capacity=50)
        ring.log(INFO, "ROUTING", "route added")
        lines = ring.format_recent(10)
        self.assertEqual(len(lines), 1)
        self.assertIn("ROUTING", lines[0])
        self.assertIn("route added", lines[0])

    def test_dump_text(self):
        ring = LogRing(capacity=50)
        ring.log(INFO, "A", "line 1")
        ring.log(INFO, "B", "line 2")
        text = ring.dump_text()
        self.assertIn("line 1", text)
        self.assertIn("line 2", text)
        self.assertIn("\n", text)

    def test_snapshot_json(self):
        ring = LogRing(capacity=50)
        ring.log(INFO, "T", "test msg", state="RUNNING")
        j = ring.snapshot_json()
        data = json.loads(j)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["component"], "T")
        self.assertEqual(data[0]["state"], "RUNNING")

    def test_clear(self):
        ring = LogRing(capacity=50)
        ring.log(INFO, "T", "msg")
        self.assertEqual(len(ring), 1)
        ring.clear()
        self.assertEqual(len(ring), 0)

    def test_empty_ring(self):
        ring = LogRing(capacity=50)
        self.assertEqual(len(ring), 0)
        self.assertEqual(ring.recent(), [])
        self.assertEqual(ring.format_recent(), [])
        self.assertEqual(ring.dump_text(), "")
        self.assertEqual(json.loads(ring.snapshot_json()), [])

    def test_log_returns_record(self):
        ring = LogRing(capacity=50)
        rec = ring.log(INFO, "T", "msg")
        self.assertIsInstance(rec, LogRecord)
        self.assertEqual(rec.message, "msg")

    def test_concurrent_log_safety(self):
        ring = LogRing(capacity=100)
        errors = []

        def writer(n):
            try:
                for i in range(50):
                    ring.log(INFO, "W", f"thread-{n}-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(ring), 100)  # capped at capacity


if __name__ == "__main__":
    unittest.main()
