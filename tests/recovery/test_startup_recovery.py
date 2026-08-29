"""Unit tests for tunmood.startup_recovery - Phase 5 crash recovery.

All system probes are fakes: deterministic, no Windows, no admin, no
subprocesses. The marker tests use a temp path.

Run:  python -m unittest discover -s tests -v
"""
import json
import os
import tempfile
import unittest

from tunmood.startup_recovery import (
    Probes, StartupFindings, clear_marker, read_marker, recover, scan,
    startup_recover, write_marker,
)


def make_probes(orphans=0, wintun_routes=0, host_routes=(), fail=None):
    """Fake probes with call recording. `fail` = set of probe names that
    raise, to verify scan/recover survive broken probes."""
    calls = []

    def guard(name, fn):
        def run(*a, **kw):
            if fail and name in fail:
                raise OSError(f"{name} exploded")
            calls.append((name,) + a)
            return fn(*a, **kw)
        return run

    state = {"killed": None, "torn_down": False, "swept": None}

    p = Probes(
        tun2socks_count=guard("tun2socks_count", lambda: orphans),
        wintun_route_count=guard("wintun_route_count",
                                 lambda: wintun_routes),
        host_routes=guard("host_routes", lambda hosts: list(host_routes)),
        kill_tun2socks=guard("kill", lambda: state.update(killed=orphans)
                             or orphans),
        teardown_adapter=guard("teardown",
                               lambda: state.update(torn_down=True) or True),
        sweep_host_routes=guard("sweep",
                                lambda routes: state.update(swept=routes)
                                or len(routes)),
    )
    return p, calls, state


class TestMarker(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "marker.json")

    def test_write_read_clear_roundtrip(self):
        self.assertIsNone(read_marker(self.path))          # fresh system
        write_marker(4242, self.path)
        data = read_marker(self.path)
        self.assertEqual(data["pid"], 4242)
        self.assertIn("started", data)
        clear_marker(self.path)
        self.assertIsNone(read_marker(self.path))          # clean exit

    def test_clear_is_idempotent(self):
        clear_marker(self.path)                            # no file: no raise
        write_marker(1, self.path)
        clear_marker(self.path)
        clear_marker(self.path)

    def test_corrupt_marker_reads_as_none(self):
        with open(self.path, "w") as f:
            f.write("{not json")
        self.assertIsNone(read_marker(self.path))

    def test_marker_is_json(self):
        write_marker(7, self.path)
        with open(self.path, encoding="utf-8") as f:
            json.load(f)                                   # must stay parseable


class TestScan(unittest.TestCase):
    def test_clean_system_is_not_dirty(self):
        p, _, _ = make_probes()
        f = scan(probes=p,
                 marker_path=os.path.join(tempfile.mkdtemp(), "none.json"))
        self.assertFalse(f.dirty)
        self.assertIsNone(f.marker)
        self.assertEqual(f.orphan_tun2socks, 0)

    def test_each_finding_marks_dirty(self):
        p, _, _ = make_probes(orphans=2)
        self.assertTrue(scan(probes=p).dirty)
        p, _, _ = make_probes(wintun_routes=3)
        self.assertTrue(scan(probes=p).dirty)
        p, _, _ = make_probes(host_routes=[("v4", "1.2.3.4/32")])
        # host-route probing only runs when hosts are requested
        self.assertTrue(scan(probes=p, hosts=["example.com"]).dirty)

    def test_unclean_marker_marks_dirty_with_pid(self):
        path = os.path.join(tempfile.mkdtemp(), "marker.json")
        write_marker(999, path)
        f = scan(probes=make_probes()[0], marker_path=path)
        self.assertTrue(f.dirty)
        self.assertEqual(f.marker["pid"], 999)

    def test_broken_probes_degrade_to_clean_not_crash(self):
        p, _, _ = make_probes(fail={"tun2socks_count", "wintun_route_count",
                                    "host_routes"})
        f = scan(probes=p, marker_path=os.path.join(tempfile.mkdtemp(),
                                                    "none.json"))
        self.assertFalse(f.dirty)                # safe defaults, no raise

    def test_host_routes_probe_only_runs_with_hosts(self):
        p, calls, _ = make_probes(host_routes=[("v4", "1.1.1.1/32")])
        scan(probes=p)                           # no hosts -> probe skipped
        self.assertFalse(any(c[0] == "host_routes" for c in calls))
        scan(probes=p, hosts=["example.com"])
        self.assertTrue(any(c[0] == "host_routes" for c in calls))


class TestSummary(unittest.TestCase):
    def test_summary_lines_describe_each_finding(self):
        f = StartupFindings(marker={"pid": 31337}, orphan_tun2socks=1,
                            wintun_routes=2,
                            host_routes=[("v4", "1.1.1.1/32"),
                                         ("v6", "::1/128")])
        lines = f.summary_lines()
        self.assertEqual(len(lines), 4)
        self.assertIn("31337", lines[0])
        self.assertIn("orphaned tun2socks", lines[1])
        self.assertIn("Wintun", lines[2])
        self.assertIn("2", lines[3])

    def test_clean_findings_summarize_to_nothing(self):
        self.assertEqual(StartupFindings().summary_lines(), [])


class TestRecover(unittest.TestCase):
    def test_nothing_dirty_means_no_actions(self):
        p, calls, state = make_probes()
        actions = recover(StartupFindings(), probes=p)
        self.assertEqual(actions, [])
        self.assertFalse(state["torn_down"])

    def test_orphans_are_killed_before_teardown(self):
        # Order matters: a live tun2socks would re-assert its routes.
        p, _, state = make_probes(orphans=2, wintun_routes=5)
        actions = recover(StartupFindings(orphan_tun2socks=2,
                                          wintun_routes=5), probes=p)
        self.assertEqual(state["killed"], 2)
        self.assertTrue(state["torn_down"])
        self.assertEqual(len(actions), 2)
        self.assertIn("kill", actions[0])
        self.assertIn("Wintun", actions[1])

    def test_marker_alone_triggers_defensive_teardown(self):
        p, _, state = make_probes()
        actions = recover(StartupFindings(marker={"pid": 1}), probes=p)
        self.assertTrue(state["torn_down"])
        self.assertEqual(len(actions), 1)

    def test_host_routes_are_swept(self):
        routes = [("v4", "1.1.1.1/32"), ("v6", "::1/128")]
        p, _, state = make_probes(host_routes=routes)
        actions = recover(StartupFindings(host_routes=routes), probes=p)
        self.assertEqual(state["swept"], routes)
        self.assertEqual(len(actions), 1)
        self.assertIn("2 route(s)", actions[0])

    def test_failing_step_is_logged_never_raised(self):
        p, _, state = make_probes(orphans=1)

        def boom():
            raise OSError("access denied")

        p.kill_tun2socks = boom
        p.teardown_adapter = lambda: state.update(torn_down=True) or True
        lines = []
        actions = recover(StartupFindings(orphan_tun2socks=1), probes=p,
                          log=lines.append)
        # The failed step is reported, the remaining steps still run.
        self.assertTrue(any("failed" in a for a in actions))
        self.assertTrue(any("'kill" in ln for ln in lines))
        self.assertTrue(state["torn_down"])

    def test_progress_callback_counts_tasks(self):
        p, _, _ = make_probes(orphans=1, wintun_routes=1)
        seen = []
        recover(StartupFindings(orphan_tun2socks=1, wintun_routes=1),
                probes=p,
                progress=lambda done, total, label: seen.append((done, total)))
        self.assertEqual(seen, [(0, 2), (1, 2)])


class TestOneCallConvenience(unittest.TestCase):
    def test_clean_start_writes_marker_and_does_nothing(self):
        path = os.path.join(tempfile.mkdtemp(), "marker.json")
        p, _, state = make_probes()
        actions = startup_recover(probes=p, marker_path=path)
        self.assertEqual(actions, [])
        self.assertFalse(state["torn_down"])
        self.assertIsNotNone(read_marker(path))   # fresh marker written

    def test_dirty_start_recovers_then_rewrites_marker(self):
        path = os.path.join(tempfile.mkdtemp(), "marker.json")
        write_marker(111, path)                   # leftover from a crash
        p, _, state = make_probes(wintun_routes=4)
        actions = startup_recover(probes=p, marker_path=path)
        self.assertEqual(len(actions), 1)
        self.assertTrue(state["torn_down"])
        # The stale marker was REPLACED by this run's marker.
        self.assertEqual(read_marker(path)["pid"], os.getpid())


if __name__ == "__main__":
    unittest.main()


