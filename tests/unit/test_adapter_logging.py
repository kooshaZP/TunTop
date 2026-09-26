"""Unit tests for --log-adapter-activity: UDP/QUIC connection parsing,
ICMP counter deltas, Wintun throughput deltas, and the _poll_connections
adapter-activity branch (dedup, rate limiting, component tagging).

Pure mocks - no real network or adapter access. Uses the same
__new__-without-init + PropertyMock pattern as the dashboard regression
suite.
"""
import json
import queue
import unittest
from unittest import mock

from tuntop.ui import dashboard
from tuntop.core.events import LogRing


def _udp_json(proto="UDP", remote="8.8.8.8", rport=53, local="192.168.1.100",
              lport=5353, proc="chrome", pid=1234):
    return json.dumps([{
        "Proto": proto, "Local": local, "Lport": lport,
        "Remote": remote, "Rport": rport, "Proc": proc, "Pid": pid,
    }])


class _AdapterApp:
    """Build a BTopTui without calling __init__ (which needs a tty) for
    testing _poll_connections and _blog."""

    @staticmethod
    def create(log_adapter_activity=True):
        app = dashboard.BTopTui.__new__(dashboard.BTopTui)
        app._conn_poll_ts = 0
        app._seen_conns = {}
        app._net_rate = {}
        app._log_adapter_activity = log_adapter_activity
        app._seen_udp_conns = {}
        app._seen_icmp_conns = {}
        app._last_adapter_rx = None
        app._last_adapter_tx = None
        app.event_log = LogRing(capacity=500)
        app.logs = queue.Queue()
        app.log_lines = []
        return app


class TestGetUdpConnections(unittest.TestCase):
    def test_parses_json_list(self):
        with mock.patch.object(dashboard, "_ps",
                               return_value=(True, _udp_json())):
            result = dashboard._get_udp_connections()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["Proto"], "UDP")
        self.assertEqual(result[0]["Proc"], "chrome")

    def test_quic_heuristic_port_443(self):
        # The QUIC classification lives in the PowerShell script itself
        # (RemotePort -eq 443 => Proto 'QUIC'). Mock _ps to return what that
        # script would produce, and verify the function passes it through.
        with mock.patch.object(dashboard, "_ps",
                               return_value=(True, _udp_json(
                                   proto="QUIC", rport=443))):
            result = dashboard._get_udp_connections()
        self.assertEqual(result[0]["Proto"], "QUIC")
        self.assertEqual(result[0]["Rport"], 443)

    def test_quic_heuristic_in_script(self):
        # Verify the PowerShell source actually embeds the port-443 => QUIC
        # classification (the heuristic cannot be tested without PowerShell).
        src = dashboard._get_udp_connections.__code__
        ps_script = None
        for const in src.co_consts:
            if isinstance(const, str) and "Get-NetUDPConnection" in const:
                ps_script = const
                break
        self.assertIsNotNone(ps_script)
        self.assertIn("RemotePort -eq 443", ps_script)

    def test_non_443_is_udp(self):
        with mock.patch.object(dashboard, "_ps",
                               return_value=(True, _udp_json(rport=53))):
            result = dashboard._get_udp_connections()
        self.assertEqual(result[0]["Proto"], "UDP")

    def test_single_object_wrapped_in_list(self):
        single = _udp_json()
        with mock.patch.object(dashboard, "_ps",
                               return_value=(True, single)):
            result = dashboard._get_udp_connections()
        self.assertEqual(len(result), 1)

    def test_ps_failure_returns_empty(self):
        with mock.patch.object(dashboard, "_ps",
                               return_value=(False, "error")):
            self.assertEqual(dashboard._get_udp_connections(), [])

    def test_invalid_json_returns_empty(self):
        with mock.patch.object(dashboard, "_ps",
                               return_value=(True, "not json")):
            self.assertEqual(dashboard._get_udp_connections(), [])


class TestGetIcmpStats(unittest.TestCase):
    def test_parses_netsh_received_sent(self):
        netsh = (
            "Protocol: ICMPv4\n"
            "                        Received          Sent\n"
            "-----------------------------------------------\n"
            "Number of received packets         100           50\n"
            "Number of received errors           2            1\n"
        )
        with mock.patch.object(dashboard, "_ps",
                               return_value=(True, netsh)):
            result = dashboard._get_icmp_stats()
        self.assertIn("ipv4", result)
        self.assertEqual(result["ipv4"]["in"], 102)
        self.assertEqual(result["ipv4"]["out"], 51)

    def test_ps_failure_returns_none_for_family(self):
        with mock.patch.object(dashboard, "_ps",
                               return_value=(False, "err")):
            result = dashboard._get_icmp_stats()
        self.assertIsNone(result["ipv4"])
        self.assertIsNone(result["ipv6"])

    def test_empty_output_zeroes(self):
        with mock.patch.object(dashboard, "_ps",
                               return_value=(True, "")):
            result = dashboard._get_icmp_stats()
        self.assertEqual(result["ipv4"]["in"], 0)
        self.assertEqual(result["ipv4"]["out"], 0)

    def test_invalid_json_in_ps_ok_but_empty(self):
        with mock.patch.object(dashboard, "_ps",
                               return_value=(True, "garbage\nno numbers")):
            result = dashboard._get_icmp_stats()
        self.assertEqual(result["ipv4"]["in"], 0)
        self.assertEqual(result["ipv4"]["out"], 0)


class TestGetAdapterThroughput(unittest.TestCase):
    def test_parses_json(self):
        payload = json.dumps({"ReceivedBytes": 1000, "SentBytes": 500})
        with mock.patch.object(dashboard, "_ps",
                               return_value=(True, payload)):
            result = dashboard._get_adapter_throughput()
        self.assertEqual(result, {"rx": 1000, "tx": 500})

    def test_ps_failure_returns_none(self):
        with mock.patch.object(dashboard, "_ps",
                               return_value=(False, "err")):
            self.assertIsNone(dashboard._get_adapter_throughput())

    def test_invalid_json_returns_none(self):
        with mock.patch.object(dashboard, "_ps",
                               return_value=(True, "not json")):
            self.assertIsNone(dashboard._get_adapter_throughput())


class TestBlogComponent(unittest.TestCase):
    def test_default_component_is_dashboard(self):
        app = _AdapterApp.create()
        app._blog("hello")
        rec = app.event_log.recent()[-1]
        self.assertEqual(rec.component, "DASHBOARD")
        self.assertEqual(rec.message, "hello")

    def test_adapter_component(self):
        app = _AdapterApp.create()
        app._blog("something", component="ADAPTER")
        rec = app.event_log.recent()[-1]
        self.assertEqual(rec.component, "ADAPTER")

    def test_json_record_logged_to_event_log(self):
        app = _AdapterApp.create()
        record = json.dumps({"proto": "UDP", "src": "1.1.1.1",
                             "sport": 53, "dst": "2.2.2.2",
                             "dport": 443, "proc": "test", "pid": 99})
        app._blog(record, component="ADAPTER")
        rec = app.event_log.recent()[-1]
        self.assertEqual(rec.component, "ADAPTER")
        self.assertEqual(rec.message, record)


class TestPollConnectionsAdapterBranch(unittest.TestCase):
    """Test the adapter-activity branch of _poll_connections."""

    def setUp(self):
        self.app = _AdapterApp.create()
        self._state_patch = mock.patch.object(
            dashboard.BTopTui, "state",
            new_callable=mock.PropertyMock)
        self._mock_state = self._state_patch.start()
        self._mock_state.return_value = "RUNNING"
        self._time_patch = mock.patch.object(dashboard.time, "time")
        self._mock_time = self._time_patch.start()

    def tearDown(self):
        self._state_patch.stop()
        self._time_patch.stop()

    def _adapter_records(self):
        """Return event-log records with component ADAPTER."""
        return [r for r in self.app.event_log.recent()
                if r.component == "ADAPTER"]

    def test_logs_udp_connection_as_json(self):
        self._mock_time.return_value = 1000000.0
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections",
                               return_value=json.loads(_udp_json())), \
             mock.patch.object(dashboard, "_get_icmp_stats", return_value={}), \
             mock.patch.object(dashboard, "_get_adapter_throughput",
                               return_value={"rx": 100, "tx": 50}):
            self.app._poll_connections()
        recs = self._adapter_records()
        self.assertTrue(len(recs) > 0)
        json_recs = [r for r in recs
                     if r.message.strip().startswith("{")]
        self.assertTrue(len(json_recs) > 0)
        parsed = json.loads(json_recs[0].message)
        self.assertIn("proto", parsed)
        self.assertEqual(parsed["proto"], "UDP")
        self.assertEqual(parsed["proc"], "chrome")

    def test_quic_tagged_as_proto(self):
        self._mock_time.return_value = 1000000.0
        conn = {"Proto": "QUIC", "Local": "1.1.1.1", "Lport": 5353,
                "Remote": "2.2.2.2", "Rport": 443, "Proc": "chrome", "Pid": 1}
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections",
                               return_value=[conn]), \
             mock.patch.object(dashboard, "_get_icmp_stats", return_value={}), \
             mock.patch.object(dashboard, "_get_adapter_throughput",
                               return_value={"rx": 100, "tx": 50}):
            self.app._poll_connections()
        recs = self._adapter_records()
        json_recs = [r for r in recs if r.message.strip().startswith("{")]
        self.assertTrue(len(json_recs) > 0)
        parsed = json.loads(json_recs[0].message)
        self.assertEqual(parsed["proto"], "QUIC")
        self.assertEqual(parsed["dport"], 443)

    def test_dedup_suppresses_repeat_connections(self):
        self._mock_time.return_value = 1000000.0
        conn = {"Proto": "UDP", "Local": "1.1.1.1", "Lport": 5353,
                "Remote": "2.2.2.2", "Rport": 53, "Proc": "chrome", "Pid": 1}
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections",
                               return_value=[conn]), \
             mock.patch.object(dashboard, "_get_icmp_stats", return_value={}), \
             mock.patch.object(dashboard, "_get_adapter_throughput",
                               return_value={"rx": 100, "tx": 50}):
            self.app._poll_connections()
        # Only JSON connection records (not throughput lines).
        json_recs = [r for r in self._adapter_records()
                     if r.message.strip().startswith("{")]
        self.assertEqual(len(json_recs), 1)
        # Second poll (5s later) with the SAME connection should be deduped.
        self._mock_time.return_value = 1000005.0
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections",
                               return_value=[conn]), \
             mock.patch.object(dashboard, "_get_icmp_stats", return_value={}), \
             mock.patch.object(dashboard, "_get_adapter_throughput",
                               return_value={"rx": 200, "tx": 100}):
            self.app._poll_connections()
        json_recs = [r for r in self._adapter_records()
                     if r.message.strip().startswith("{")]
        self.assertEqual(len(json_recs), 1)

    def test_rate_limiting_suppresses_same_destination(self):
        self._mock_time.return_value = 1000000.0
        conn_a = {"Proto": "UDP", "Local": "1.1.1.1", "Lport": 5353,
                  "Remote": "2.2.2.2", "Rport": 53, "Proc": "chrome", "Pid": 1}
        conn_b = {"Proto": "UDP", "Local": "1.1.1.2", "Lport": 5354,
                  "Remote": "2.2.2.2", "Rport": 53, "Proc": "firefox", "Pid": 2}
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections",
                               return_value=[conn_a]), \
             mock.patch.object(dashboard, "_get_icmp_stats", return_value={}), \
             mock.patch.object(dashboard, "_get_adapter_throughput",
                               return_value={"rx": 100, "tx": 50}):
            self.app._poll_connections()
        json_recs = [r for r in self._adapter_records()
                     if r.message.strip().startswith("{")]
        self.assertEqual(len(json_recs), 1)
        # Second poll (5s later) with a DIFFERENT connection to the SAME
        # destination:port -> suppressed by the per-destination rate limit.
        self._mock_time.return_value = 1000005.0
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections",
                               return_value=[conn_b]), \
             mock.patch.object(dashboard, "_get_icmp_stats", return_value={}), \
             mock.patch.object(dashboard, "_get_adapter_throughput",
                               return_value={"rx": 200, "tx": 100}):
            self.app._poll_connections()
        json_recs = [r for r in self._adapter_records()
                     if r.message.strip().startswith("{")]
        self.assertEqual(len(json_recs), 1)

    def test_icmp_delta_logged(self):
        self._mock_time.return_value = 1000000.0
        # First poll seeds the counters (no log), second poll logs the delta.
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_icmp_stats",
                               return_value={"ipv4": {"in": 10, "out": 5},
                                             "ipv6": {"in": 2, "out": 1}}), \
             mock.patch.object(dashboard, "_get_adapter_throughput",
                               return_value={"rx": 100, "tx": 50}):
            self.app._poll_connections()
        self.assertEqual(len(self._adapter_records()), 0)
        # Seed done; second poll with deltas.
        self._mock_time.return_value = 1000005.0
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_icmp_stats",
                               return_value={"ipv4": {"in": 20, "out": 15},
                                             "ipv6": {"in": 4, "out": 3}}), \
             mock.patch.object(dashboard, "_get_adapter_throughput",
                               return_value={"rx": 200, "tx": 100}):
            self.app._poll_connections()
        recs = self._adapter_records()
        icmp = [r for r in recs if "icmp" in r.message.lower()]
        self.assertTrue(len(icmp) > 0)
        self.assertIn("ipv4", icmp[0].message)
        self.assertIn("in=10", icmp[0].message)

    def test_throughput_delta_logged(self):
        self._mock_time.return_value = 1000000.0
        # First poll seeds throughput (no delta log).
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_icmp_stats", return_value={}), \
             mock.patch.object(dashboard, "_get_adapter_throughput",
                               return_value={"rx": 100, "tx": 50}):
            self.app._poll_connections()
        self.assertEqual(len(self._adapter_records()), 0)
        # Second poll with non-zero deltas.
        self._mock_time.return_value = 1000005.0
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_icmp_stats", return_value={}), \
             mock.patch.object(dashboard, "_get_adapter_throughput",
                               return_value={"rx": 300, "tx": 150}):
            self.app._poll_connections()
        recs = self._adapter_records()
        tp = [r for r in recs if "rx=" in r.message]
        self.assertTrue(len(tp) > 0)

    def test_adapter_activity_off_no_logs(self):
        app = _AdapterApp.create(log_adapter_activity=False)
        self._mock_time.return_value = 1000000.0
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections") as m_udp, \
             mock.patch.object(dashboard, "_get_icmp_stats") as m_icmp, \
             mock.patch.object(dashboard, "_get_adapter_throughput") as m_tp:
            app._poll_connections()
        m_udp.assert_not_called()
        m_icmp.assert_not_called()
        m_tp.assert_not_called()

    def test_throttle_blocks_second_call(self):
        self._mock_time.return_value = 1000000.0
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections") as m_udp, \
             mock.patch.object(dashboard, "_get_icmp_stats"), \
             mock.patch.object(dashboard, "_get_adapter_throughput"):
            self.app._poll_connections()
        m_udp.assert_called_once()
        # 1 second later - within the 5s throttle window.
        self._mock_time.return_value = 1000001.0
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections") as m_udp2, \
             mock.patch.object(dashboard, "_get_icmp_stats"), \
             mock.patch.object(dashboard, "_get_adapter_throughput"):
            self.app._poll_connections()
        m_udp2.assert_not_called()

    def test_does_not_run_when_tunnel_not_running(self):
        self._mock_time.return_value = 1000000.0
        self._mock_state.return_value = "STOPPED"
        with mock.patch.object(dashboard, "_get_active_connections",
                               return_value=[]), \
             mock.patch.object(dashboard, "_get_udp_connections") as m_udp, \
             mock.patch.object(dashboard, "_get_icmp_stats") as m_icmp, \
             mock.patch.object(dashboard, "_get_adapter_throughput") as m_tp:
            self.app._poll_connections()
        m_udp.assert_not_called()
        m_icmp.assert_not_called()
        m_tp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
