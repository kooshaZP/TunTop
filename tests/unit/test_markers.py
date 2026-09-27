"""Unit tests for tuntop.core.markers - the helper stdout vocabulary.

The whole point of the module is that a helper line's meaning is decided in
exactly one, pure, table-driven place. These tests pin that mapping down:
they use the helper's REAL printed strings (copied from
``tuntop/tunnel/helper.py``), so a renamed marker fails here instead of
silently degrading into an unclassified line in a reader thread.

Pure stdlib, no Windows calls, no admin rights: runs anywhere, including CI.

Run:  python -m unittest discover -s tests -v
"""
import unittest
from pathlib import Path

from tuntop.core import markers
from tuntop.core.markers import Verdict, classify
from tuntop.core.recovery import FailureKind
from tuntop.core.state import TunnelState

_HELPER = Path(__file__).resolve().parents[2] / "tuntop" / "tunnel" / "helper.py"


def helper_text():
    return _HELPER.read_text(encoding="utf-8")


class TestClassification(unittest.TestCase):
    def test_empty_and_ordinary_lines_are_unclassified(self):
        for line in ("", "   ", "[*] Checking local SOCKS5 proxy at ..."):
            self.assertIsNone(classify(line), line)

    def test_classify_never_raises(self):
        for weird in (None.__class__ and "\x00\xff", "\n", "]" * 5000):
            classify(weird)          # must not raise

    def test_start_sequence_markers(self):
        v = classify("[+] TUNNEL ACTIVE", TunnelState.STARTING_TUN2SOCKS)
        self.assertIs(v.target, TunnelState.VERIFYING)
        self.assertTrue(v.log)
        self.assertTrue(v.log_raw)

        v = classify("[*] Press Ctrl+C to stop.", TunnelState.VERIFYING)
        self.assertIs(v.target, TunnelState.RUNNING)
        # The helper's Ctrl+C instruction is noise; the announcement replaces
        # it and the raw line is NOT echoed on top.
        self.assertIn("START SEQUENCE COMPLETE", v.replace)
        self.assertFalse(v.log_raw)

    def test_unverified_start_is_degraded_not_running(self):
        """A fully installed tunnel that never proved traffic must never be
        announced as ready - that is the 'everything says RUNNING and nothing
        works' failure."""
        v = classify("[!] TUNNEL DEGRADED - traffic verification failed: no probe",
                     TunnelState.VERIFYING)
        self.assertIs(v.target, TunnelState.DEGRADED)
        self.assertIsNot(v.target, TunnelState.RUNNING)
        self.assertIs(v.kind, FailureKind.DNS)

    def test_endpoint_loop_is_a_routes_fault_not_a_dns_fault(self):
        v = classify("[!] TUNNEL DEGRADED - proxy endpoint routes loop: 1 "
                     "endpoint(s) would be captured by the TUN just installed",
                     TunnelState.VERIFYING)
        self.assertIs(v.target, TunnelState.DEGRADED)
        self.assertIs(v.kind, FailureKind.ROUTES)

    def test_self_heal_cycle(self):
        self.assertIs(classify("[*] Self-healing: re-applying Wintun config and "
                               "TUN routes...", TunnelState.RUNNING).target,
                     TunnelState.RECOVERING)
        self.assertIs(classify("[+] Self-heal applied.", TunnelState.RECOVERING
                               ).target, TunnelState.RUNNING)

    def test_missing_adapter_is_failed_and_adapter_kind(self):
        v = classify("[!] Self-heal: Wintun adapter is gone; cannot re-apply "
                     "routes.", TunnelState.RUNNING)
        self.assertIs(v.target, TunnelState.FAILED)
        self.assertIs(v.kind, FailureKind.ADAPTER)

    def test_dead_forwarder_is_a_process_incident(self):
        v = classify("[!] tun2socks exited unexpectedly (code 1) - the TUN had "
                     "no userspace forwarder, so no traffic could pass through "
                     "it. Tearing the tunnel down.", TunnelState.RUNNING)
        self.assertIs(v.target, TunnelState.FAILED)
        self.assertIs(v.kind, FailureKind.PROCESS)


class TestProxyOutageIsNotADnsOutage(unittest.TestCase):
    """The regression that motivated the module: a closed SOCKS5 port used to
    be reported as FailureKind.DNS, so the DNS ladder escalated to a full
    helper restart - and a restart cannot succeed while the port is refused
    (start_tun2socks_pipe exits on it). One upstream outage became a restart
    crash loop that never recovered."""

    def test_proxy_down_maps_to_proxy_kind(self):
        v = classify("[MONITOR] proxy SOCKS5 is NOT listening on "
                     "127.0.0.1:10808 - the TUN and its routes are installed "
                     "and fine, but there is no upstream to forward to.",
                     TunnelState.RUNNING)
        self.assertIs(v.kind, FailureKind.PROXY)
        self.assertIsNot(v.kind, FailureKind.DNS)
        self.assertIs(v.target, TunnelState.DEGRADED)

    def test_proxy_up_does_not_claim_running(self):
        """The port answering again is necessary but not sufficient - only a
        real traffic probe may promote the tunnel back to RUNNING."""
        v = classify("[MONITOR] proxy SOCKS5 is listening again on "
                     "127.0.0.1:10808 - re-verifying the tunnel now.",
                     TunnelState.DEGRADED)
        self.assertIsNone(v.target)
        self.assertIsNone(v.kind)
        self.assertTrue(v.log)

    def test_probe_failure_stays_dns(self):
        v = classify("[MONITOR] tunnel check failed (2/2): no endpoint "
                     "answered", TunnelState.RUNNING)
        self.assertIs(v.kind, FailureKind.DNS)


class TestGating(unittest.TestCase):
    def test_leak_ok_only_clears_a_leak_verdict(self):
        line = "[MONITOR] leak check OK: same exit 1.2.3.4"
        self.assertIs(classify(line, TunnelState.DEGRADED).target,
                      TunnelState.RUNNING)
        # From any other state the line is ordinary output again.
        for state in (TunnelState.RUNNING, TunnelState.VERIFYING,
                      TunnelState.RECOVERING, TunnelState.STOPPED):
            self.assertIsNone(classify(line, state), state)

    def test_unknown_current_skips_the_gate(self):
        self.assertIs(classify("[MONITOR] leak check OK: x", None).target,
                      TunnelState.RUNNING)


class TestMarkerContract(unittest.TestCase):
    """Every marker the helper can print is classified, and no cosmetic line
    accidentally acquired a state meaning."""

    def test_every_helper_marker_literal_is_known(self):
        text = helper_text()
        literals = {
            "TUNNEL_ACTIVE": markers.TUNNEL_ACTIVE,
            "READY": markers.READY,
            "START_DEGRADED": markers.START_DEGRADED,
            "START_DEGRADED_LOOP": markers.START_DEGRADED_LOOP,
            "SELF_HEALING": markers.SELF_HEALING,
            "SELF_HEAL_OK": markers.SELF_HEAL_OK,
            "ADAPTER_GONE": markers.ADAPTER_GONE,
            "SELF_HEAL_FAILED": markers.SELF_HEAL_FAILED,
            "PROXY_DOWN": markers.PROXY_DOWN,
            "PROXY_UP": markers.PROXY_UP,
            "TUN2SOCKS_DEAD": markers.TUN2SOCKS_DEAD,
            "PROBE_OK": markers.PROBE_OK,
            "PROBE_FAILED": markers.PROBE_FAILED,
            "LEAK_DETECTED": markers.LEAK_DETECTED,
            "LEAK_OK": markers.LEAK_OK,
        }
        for name, marker in literals.items():
            with self.subTest(marker=name):
                self.assertIn(marker, text,
                              f"helper.py no longer prints {name} "
                              f"({marker!r}) - update the vocabulary")

    def test_helper_prints_the_proxy_markers(self):
        text = helper_text()
        self.assertIn("[MONITOR] proxy SOCKS5 is NOT listening", text)
        self.assertIn("[MONITOR] proxy SOCKS5 is listening again", text)
        self.assertIn("[!] tun2socks exited unexpectedly", text)
        self.assertIn("[!] TUNNEL DEGRADED - traffic verification failed", text)
        self.assertIn("[!] TUNNEL DEGRADED - proxy endpoint routes loop", text)

    def test_helper_only_announces_ready_after_verification(self):
        """The ready marker must be behind the verification result, or a
        broken tunnel is announced as usable again."""
        text = helper_text()
        verify = text.index("stable = wait_for_tunnel_stable()")
        ready = text.index('print("[*] Press Ctrl+C to stop.", flush=True)')
        self.assertLess(verify, ready)
        # ...and the condition guarding it must mention `stable`.
        guard = text[max(0, ready - 200):ready]
        self.assertIn("if stable and endpoints_ok:", guard)

    def test_cosmetic_markers_have_no_state(self):
        for marker in markers.NON_STATE_MARKERS:
            with self.subTest(marker=marker):
                self.assertIsNone(classify(marker + " trailing detail"))

    def test_known_markers_are_unique_and_non_empty(self):
        self.assertEqual(len(set(markers.KNOWN_MARKERS)),
                         len(markers.KNOWN_MARKERS))
        for marker in markers.KNOWN_MARKERS:
            self.assertTrue(marker.strip())
            self.assertTrue(markers.known_marker(marker + " x"), marker)

    def test_no_rule_shadows_a_more_specific_later_rule(self):
        """Matching is order-sensitive; a shorter prefix listed first would
        swallow a longer, more specific marker that follows it."""
        for i, (prefix, _) in enumerate(markers._RULES):
            for later, _verdict in markers._RULES[i + 1:]:
                self.assertFalse(
                    later.startswith(prefix),
                    f"{later!r} is shadowed by the earlier rule {prefix!r}")


class TestVerdictRules(unittest.TestCase):
    def test_every_state_change_carries_a_reason(self):
        for prefix, verdict in markers._RULES:
            if verdict.target is not None:
                with self.subTest(marker=prefix):
                    self.assertTrue(verdict.effective_reason,
                                    f"{prefix!r} changes state with no reason")

    def test_reported_failures_carry_a_detail(self):
        for prefix, verdict in markers._RULES:
            if verdict.kind is not None:
                with self.subTest(marker=prefix):
                    self.assertTrue(verdict.detail_for(prefix),
                                    f"{prefix!r} reports a failure with no "
                                    "detail for the recovery log")

    def test_detail_is_taken_from_the_helper_line(self):
        """The helper puts the actual cause after the separator; a fixed
        string would throw it away."""
        self.assertEqual(
            classify("[MONITOR] tunnel check failed (2/2): no endpoint "
                     "answered", TunnelState.RUNNING).detail_for(
                         "[MONITOR] tunnel check failed (2/2): no endpoint "
                         "answered"),
            "no endpoint answered")
        self.assertEqual(
            classify("[!] Self-heal failed: netsh exit 1",
                     TunnelState.RUNNING).detail_for(
                         "[!] Self-heal failed: netsh exit 1"),
            "netsh exit 1")
        # No usable tail -> the fixed fallback, never an empty incident.
        v = classify("[MONITOR] tunnel check failed", TunnelState.RUNNING)
        self.assertTrue(v.detail_for("[MONITOR] tunnel check failed"))

    def test_start_degraded_keeps_the_helper_explanation(self):
        line = ("[!] TUNNEL DEGRADED - traffic verification failed: the TUN "
                "and its routes are installed but no traffic probe succeeded "
                "through them.")
        self.assertIn("no traffic probe succeeded",
                      classify(line, TunnelState.VERIFYING).detail_for(line))

    def test_verdict_is_immutable(self):
        v = Verdict(target=TunnelState.RUNNING)
        with self.assertRaises(Exception):
            v.target = TunnelState.STOPPED       # frozen dataclass

    def test_applies_in_without_a_gate(self):
        v = Verdict(target=TunnelState.RUNNING)
        self.assertTrue(v.applies_in(TunnelState.STOPPED))
        self.assertTrue(v.applies_in(None))


if __name__ == "__main__":
    unittest.main()
