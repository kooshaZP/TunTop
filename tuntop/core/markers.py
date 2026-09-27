"""The helper's stdout vocabulary - the one place that decides what each
line MEANS.

The helper (``tuntop.tunnel.helper``) and the dashboard share only a pipe of
free-form text, so the dashboard's reader thread used to carry a ~200-line
``if line.startswith(...)`` chain that quietly decided three things at once:

    1. which tunnel STATE the machine should move to,
    2. which RECOVERY failure kind to report (and therefore which repair
       ladder runs, and how long it waits before the first attempt),
    3. whether the line is shown, replaced or swallowed in the event log.

That coupling is where precision went to die. ``[MONITOR] tunnel check
failed`` was hard-coded to ``FailureKind.DNS`` regardless of the actual
cause, so a *proxy* outage (the local SOCKS5 port is closed) was handled by a
DNS repair ladder that escalates to a full helper restart - and a restart
cannot succeed while the port is closed (``start_tun2socks_pipe`` exits on a
refused connect). One upstream outage therefore escalated into a restart
crash loop that took the whole tunnel down and never came back.

Here the vocabulary is data, in one table, and it is PURE: a line in, a
``Verdict`` out, no I/O, no state mutation, no Windows calls. That makes the
mapping exhaustively unit-testable (see ``tests/unit/test_markers.py``) and
turns an unclassified line into an explicit, greppable decision instead of
an accident of ordering inside a thread.

The helper's line format is therefore a CONTRACT. Renaming a marker means
changing it here too.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from tuntop.core.recovery import FailureKind
from tuntop.core.state import TunnelState


@dataclass(frozen=True)
class Verdict:
    """What one helper line means. Every field defaults to "do nothing",
    so a purely informational marker is `Verdict(log=True)`."""

    #: Tunnel state to request. Applied with ``try_transition``, so an
    #: illegal target is dropped (and counted) by the state machine itself
    #: rather than being second-guessed here.
    target: Optional[TunnelState] = None
    #: Why we are asking for it; falls back to `detail` when empty.
    reason: str = ""
    #: Recovery failure kind to report, or None to report nothing.
    kind: Optional[FailureKind] = None
    #: Incident detail handed to the recovery engine.
    detail: str = ""
    #: When set, the incident detail is taken from the helper line itself -
    #: everything after the first occurrence of this separator. The helper
    #: puts the real cause there ("...: no endpoint answered"), and a fixed
    #: string would throw that away, which is exactly the information an
    #: operator needs to tell a dead DNS path from a dead route.
    detail_after: str = ""
    #: False to swallow the line from the event log (pure noise, e.g. the
    #: 30 s "[MONITOR] tunnel OK" heartbeat, whose information is carried by
    #: the state transition itself).
    log: bool = True
    #: When set, this text is logged INSTEAD of the raw line (the helper
    #: prints a Ctrl+C instruction; the dashboard prints what it means).
    replace: str = ""
    #: When True the raw line is logged too, after `replace` - for markers
    #: whose dashboard gloss must not hide the helper's own words.
    log_raw: bool = False
    #: When non-empty, the state request only applies if the machine is
    #: currently in one of these states. Empty = no gate.
    only_from: tuple = field(default_factory=tuple)

    @property
    def effective_reason(self) -> str:
        """The string to hand the state machine as the transition reason."""
        return self.reason or self.detail

    def detail_for(self, line: str) -> str:
        """The incident detail for `line`: whatever the helper reported after
        `detail_after`, or the fixed `detail` when there is nothing usable."""
        if self.detail_after:
            head, sep, tail = line.partition(self.detail_after)
            if sep and tail.strip():
                return tail.strip()
        return self.detail

    def applies_in(self, current: Optional[TunnelState]) -> bool:
        """Whether this verdict's state request is meaningful from `current`.

        `current=None` means "unknown", and the gate is then not applied."""
        if not self.only_from or current is None:
            return True
        return current in self.only_from


# ── Marker text (the contract with tuntop.tunnel.helper) ──────────────────

#: Start sequence finished but traffic never verified.
START_DEGRADED = "[!] TUNNEL DEGRADED - traffic verification failed"
#: Start sequence finished with a proxy transport that loops through the TUN.
START_DEGRADED_LOOP = "[!] TUNNEL DEGRADED - proxy endpoint routes loop"
#: Routes are in; the helper is now probing real traffic.
TUNNEL_ACTIVE = "[+] TUNNEL ACTIVE"
#: The helper's "you may now Ctrl+C" line - emitted only after verification.
READY = "[*] Press Ctrl+C to stop"
SELF_HEALING = "[*] Self-healing:"
SELF_HEAL_OK = "[+] Self-heal applied."
#: The Wintun adapter itself disappeared - the tunnel cannot be repaired in
#: place, only rebuilt.
ADAPTER_GONE = "[!] Self-heal: Wintun adapter is gone"
SELF_HEAL_FAILED = "[!] Self-heal failed:"
#: The local SOCKS5 inbound stopped accepting connections (upstream outage).
PROXY_DOWN = "[MONITOR] proxy SOCKS5 is NOT listening"
#: ... and started answering again.
PROXY_UP = "[MONITOR] proxy SOCKS5 is listening again"
#: tun2socks, the userspace forwarder, died.
TUN2SOCKS_DEAD = "[!] tun2socks exited unexpectedly"
PROBE_FAILED = "[MONITOR] tunnel check failed"
PROBE_OK = "[MONITOR] tunnel OK"
LEAK_DETECTED = "[MONITOR] LEAK DETECTED"
LEAK_OK = "[MONITOR] leak check OK"

#: Purely cosmetic helper lines the reader still has to notice (geo progress,
#: proxy2 status, DNS resolution notes, gateway re-points). Listed so the
#: tests can assert none of them was accidentally given a state meaning.
NON_STATE_MARKERS: tuple = (
    "[GEO-PARSE]", "[GEO-LOAD]", "[GEO-DONE]",
    "[*] proxy2 pipe skipped", "[*] proxy2 pipe active",
    "[*] Loading geo bypass ranges", "[*] Installing geoip",
    "[GATEWAY]",
)


# ── Verdicts ──────────────────────────────────────────────────────────────

V_ROUTES_INSTALLED = Verdict(
    target=TunnelState.VERIFYING, reason="routes installed",
    replace="[*] Routes installed - verifying traffic through the TUN...",
    log_raw=True)

V_START_COMPLETE = Verdict(
    target=TunnelState.RUNNING, reason="start sequence complete - tunnel stable",
    log=False,
    replace="[+] START SEQUENCE COMPLETE - the TUN is READY TO USE.")

# The start sequence completed WITHOUT proving traffic. Routes stay installed
# and the tunnel heals by itself, so this is DEGRADED (recoverable in place),
# never FAILED and never RUNNING. The two causes get different ladders: an
# endpoint route that loops is a ROUTES fault (re-assert the transport
# routes), an unverified probe is the ordinary egress/DNS ladder.
V_START_DEGRADED = Verdict(
    target=TunnelState.DEGRADED,
    reason="start sequence finished but traffic did not verify",
    kind=FailureKind.DNS, detail_after="failed: ",
    detail="tunnel installed but the first traffic probe failed")

V_START_DEGRADED_LOOP = Verdict(
    target=TunnelState.DEGRADED,
    reason="proxy endpoint routes would loop through the TUN",
    kind=FailureKind.ROUTES, detail_after="loop: ",
    detail="proxy endpoint /32 bypasses are missing or pinned to a tunnel")

V_SELF_HEALING = Verdict(
    target=TunnelState.RECOVERING,
    reason="self-heal: re-applying wintun config and routes")

V_SELF_HEAL_OK = Verdict(
    target=TunnelState.RUNNING, reason="self-heal applied")

V_ADAPTER_GONE = Verdict(
    target=TunnelState.FAILED, reason="self-heal: Wintun adapter is gone",
    kind=FailureKind.ADAPTER,
    detail="Wintun adapter is gone; cannot re-apply routes")

V_SELF_HEAL_FAILED = Verdict(
    target=TunnelState.DEGRADED, reason="self-heal failed",
    kind=FailureKind.ROUTES, detail_after=": ",
    detail="self-heal could not re-apply the TUN configuration")

# A closed SOCKS5 port is an UPSTREAM outage, deliberately NOT a DNS/route
# fault: no route repair can fix a closed port, and neither can a helper
# restart. Its ladder waits for the port instead of restarting anything.
V_PROXY_DOWN = Verdict(
    target=TunnelState.DEGRADED,
    reason="local SOCKS5 proxy is not listening",
    kind=FailureKind.PROXY, detail_after=" - ",
    detail="local SOCKS5 proxy stopped accepting connections")

# Coming back is not a success claim. The tunnel only returns to RUNNING when
# a real traffic probe passes - the helper re-probes immediately, so the gap
# is one probe, not one monitor interval.
V_PROXY_UP = Verdict(reason="local SOCKS5 proxy is listening again")

V_PROBE_FAILED = Verdict(
    target=TunnelState.DEGRADED, reason="monitor probe failed",
    kind=FailureKind.DNS, detail_after="): ",
    detail="the monitor's traffic probe failed through the TUN")

V_PROBE_OK = Verdict(
    target=TunnelState.RUNNING, reason="monitor probe OK", log=False)

V_LEAK = Verdict(
    target=TunnelState.DEGRADED,
    reason="traffic leaks outside the TUN")

# A passing leak check only re-proves egress while the machine is actually
# holding a leak verdict. Ungated, it would resurrect a tunnel that failed
# for an unrelated reason - the leak probe shares the regular probe's
# success, so it says nothing about the proxy being alive.
V_LEAK_OK = Verdict(
    target=TunnelState.RUNNING,
    reason="leak check OK - all egress via the tunnel",
    only_from=(TunnelState.DEGRADED,))

V_TUN2SOCKS_DEAD = Verdict(
    target=TunnelState.FAILED, reason="tun2socks exited",
    kind=FailureKind.PROCESS, detail_after="(code ",
    detail="tun2socks exited - the TUN has no userspace forwarder")


#: (marker prefix, verdict). Matching is order-SENSITIVE: the first rule whose
#: prefix matches wins, so a rule must never be able to shadow a more specific
#: one that follows it. Prefixes are matched with ``startswith``, which keeps
#: them working when the helper appends detail after the marker.
_RULES: tuple = (
    (START_DEGRADED_LOOP, V_START_DEGRADED_LOOP),
    (START_DEGRADED, V_START_DEGRADED),
    (TUNNEL_ACTIVE, V_ROUTES_INSTALLED),
    (READY, V_START_COMPLETE),
    (SELF_HEALING, V_SELF_HEALING),
    (SELF_HEAL_OK, V_SELF_HEAL_OK),
    (ADAPTER_GONE, V_ADAPTER_GONE),
    (SELF_HEAL_FAILED, V_SELF_HEAL_FAILED),
    (PROXY_DOWN, V_PROXY_DOWN),
    (PROXY_UP, V_PROXY_UP),
    (PROBE_FAILED, V_PROBE_FAILED),
    (PROBE_OK, V_PROBE_OK),
    (LEAK_DETECTED, V_LEAK),
    (LEAK_OK, V_LEAK_OK),
    (TUN2SOCKS_DEAD, V_TUN2SOCKS_DEAD),
)

#: Every prefix the classifier recognises, in match order. Tests assert the
#: helper's own literals are all here, so a renamed marker cannot silently
#: degrade into an unclassified line.
KNOWN_MARKERS: tuple = tuple(prefix for prefix, _ in _RULES)


def classify(line: str, current: Optional[TunnelState] = None
            ) -> Optional[Verdict]:
    """Map one helper stdout line to its meaning.

    Returns None when the line is ordinary output with no state or recovery
    consequence - which includes a state-bearing marker whose gate does not
    hold (``current`` provided and the machine is not in ``only_from``).

    Pure and total: any input, including "", yields a Verdict or None and it
    never raises, so the reader thread can call it on every line of helper
    output without a try/except around it.
    """
    if not line:
        return None
    for prefix, verdict in _RULES:
        if line.startswith(prefix):
            return verdict if verdict.applies_in(current) else None
    return None


def known_marker(line: str) -> bool:
    """True when `line` is a marker the vocabulary recognises."""
    return classify(line) is not None
