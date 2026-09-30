r"""DNS leak guard - pin the Windows DNS client to the tunnel resolvers.

WHY THIS EXISTS
---------------
Setting resolvers on the `wintun` adapter and lowering its InterfaceMetric is
NOT enough to keep DNS inside the tunnel. Windows enables Smart Multi-Homed
Name Resolution (SMHNR) by default: the DNS client sends each query out over
EVERY connected interface that has resolvers and takes the first answer. The
interface metric only ORDERS the server list - it does not stop the parallel
query to a DHCP-assigned physical resolver (the router's 192.168.1.1), which
is on-link, so the TUN's split-defaults (0.0.0.0/1, ::/1) never capture it.
The router/ISP answer wins and the ISP's resolvers show up in a leak test -
while TunTop's own probes (which only test the CONFIGURED resolvers) still
report "no leak". Closing that gap is this module's job.

THE MECHANISM: a catch-all NRPT rule
------------------------------------
The Name Resolution Policy Table (NRPT) is consulted by the Windows DNS
client for every name, and a rule that claims the root namespace (".") with
an override server list makes the client use ONLY those servers - regardless
of whether SMHNR is on or off (SANS: "Preventing Windows 10 SMHNR DNS
Leakage"). The rule lives in the local policy store:

    HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig

with values Version (DWORD), Name (MULTI_SZ namespaces), GenericDNSServers
(REG_SZ) and ConfigOptions (DWORD, 0x8 = "use the provided override DNS
resolvers"). Every key this module writes starts with the TunTop- prefix, so
cleanup can enumerate exactly what it created and never touch a foreign rule
(a corporate VPN's, DirectAccess's, ...).

RFC 6762 reserves `.local` for multicast DNS and forbids unicast resolvers
from answering for it: a catch-all rule would hand it to 8.8.8.8 anyway and
printers/NAS boxes would start answering NXDOMAIN. So a SECOND rule claims
`.local` with an empty server list, which Windows treats as an EXEMPTION
(resolve such names normally). The encoding matters: GenericDNSServers must
be PRESENT and empty while ConfigOptions stays 0x8 - a missing value makes
Windows drop the rule entirely and the catch-all keeps the query.

CLEANUP IS SACRED
-----------------
An NRPT rule that outlives the tunnel would keep hijacking name resolution, so
removal has five independent owners: the helper's cleanup(), the next launch's
startup recovery, the detached cleanup watchdog, the dashboard's stop/quit
sweeps, and - the only one that survives the machine itself - a ONE-SHOT
Task Scheduler entry armed for the next boot (boot_cleanup_action). A BSOD or a
power cut kills the other four in the same instant, and the rule is a registry
entry that does not care whether TunTop ever runs again, so that fifth owner is
what keeps a crash from leaving a machine with no name resolution at all. It is
armed by install() BEFORE the rule is written, and consumed (and deleted) by the
first boot that follows. STATE_FILE records what was installed so even a crash
in the middle of the install stays recoverable.

Pure stdlib, no pip dependencies. The PowerShell text lives here (single
source of truth, unit-tested as text) and the runner is injectable, so the
module behaves identically in tests, in the helper process and in the
dashboard.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
from typing import Callable, Optional

__all__ = [
    "GUARD_KEY_PREFIX", "MATCH_KEY", "EXEMPT_LOCAL_KEY", "LOCAL_NAMESPACE",
    "CATCH_ALL_NAMESPACE", "CONFIG_OPTIONS_OVERRIDE_DNS", "RULE_VERSION",
    "DEFAULT_EXEMPT_NAMESPACES", "STATE_FILE", "NRPT_ROOT", "BOOT_TASK_NAME",
    "guard_resolvers", "install_script", "uninstall_script", "detect_script",
    "parse_detect", "save_state", "load_state", "clear_state", "state_path",
    "install", "uninstall", "detect", "ensure_installed", "ensure_removed",
    "foreign_resolvers", "foreign_resolvers_script", "guard_in_force",
    "parse_foreign", "DEFAULT_TUNNEL_ALIASES",
    "boot_cleanup_action", "arm_boot_cleanup_script",
    "disarm_boot_cleanup_script", "arm_boot_cleanup", "disarm_boot_cleanup",
]

# ── Rule identity ───────────────────────────────────────────────────────────
#: Every registry key this module writes starts here, so removal can
#: enumerate exactly the rules TunTop created.
GUARD_KEY_PREFIX = "TunTop-"
MATCH_KEY = GUARD_KEY_PREFIX + "Match"                # the catch-all rule
EXEMPT_LOCAL_KEY = GUARD_KEY_PREFIX + "ExemptLocal"   # the .local exemption

#: The root namespace claims every name - the NRPT's notation for "all names"
#: is a single dot.
CATCH_ALL_NAMESPACE = "."
#: RFC 6762 multicast-DNS namespace: must stay resolvable WITHOUT a unicast
#: resolver answering for it.
LOCAL_NAMESPACE = ".local"
#: Namespaces that always get the exemption treatment (extendable per run via
#: --dns-guard-exempt, e.g. a home domain only the router resolver knows).
DEFAULT_EXEMPT_NAMESPACES = (LOCAL_NAMESPACE,)

#: NRPT ConfigOptions bit for "use the provided override DNS resolvers".
CONFIG_OPTIONS_OVERRIDE_DNS = 0x8
#: Rule schema version (2 is what Add-DnsClientNrptRule writes on Win10/11).
RULE_VERSION = 2

#: The local (non-GPO) NRPT store the DNS client consults for every query.
NRPT_ROOT = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig"
NRPT_PS_ROOT = ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache"
                "\\Parameters\\DnsPolicyConfig")

# Re-exported so callers can reach the shared VPN-adapter pattern from here
# too. It is DEFINED in tuntop.config.defaults (one definition, imported by
# the helper, the egress script builder and the health checks - it used to be
# re-hardcoded in seven places across three modules, and any disagreement made
# a route get pointed at an interface the rest of the code believed was "not
# a VPN").
from tuntop import procidentity
from tuntop.config.defaults import VPN_IFACE_RE as VPN_IFACE_RE  # noqa: F401
from tuntop.psshell import ps_quote

#: Where the install record lives. Frozen exe: next to TunTop.exe (stable
#: across runs, identical for the helper child and the watchdog); source run:
#: next to this module - the same rule core/startup_recovery.py uses for
#: MARKER_FILE.
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          ".tuntop_dns_guard.json")
if getattr(sys, "frozen", False):
    STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(sys.executable)),
                              ".tuntop_dns_guard.json")

STATE_VERSION = 2
#: A rule with no override servers would force every lookup to fail - never
#: write one, and never claim more resolvers than a rule can carry.
_MAX_SERVERS = 8

#: The Comment written into the catch-all rule (also what makes a
#: cmdlet-created leftover identifiable during cleanup).
GUARD_COMMENT = ("TunTop: temporary DNS leak protection - all name resolution "
                 "is pinned to the tunnel resolvers. Removed when the tunnel "
                 "stops.")

#: Name of the ONE-SHOT boot-time cleanup task (see boot_cleanup_action).
#: TunTop- prefixed like the registry keys, so it is obvious in Task Scheduler
#: whose task it is and so an operator can unregister it by hand.
BOOT_TASK_NAME = "TunTop-DnsGuard-Removal"


def state_path() -> str:
    """The install record's path (read through a function so a test can
    redirect the module global without touching the filesystem)."""
    return STATE_FILE


# ── Resolver selection ──────────────────────────────────────────────────────

def guard_resolvers(dns4, dns6) -> list:
    """The resolvers the catch-all rule should claim, in order (v4 first).

    An empty list means "nothing to pin": the caller must then make sure no
    stale rule survives (`ensure_removed`), because a guard pointing at an
    empty list is a black hole, not protection."""
    out = []
    for srv in (dns4, dns6):
        s = str(srv).strip() if srv else ""
        if s and s not in out:
            out.append(s)
    return out[:_MAX_SERVERS]


def _servers_value(resolvers) -> str:
    """`GenericDNSServers` REG_SZ payload: one address, or several joined with
    ';' (the separator Windows' own GPO export uses for an NRPT server
    list)."""
    return ";".join(str(s).strip() for s in (resolvers or [])
                    if str(s).strip())


def _ps_quote(text) -> str:
    """Single-quote a PowerShell literal, so a namespace or comment can never
    break out into the script body.

    The ESCAPING is the shared tuntop.psshell.ps_quote - this used to be a
    third copy of the same logic that only doubled the ASCII apostrophe, which
    is precisely what the psshell docstring promised could never happen. It is
    the only one of the three that also WRAPS the value in quotes, so the
    wrapper stays here and only the escape delegates.
    """
    return "'" + ps_quote(text) + "'"


def _normalise_exempt(names):
    """Canonical NRPT namespace form for the exemption list.

    NRPT treats a name WITHOUT a leading dot as an EXACT match and a name WITH
    one as a suffix match ("this domain and everything under it"). So
    `--dns-guard-exempt corp.example` used to be written literally and matched
    only the name `corp.example` itself - `printer.corp.example`,
    `files.corp.example` and every other host under it stayed pinned to the
    tunnel resolvers, which is the opposite of what the user asked for and
    looks like the exemption "not working".

    So: lowercase, strip surrounding dots, and re-add exactly one leading dot.
    `.local` is already written with its dot and is unaffected. A bare
    hostname is still promoted to a suffix match, which is the only reading
    anyone means by "keep this domain resolvable".
    """
    out = []
    for n in (names or ()):
        s = str(n).strip().lower().strip(".")
        if s and f".{s}" not in out:
            out.append(f".{s}")
    return out


# ── Script text (single source of truth, unit-tested) ───────────────────────

def install_script(resolvers, exempt=(), comment: str = GUARD_COMMENT) -> str:
    """PowerShell that installs (or refreshes) the catch-all rule plus the
    exemption rule, then flushes the resolver cache.

    WRITTEN IN PLACE, NEVER SWAPPED. This used to drop every TunTop-* key up
    front and only then write the replacement, which opened a window - on
    EVERY re-apply (self-heal, a live [N] DNS change, a VPN-shadow pass) - in
    which no rule existed at all, i.e. Windows was free to ask a physical
    adapter's resolver in parallel and let the ISP answer. That is exactly the
    leak the guard exists to close, and it reopened for the duration of the
    re-assert on a schedule the tunnel itself drives.

    A later revision staged the replacement under a `TunTop-Match.new` key and
    then did `Remove-Item` on the LIVE key followed by `Move-Item` - which is
    the same gap, narrowed to the two statements between them, and still on
    every re-assert. `Move-Item -Force` cannot overwrite an existing directory
    in PowerShell, so the delete was load-bearing for the swap and the swap was
    the leak. There is no need for a swap at all: `New-Item -Force` opens the
    key when it exists, and each `New-ItemProperty -Force` is an idempotent
    value replace. The rule therefore exists CONTINUOUSLY and only its
    contents are refreshed.

    THE FAILURE DIRECTION IS SAFE. If a value write fails part-way the rule
    keeps the PREVIOUS server list - which is still the tunnel's resolvers, so
    it is still a working leak-free pin, not a black hole. The script reports
    DNS_GUARD_FAIL, `install()` returns False and the monitor's re-assert
    retries. The old staging version instead had to delete the good rule to
    find out whether the new one could be written."""
    servers = _servers_value(resolvers)
    if not servers:
        # Callers must use uninstall_script() for this case: a rule with no
        # servers is a black hole, so fail loudly instead of writing it.
        return "Write-Output 'DNS_GUARD_FAIL:no resolver configured'\n"
    exempts = _normalise_exempt(exempt)
    exempt_script = ""
    # Keys that must survive the post-write sweep. With no exemptions the
    # exemption key is NOT protected, so removing the last --dns-guard-exempt
    # actually deletes its stale NRPT rule (it is what
    # `Remove-DnsClientNrptRule` would otherwise leave behind) - and the name
    # does not appear in the script at all in that case.
    keep_keys = [MATCH_KEY] + ([EXEMPT_LOCAL_KEY] if exempts else [])
    keep_ps = "\n            -and ".join(
        f"$_.PSChildName -ne {_ps_quote(k)}" for k in keep_keys)
    if exempts:
        names_ps = ",".join(_ps_quote(n) for n in exempts)
        exempt_script = f"""
    # Exemption rule: names Windows must keep resolving normally. The
    # GenericDNSServers value MUST be present and empty here (ConfigOptions
    # stays 0x8): a missing value makes Windows discard the rule and the
    # catch-all keeps the query - exactly the NXDOMAIN-for-.local bug this
    # rule prevents. Written IN PLACE for the same reason as the catch-all
    # above: it is never deleted, so it is never absent either.
    $ex = Join-Path $root {_ps_quote(EXEMPT_LOCAL_KEY)}
    New-Item -Path $ex -Force | Out-Null
    New-ItemProperty -Path $ex -Name 'Version' -PropertyType DWord -Value {RULE_VERSION} -Force | Out-Null
    New-ItemProperty -Path $ex -Name 'Name' -PropertyType MultiString -Value @({names_ps}) -Force | Out-Null
    New-ItemProperty -Path $ex -Name 'GenericDNSServers' -PropertyType String -Value '' -Force | Out-Null
    New-ItemProperty -Path $ex -Name 'ConfigOptions' -PropertyType DWord -Value {CONFIG_OPTIONS_OVERRIDE_DNS} -Force | Out-Null
    New-ItemProperty -Path $ex -Name 'Comment' -PropertyType String -Value {_ps_quote('TunTop: NRPT exemption - names the tunnel resolvers must not answer (mDNS .local etc.).')} -Force | Out-Null
"""
    return f"""$ErrorActionPreference = 'Stop'
$root = {_ps_quote(NRPT_PS_ROOT)}
try {{
    if (-not (Test-Path $root)) {{ New-Item -Path $root -Force | Out-Null }}
    # IN PLACE. See the docstring: staging under a .new key and swapping still
    # required deleting the live rule first, which is a gap on every
    # re-assert. `New-Item -Force` opens the key when it exists, so the
    # catch-all is never absent - only its values are refreshed.
    $k = Join-Path $root {_ps_quote(MATCH_KEY)}
    New-Item -Path $k -Force | Out-Null
    New-ItemProperty -Path $k -Name 'Version' -PropertyType DWord -Value {RULE_VERSION} -Force | Out-Null
    New-ItemProperty -Path $k -Name 'Name' -PropertyType MultiString -Value @({_ps_quote(CATCH_ALL_NAMESPACE)}) -Force | Out-Null
    New-ItemProperty -Path $k -Name 'GenericDNSServers' -PropertyType String -Value {_ps_quote(servers)} -Force | Out-Null
    New-ItemProperty -Path $k -Name 'ConfigOptions' -PropertyType DWord -Value {CONFIG_OPTIONS_OVERRIDE_DNS} -Force | Out-Null
    New-ItemProperty -Path $k -Name 'Comment' -PropertyType String -Value {_ps_quote(comment)} -Force | Out-Null
{exempt_script}    # NOW drop anything that is NOT part of the set we just wrote -
    # i.e. a stale exemption key, or a .new/.old left behind by a run of the
    # pre-1.0.51 staging version. The keys we just wrote are always kept, and
    # the live catch-all is never a sweep candidate.
    Get-ChildItem -Path $root -ErrorAction SilentlyContinue |
        Where-Object {{
            $_.PSChildName -like {_ps_quote(GUARD_KEY_PREFIX + '*')}
            -and {keep_ps}
        }} |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Clear-DnsClientCache -ErrorAction SilentlyContinue | Out-Null
    Write-Output 'DNS_GUARD_OK'
}} catch {{
    Write-Output ('DNS_GUARD_FAIL:' + $_.Exception.Message)
}}
"""

def uninstall_script() -> str:
    """PowerShell that removes every rule TunTop created and flushes the
    resolver cache. Safe to run when nothing is installed; NEVER removes a
    foreign NRPT rule.

    The Remove-DnsClientNrptRule pass is a best-effort safety net for rules
    created through the cmdlet (GUID-named keys carrying our display name /
    comment) by an older or partial install.

    The removals are deliberately SilentlyContinue (one unreadable key must not
    abort the sweep), which is exactly why the script RE-ENUMERATES afterwards
    and only reports DNS_GUARD_REMOVED when nothing of ours survived: a denied
    or in-use key removal leaves the rule behind, and telling the caller
    'removed' then would strand a catch-all pin with no record to retry from."""
    return f"""$ErrorActionPreference = 'Stop'
$root = {_ps_quote(NRPT_PS_ROOT)}
try {{
    # PROVE we can actually READ the store before sweeping. Without this,
    # every cmdlet below runs with -ErrorAction SilentlyContinue: a
    # non-elevated process (or an ACL-denied DnsPolicyConfig) makes
    # Get-ChildItem return nothing, $left.Count is 0, and the script happily
    # printed DNS_GUARD_REMOVED while the TunTop-* keys were still there -
    # pinning all name resolution to a tunnel that is being torn down. An
    # unreadable store is a FAILURE, not an empty one.
    if (-not (Test-Path -LiteralPath $root)) {{
        Write-Output 'DNS_GUARD_REMOVED'
        return
    }}
    $probe = @(Get-ChildItem -Path $root -ErrorAction Stop)
    Get-ChildItem -Path $root -ErrorAction SilentlyContinue |
        Where-Object {{ $_.PSChildName -like {_ps_quote(GUARD_KEY_PREFIX + '*')} }} |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object {{ ($_.DisplayName -like 'TunTop*') -or ($_.Comment -like 'TunTop*') }} |
        ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }}
    Clear-DnsClientCache -ErrorAction SilentlyContinue | Out-Null
    $left = @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue |
        Where-Object {{ $_.PSChildName -like {_ps_quote(GUARD_KEY_PREFIX + '*')} }})
    if ($left.Count -gt 0) {{
        Write-Output ('DNS_GUARD_UNINSTALL_FAIL:still present: ' +
            (($left | ForEach-Object {{ $_.PSChildName }}) -join ','))
    }} else {{
        Write-Output 'DNS_GUARD_REMOVED'
    }}
}} catch {{
    Write-Output ('DNS_GUARD_UNINSTALL_FAIL:' + $_.Exception.Message)
}}
"""


def boot_cleanup_action(path: Optional[str] = None) -> str:
    """The body the boot task runs AS SYSTEM, once, at the next startup.

    WHY A BOOT TASK AND NOT A PROCESS
    ---------------------------------
    Every other owner of the removal is a running process: the helper's
    cleanup(), startup recovery, the detached watchdog, the dashboard's
    sweeps. A BSOD or a power cut kills all of them in the same instant, and
    the NRPT rule is a REGISTRY entry - it does not care whether TunTop ever
    runs again. Name resolution is then broken at the OS level, with no user
    logged in, and the only documented way out is a flag the user has to
    remember. The watchdog cannot cover this either: it is a child of the
    dashboard whose whole job is to wait for the dashboard's process to exit,
    so it dies with the OS and nothing respawns it until a user launches
    TunTop - which is the exact situation this exists to avoid.

    SELF-CONTAINED ON PURPOSE. The action is a plain PowerShell one-liner and
    never names TunTop.exe, python, sys.executable or any temp path. After the
    crash that made this necessary the user may well have moved, replaced or
    deleted the app, and a scheduled task whose action cannot be found fails
    SILENTLY at boot - the machine would stay broken with a green-looking task
    in the scheduler.

    The registry root, the TunTop-* prefix and the state file all come from the
    SAME constants uninstall_script() uses, so the invariant that matters most -
    a foreign NRPT rule (a corporate VPN's, DirectAccess's) is never touched -
    cannot drift between the two.
    """
    return (
        "$ErrorActionPreference = 'SilentlyContinue'; "
        f"$r = {_ps_quote(NRPT_PS_ROOT)}; "
        "if (Test-Path -LiteralPath $r) { Get-ChildItem -LiteralPath $r | "
        f"Where-Object {{ $_.PSChildName -like {_ps_quote(GUARD_KEY_PREFIX + '*')} }}"
        " | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }; "
        # The install record must go too, or dns_guard_present() reports True
        # on EVERY later launch and each one logs a phantom "remove leftover
        # DNS guard" for a rule that no longer exists.
        f"Remove-Item -LiteralPath {_ps_quote(path or state_path())} -Force "
        "-ErrorAction SilentlyContinue; "
        "Clear-DnsClientCache -ErrorAction SilentlyContinue | Out-Null"
    )


def arm_boot_cleanup_script(path: Optional[str] = None) -> str:
    """Register/overwrite the one-shot AtStartup cleanup task. Prints
    DNS_GUARD_BOOT_ARMED, or DNS_GUARD_BOOT_FAIL:<reason>.

    -AtStartup + SYSTEM + Highest, because the removal has to happen BEFORE
    anyone logs in - a machine that cannot complete a logon, or whose
    networking needs DNS first, never reaches the point where a user-space
    process could have cleaned up.

    -DeleteExpiredTaskAfter 0 is what makes this a ONE-SHOT: Task Scheduler
    deletes the task the moment it has run, so a leftover can never
    accumulate, re-fire on later boots, or be mistaken for a permanent
    component. The whole lifecycle is therefore bounded by the guard's own.

    -Force makes registration idempotent, which matters because the guard is
    re-asserted on every self-heal cycle and every live [N] DNS change.

    The action travels as -EncodedCommand (base64 UTF-16LE) rather than as
    quoted text. Boot-cleanup actions are exactly where quoting goes wrong: the
    body is a single-quoted PowerShell literal that itself carries single
    quotes, and the alternative (`-Command "..."`) makes the child's own parser
    expand the body's variables. Base64 sidesteps both - nothing in the payload
    needs escaping at any layer.
    """
    encoded = base64.b64encode(
        boot_cleanup_action(path).encode("utf-16-le")).decode("ascii")
    # Pre-computed rather than inline. A MULTI-LINE expression (or a backslash)
    # inside an f-string replacement field is a SyntaxError before 3.12 - PEP
    # 701 is what relaxed it - and this module has to import on the 3.10 floor
    # CI tests. 1.0.49 shipped a SyntaxError from exactly this construct, on
    # the interpreter the release build did not use, and the fix is to keep
    # every replacement field a single line with no escapes.
    arg = ("-NoProfile -NonInteractive -WindowStyle Hidden "
           "-ExecutionPolicy Bypass -EncodedCommand " + encoded)
    return f"""$ErrorActionPreference = 'Stop'
try {{
    $task = {_ps_quote(BOOT_TASK_NAME)}
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument {_ps_quote(arg)}
    $trg = New-ScheduledTaskTrigger -AtStartup
    $prn = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
        -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 0)
    Register-ScheduledTask -TaskName $task -Action $act -Trigger $trg `
        -Principal $prn -Settings $set -Force | Out-Null
    # Do not trust Register-ScheduledTask's exit: a constrained or disabled
    # Task Scheduler can accept the call and register nothing, and the whole
    # point of this is that a silent no-op here means a machine with no DNS.
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {{
        Write-Output 'DNS_GUARD_BOOT_ARMED'
    }} else {{
        Write-Output 'DNS_GUARD_BOOT_FAIL:the task did not register'
    }}
}} catch {{
    Write-Output ('DNS_GUARD_BOOT_FAIL:' + $_.Exception.Message)
}}
"""


def disarm_boot_cleanup_script() -> str:
    """Unregister the one-shot boot task. Prints DNS_GUARD_BOOT_DISARMED, or
    DNS_GUARD_BOOT_DISARM_FAIL:<reason>.

    Only ever called on a CONFIRMED rule removal. A task left behind is
    harmless (it runs once, finds nothing, deletes itself), whereas a rule left
    behind is not - so the asymmetry is deliberate and the callers must keep
    it. An absent task is a success: there is nothing to disarm.
    """
    return f"""$ErrorActionPreference = 'Stop'
try {{
    $task = {_ps_quote(BOOT_TASK_NAME)}
    $t = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    if ($t) {{
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Stop
        Write-Output 'DNS_GUARD_BOOT_DISARMED'
    }} else {{
        Write-Output 'DNS_GUARD_BOOT_DISARMED'
    }}
}} catch {{
    Write-Output ('DNS_GUARD_BOOT_DISARM_FAIL:' + $_.Exception.Message)
}}
"""


def detect_script() -> str:
    """PowerShell that reports the guard's state in one parseable line:

        DNS_GUARD_STATE:keys=<n>,match=<n>,effective=<true|false>,servers=<...>

    `keys` counts our registry rules (the catch-all plus any exemption);
    `match` counts ONLY the catch-all, so a caller can tell "our pin is
    installed" from "only the .local exemption survived a GPO refresh";
    `effective` is whether Windows' own effective NRPT policy actually carries
    the root namespace - the ground truth, since a rule Windows dropped from
    the policy never takes effect; `boot` is whether the one-shot startup task
    that removes a surviving rule is still armed, i.e. whether a BSOD would
    leave this machine without DNS. It rides along in THIS spawn rather than
    adding a second one, because the health row reads it on every tick."""
    return f"""$root = {_ps_quote(NRPT_PS_ROOT)}
$keys = @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue |
    Where-Object {{ $_.PSChildName -like {_ps_quote(GUARD_KEY_PREFIX + '*')} }})
$match = @($keys | Where-Object {{ $_.PSChildName -eq {_ps_quote(MATCH_KEY)} }}).Count
$servers = ''
$eff = $false
try {{
    if ($match -gt 0) {{
        $k = $keys | Where-Object {{ $_.PSChildName -eq {_ps_quote(MATCH_KEY)} }} | Select-Object -First 1
        $servers = [string](Get-ItemProperty -Path $k.PSPath -Name 'GenericDNSServers' -ErrorAction SilentlyContinue).GenericDNSServers
    }}
}} catch {{ }}
try {{
    $pol = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
    if (@($pol | Where-Object {{ $_.Namespace -contains {_ps_quote(CATCH_ALL_NAMESPACE)} }}).Count -gt 0) {{
        $eff = $true
    }}
}} catch {{ }}
$boot = $false
try {{
    $boot = [bool](Get-ScheduledTask -TaskName {_ps_quote(BOOT_TASK_NAME)} -ErrorAction SilentlyContinue)
}} catch {{ }}
# FIELD SEPARATOR: ',' - NOT ';'. The `servers` field is a resolver LIST
# joined with ';' by _servers_value(), so splitting the line on ';' chopped a
# two-resolver value ("8.8.8.8;2606:4700:4700::1111") into a first field
# "8.8.8.8" plus an orphan part that matched no branch and was dropped. Every
# diagnostic then reported only the first resolver, hiding the v6 half of the
# pin. A resolver list can never contain ',', so ',' is unambiguous.
Write-Output ('DNS_GUARD_STATE:keys=' + @($keys).Count + ',match=' + $match + ',effective=' + $eff.ToString().ToLower() + ',boot=' + $boot.ToString().ToLower() + ',servers=' + $servers)
"""


def parse_detect(out) -> dict:
    """Parse detect_script()'s output. Always returns a dict:

        {"keys": int, "match": int, "effective": bool, "boot": bool,
         "servers": str, "ok": bool}

    `ok` is True only when OUR catch-all rule exists AND Windows' effective
    policy carries the root namespace, i.e. the guard is actually protecting
    DNS. A leftover exemption key alone is never `ok`: it claims no namespace,
    so counting it would report a dead pin as live protection. `match` is None
    when the line predates the field, in which case `keys` is used.

    `boot` defaults to False and is NOT back-compat-patched: a line emitted
    before the field existed means the probe ran on something that cannot see
    Task Scheduler, and reporting "armed" there would be a guess. The health
    row treats it as "not crash-safe", which is the honest direction.
    """
    state = {"keys": 0, "match": None, "effective": False, "boot": False,
             "servers": "", "ok": False}
    line = ""
    for ln in str(out or "").splitlines():
        if "DNS_GUARD_STATE:" in ln:
            line = ln.split("DNS_GUARD_STATE:", 1)[1].strip()
            break
    if not line:
        return state
    # ',' - see the FIELD SEPARATOR note on detect_script(). A ';' here
    # truncated every multi-resolver `servers` value to its first entry.
    for part in line.split(","):
        key, _, val = part.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key == "keys":
            try:
                state["keys"] = int(val)
            except ValueError:
                state["keys"] = 0
        elif key == "match":
            try:
                state["match"] = int(val)
            except ValueError:
                state["match"] = 0
        elif key == "effective":
            state["effective"] = val.lower() == "true"
        elif key == "boot":
            state["boot"] = val.lower() == "true"
        elif key == "servers":
            state["servers"] = val
    ours = state["keys"] if state["match"] is None else state["match"]
    state["ok"] = bool(ours and state["effective"])
    return state


# ── Install record (crash safety) ───────────────────────────────────────────

def save_state(resolvers, exempt=(), path: Optional[str] = None,
               owner_pid: Optional[int] = None,
               boot_armed: bool = False) -> bool:
    """Record what was installed, so ANY later process can remove it."""
    target = path or state_path()
    owner = int(owner_pid if owner_pid is not None else os.getpid())
    # The creation time of the OWNING process, so a later reader can tell
    # "the installer is still running" from "an unrelated process inherited
    # its pid after a reboot". None when it cannot be read; readers treat
    # that as unprovable and fall back to liveness alone.
    owner_started = _process_start_time(owner)
    payload = {
        "version": STATE_VERSION,
        "installed": True,
        "resolvers": [str(s) for s in (resolvers or [])],
        "exempt": [str(n) for n in (exempt or [])],
        "keys": [MATCH_KEY] + ([EXEMPT_LOCAL_KEY] if exempt else []),
        "since": time.time(),
        "owner_pid": owner,
        "owner_started": owner_started,
        # Whether the one-shot startup task is registered. Recorded so the
        # diagnostics can say WHY a rule would survive a crash rather than
        # leaving the operator to guess; a v1 record simply lacks the key and
        # load_state() reports False for it.
        "boot_armed": bool(boot_armed),
    }
    try:
        # ATOMIC. open(target, "w") truncates to zero before the first write
        # reaches the file, and this record has FOUR independent readers (the
        # helper's cleanup, startup recovery, the detached watchdog and the
        # dashboard's own sweeps). A reader landing in that window got "",
        # json.load raised, load_state returned None, and it concluded "no
        # guard installed" and skipped the removal - while a live catch-all
        # pin remained. Write to a temp file in the same directory and
        # os.replace() (atomic on Windows for same-volume paths).
        tmp = f"{target}.{os.getpid()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target)
        finally:
            try:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            except OSError:
                pass
        return True
    except Exception:
        return False


def load_state(path: Optional[str] = None) -> Optional[dict]:
    """The install record, or None (no guard installed / unreadable).

    `boot_armed` is NORMALISED to a bool. A record written before 1.0.51 has
    no such key, and a caller asking "would this rule survive a crash?" must
    get a definite False rather than a KeyError - the record is also read by
    the boot task's own diagnostics path and by startup recovery."""
    target = path or state_path()
    try:
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("installed"):
        return None
    data["boot_armed"] = bool(data.get("boot_armed"))
    return data


def clear_state(path: Optional[str] = None) -> None:
    """Drop the install record (after a verified removal)."""
    target = path or state_path()
    try:
        os.remove(target)
    except OSError:
        pass


# ── Windows entry points (runner injectable for tests) ──────────────────────

def _default_runner() -> Callable:
    """The real PowerShell runner: routing._ps(script, timeout) -> (ok, out).
    Imported lazily so this module stays importable on a non-Windows box and
    during the frozen exe's early bootstrap."""
    from tuntop.network import routing
    return routing._ps


# ── Boot-time cleanup (the owner that survives a BSOD / power loss) ──────────
#
# The four other owners are all processes. This one is a Task Scheduler entry,
# registered while the rule is live and consumed by the next boot. It is
# registered by install() - which the HELPER calls - rather than by the
# dashboard or the watchdog, so the arming does not depend on the dashboard
# process existing at all.

def arm_boot_cleanup(runner: Optional[Callable] = None,
                     path: Optional[str] = None) -> tuple:
    """Register the one-shot startup task. Returns (ok, message).

    Never raises: a failure here must degrade to the pre-1.0.51 behaviour
    (report the loss loudly, keep the guard) and not abort the install. The
    guard is still worth having without crash safety; a machine with no DNS is
    not."""
    run = runner or _default_runner()
    try:
        _ok, out = run(arm_boot_cleanup_script(path))
    except Exception as e:
        return False, f"boot cleanup task could not be armed: {e}"
    text = str(out or "")
    if "DNS_GUARD_BOOT_ARMED" in text:
        return True, "boot cleanup task armed"
    reason = (text.split("DNS_GUARD_BOOT_FAIL:", 1)[1].strip()
              if "DNS_GUARD_BOOT_FAIL:" in text
              else (text.strip() or "no output"))
    return False, f"boot cleanup task could not be armed: {reason}"


def disarm_boot_cleanup(runner: Optional[Callable] = None) -> tuple:
    """Unregister the one-shot startup task. Returns (ok, message).

    Called ONLY after a confirmed rule removal - see the asymmetry note on
    disarm_boot_cleanup_script(). An absent task is success."""
    run = runner or _default_runner()
    try:
        _ok, out = run(disarm_boot_cleanup_script())
    except Exception as e:
        return False, f"boot cleanup task could not be disarmed: {e}"
    text = str(out or "")
    if "DNS_GUARD_BOOT_DISARMED" in text:
        return True, "boot cleanup task disarmed"
    reason = (text.split("DNS_GUARD_BOOT_DISARM_FAIL:", 1)[1].strip()
              if "DNS_GUARD_BOOT_DISARM_FAIL:" in text
              else (text.strip() or "no output"))
    return False, f"boot cleanup task could not be disarmed: {reason}"


def install(resolvers, exempt=(), runner: Optional[Callable] = None,
            path: Optional[str] = None) -> tuple:
    """Install/refresh the guard. Returns (ok, message).

    An empty `resolvers` installs nothing and REMOVES any existing guard: a
    pin with no servers would break resolution without protecting it.

    The boot cleanup task is armed FIRST, before a single NRPT value is
    written, so there is no window in which a live catch-all rule has nothing
    registered to remove it after a crash. The inverse asymmetry is
    deliberate: an install FAILURE never disarms, because a partially refreshed
    rule (see install_script - values are written in place) may still be live,
    and a rule without a task is the unsafe direction. A task without a rule is
    harmless: it runs once at the next boot, finds nothing and deletes itself.
    """
    resolvers = [str(s).strip() for s in (resolvers or []) if str(s).strip()]
    if not resolvers:
        return ensure_removed(runner=runner, path=path)
    run = runner or _default_runner()
    armed, arm_msg = arm_boot_cleanup(runner=run, path=path)
    try:
        _ok, out = run(install_script(resolvers, exempt))
    except Exception as e:
        return False, f"guard install failed: {e}"
    text = str(out or "")
    if "DNS_GUARD_OK" not in text:
        reason = (text.split("DNS_GUARD_FAIL:", 1)[1].strip()
                  if "DNS_GUARD_FAIL:" in text else (text.strip() or "no output"))
        return False, f"guard install failed: {reason}"
    # Collect EVERY loss before reporting, not just the first. An unwritable
    # record and an unarmed task are independent, and a caller that only hears
    # about the record has no idea the rule is also not crash-safe - which is
    # the one fact that decides whether the next power cut costs them a reboot.
    warnings = []
    if not save_state(resolvers, exempt, path=path, boot_armed=armed):
        # The rule IS live, so this is still a success - but say plainly that
        # no crash-safety record exists, because that record is what lets the
        # next launch/cleanup owner find the rule without probing.
        warnings.append("no install record could be written - a hard kill now "
                        "leaves the rule behind with no file to recover it "
                        "from")
    if not armed:
        # A failed arm is NOT a failed install - the guard is still worth
        # having and refusing to bring the tunnel up would be worse than the
        # leak - but the loss of crash safety is exactly the case a silent
        # success would hide.
        warnings.append(f"{arm_msg}. The rule is live but NOT crash-safe: a "
                        "hard kill, BSOD or power loss would leave this machine "
                        "without DNS until TunTop is launched again. Run "
                        "--remove-dns-guard to clear it by hand")
    msg = f"pinned to {', '.join(resolvers)}"
    if not warnings:
        # Named explicitly, because "the machine has no DNS until you reboot"
        # is not something the operator should have to know to look for.
        return True, msg + " (crash-safe: a one-shot startup task will remove it)"
    return True, f"{msg} - WARNING: " + "; ".join(warnings)


def uninstall(runner: Optional[Callable] = None,
              path: Optional[str] = None) -> tuple:
    """Remove every TunTop NRPT rule plus the install record. Idempotent.

    The runner's own success flag is honoured. A PowerShell run that failed
    (not found, timed out, non-zero exit) removed NOTHING, so it must be
    reported as a failure AND the install record must survive - clearing it
    there would leave an orphaned catch-all pin with no file for the next
    launch's recovery to find. "Nothing to remove" is only a success once the
    command has actually run and reported back.
    """
    run = runner or _default_runner()
    try:
        ran_ok, out = run(uninstall_script())
    except Exception as e:
        return False, f"guard removal failed: {e}"
    text = str(out or "")
    if not ran_ok:
        # The command never completed: treat it exactly like the script's own
        # failure marker - keep the record so a later owner can retry.
        return False, ("guard removal failed: "
                       + (text.strip() or "no output"))
    if "DNS_GUARD_UNINSTALL_FAIL:" in text:
        return False, ("guard removal failed: "
                       + text.split("DNS_GUARD_UNINSTALL_FAIL:", 1)[1].strip())
    if "DNS_GUARD_REMOVED" in text:
        clear_state(path=path)
        # ONLY here, and only now. The boot task is the removal's safety net,
        # so it must outlive every failed attempt (the rule is still live) and
        # must not outlive a confirmed one. A disarm failure does not make the
        # removal a failure - the task self-deletes at the next boot having
        # found nothing - but it is reported, never swallowed.
        _disarmed, disarm_msg = disarm_boot_cleanup(runner=run)
        if _disarmed:
            return True, "removed (boot cleanup task disarmed)"
        return True, ("removed, but the boot cleanup task could not be "
                      f"unregistered ({disarm_msg}). It is harmless: it runs "
                      "once at the next boot, finds no rule and deletes "
                      "itself. Remove it with: Unregister-ScheduledTask "
                      f"-TaskName {BOOT_TASK_NAME}")
    # The command ran and reported NEITHER marker. That is not proof that
    # nothing of ours was found: uninstall_script() sweeps with
    # -ErrorAction SilentlyContinue, so on a non-elevated process (or an
    # ACL-denied DnsPolicyConfig key) Get-ChildItem returns nothing, the
    # count is 0, and it prints DNS_GUARD_REMOVED even though the TunTop-*
    # keys are still there. The script now distinguishes that case with its
    # own marker; if we still see no marker at all, something else went
    # wrong (a parse error, truncated stdout) and the safe answer is to
    # report failure and KEEP the record, so the next launch's recovery
    # still knows a rule may be alive. install_script() fails closed; the
    # uninstall must too - a rule that outlives the tunnel pins every
    # process on the machine to resolvers that are now dead.
    return False, ("guard removal gave no verdict (the NRPT store could not "
                   "be read, or the sweep did not run) - treating it as a "
                   "failure so the install record is kept and the next "
                   "TunTop start retries. Re-run as Administrator if this "
                   "persists.")


def detect(runner: Optional[Callable] = None) -> tuple:
    """(probe_ok, state) - `state` is parse_detect()'s dict (plus "error")."""
    run = runner or _default_runner()
    try:
        ok, out = run(detect_script())
    except Exception as e:
        return False, {"keys": 0, "effective": False, "servers": "",
                       "ok": False, "error": str(e)}
    state = parse_detect(out)
    state["error"] = "" if ok else str(out or "")[:200]
    return bool(ok), state


def _process_start_time(pid: int) -> Optional[int]:
    """`pid`'s creation time in whole seconds since the epoch, or None.

    Thin alias onto the shared leaf (tuntop/procidentity.py) so the DNS guard
    and the crash-marker code cannot drift into two different notions of
    "same process". See that module for why a bare PID cannot answer that.
    """
    return procidentity.process_start_time(pid)


def _pid_alive(pid: int) -> bool:
    """True when `pid` is a RUNNING process. Unknown-means-dead on purpose:
    a false "dead" only means the rule gets removed (what every recovery path
    wants), while a false "alive" would strand a catch-all pin on a machine
    that no longer has a tunnel.

    Every uncertain branch returns False, including an access-denied
    OpenProcess and a failed GetExitCodeProcess. The previous version
    returned True for both - the one direction this docstring calls
    dangerous, and the direction that made `ensure_removed` answer "left in
    place" for an owner that was already gone. The trade is deliberate: a
    second instance that cannot inspect the owner clears the rule (a leak the
    tunnel's own health rows will show) rather than stranding a machine-wide
    DNS pin to dead resolvers (no resolution at all).
    """
    return procidentity.process_alive(pid)


def record_owner_alive(record: Optional[dict]) -> bool:
    """True when the install record names a live process that is NOT us.

    That is the multi-instance hazard: a second TunTop's teardown must not
    delete the catch-all pin the first one is still relying on, or the machine
    silently goes back to leaking (with every health row still green).

    The pid alone cannot answer that question - it is a recycled slot - so a
    record that carries `owner_started` is only honoured when the LIVE
    process is demonstrably the recorded one. A mismatch (or an unreadable
    creation time) means the pid now belongs to somebody else, and this
    returns False so the leftover is cleared instead of protected forever.
    Records written before start times were tracked lack the key and fall
    back to liveness alone, as they always did.
    """
    if not isinstance(record, dict):
        return False
    pid = record.get("owner_pid")
    if pid is None:
        return False            # a record from before ownership was tracked
    try:
        if int(pid) == os.getpid():
            return False
    except (TypeError, ValueError):
        return False
    if record.get("owner_started") is not None and \
            not procidentity.same_process(pid, record.get("owner_started")):
        return False
    return _pid_alive(pid)


def ensure_removed(runner: Optional[Callable] = None,
                   path: Optional[str] = None,
                   force: bool = False) -> tuple:
    """Remove the guard only when there is something to remove (a record or a
    live rule), so a run with the guard disabled does not shell out for
    nothing.

    `force` is for the recovery owners (startup recovery, the cleanup
    watchdog): they run when no live instance should own the rule, and must be
    able to clear a leftover from a crash. Without `force` a rule recorded by
    another RUNNING process is left alone - see record_owner_alive()."""
    record = load_state(path=path)
    if not force and record_owner_alive(record):
        return True, (f"left in place: owned by TunTop pid "
                      f"{record.get('owner_pid')}, which is still running")
    if record is None:
        ok, state = detect(runner=runner)
        if ok and not state.get("keys"):
            return True, "not installed"
    return uninstall(runner=runner, path=path)


def ensure_installed(dns4, dns6, exempt=(), runner: Optional[Callable] = None,
                     path: Optional[str] = None) -> tuple:
    """One-call convenience for the tunnel bring-up path: pick the resolvers,
    install, and report what happened. Returns (ok, message)."""
    resolvers = guard_resolvers(dns4, dns6)
    if not resolvers:
        return ensure_removed(runner=runner, path=path)
    return install(resolvers, exempt, runner=runner, path=path)


# ── "Is anything else able to answer?" - the check the leak test was blind to ──

#: Fallback tunnel aliases for foreign_resolvers_script(). The module stays a
#: dependency-free leaf, so the caller passes tuntop.config.defaults
#: TUNNEL_ALIASES in production; this matches it so a direct caller is still
#: correct.
DEFAULT_TUNNEL_ALIASES = ("wintun", "wintun2")


def foreign_resolvers_script(aliases=DEFAULT_TUNNEL_ALIASES) -> str:
    """PowerShell listing NON-tunnel adapters that still publish resolvers.

    Those are the servers Windows may query in parallel with the tunnel's
    (Smart Multi-Homed Name Resolution): the egress probes in the leak test
    cannot see that path at all, because they only talk to the resolvers
    TunTop knows about. Prints one `alias=ip,ip` token per adapter.

    ONLY adapters whose status is Up are considered. Get-DnsClientServerAddress
    also reports DISCONNECTED ones (an unplugged Ethernet port keeps a stale
    static resolver forever), and Windows never fans a query out to an adapter
    that is not connected - counting those would invent a leak on a machine that
    is not leaking. A Get-NetAdapter failure therefore yields an empty list,
    which the caller treats as "nothing to see" rather than a leak verdict.

    Loopback entries are dropped per address rather than per adapter, so an
    adapter publishing 127.0.0.1 *and* a real resolver is still reported.
    BOTH loopback families are filtered: with only '127.0.0.1' excluded, an
    adapter whose sole resolver was ::1 was still reported, which made the
    leak check declare "DNS is leaking" on a machine that is not."""
    tun = [str(a).replace("'", "''") for a in (aliases or ()) if str(a).strip()]
    if not tun:
        tun = ["wintun", "wintun2"]
    return ("$up = @(Get-NetAdapter -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Status -eq 'Up' } | "
            "ForEach-Object { $_.Name }); "
            "$t = @(" + ",".join("'" + a + "'" for a in tun) + "); "
            "$loops = @('127.0.0.1', '::1'); "
            "Get-DnsClientServerAddress -ErrorAction SilentlyContinue | "
            "Where-Object { $up -contains $_.InterfaceAlias -and "
            "$t -notcontains $_.InterfaceAlias } | "
            "ForEach-Object { $a = @($_.ServerAddresses | "
            "Where-Object { $_ -and $loops -notcontains $_ }); "
            "if ($a.Count -gt 0) { $_.InterfaceAlias + '=' + ($a -join ',') } }")


def parse_foreign(out) -> list:
    """Parse foreign_resolvers_script()'s output into ["Wi-Fi=192.168.1.1"]."""
    items = []
    for ln in str(out or "").splitlines():
        s = ln.strip()
        if not s or s == "No result" or "=" not in s or s.startswith("#<"):
            continue
        if s not in items:
            items.append(s)
    return items


def foreign_resolvers(runner: Optional[Callable] = None,
                      aliases=DEFAULT_TUNNEL_ALIASES) -> list:
    """Best-effort list of non-tunnel adapters with resolvers (never raises;
    an unreadable probe returns [] so a leak verdict is never invented)."""
    run = runner or _default_runner()
    try:
        ok, out = run(foreign_resolvers_script(aliases))
    except Exception:
        return []
    if not ok:
        return []
    return parse_foreign(out)


def guard_in_force(runner: Optional[Callable] = None) -> bool:
    """True when WINDOWS' own effective NRPT policy claims the root namespace
    - i.e. some catch-all pin (ours or a managed one) is in force, so the DNS
    client cannot fan a query out to every adapter's resolver. Best-effort."""
    try:
        ok, state = detect(runner=runner)
    except Exception:
        return False
    return bool(ok and state.get("effective"))

