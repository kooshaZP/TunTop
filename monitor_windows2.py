"""Elevated diagnostic: find the owner of the second black 'TunTop' window.

Mimics the user's double-click launch (the exe gets its OWN console via
CREATE_NEW_CONSOLE, stdio piped so we can log what it prints), then:
  * polls the visible-window list every 0.3s for 40s,
  * logs every NEW window (hwnd/class/title/owning pid) with a timestamp,
  * sends [S] at t=12s (exercises the helper-spawn moment; --port 59777 is
    deliberately dead so no routes are touched) and [T] at t=30s,
  * resolves every new window's pid -> image, command line, parent pid,
    so the owner of the black window is unambiguous,
  * kills the exe tree at the end.

Output: monitor_out.log (primary sink; stdout is best-effort).
"""
import ctypes
import ctypes.wintypes as wt
import subprocess
import threading
import time

LOG = r"C:\Users\KOOSHAZP\Desktop\releases\monitor_out.log"
EXE = r"C:\Users\KOOSHAZP\Desktop\releases\dist\TunTop.exe"
WATCH = 40
PRESS_S = 12
PRESS_T = 30

_logf = open(LOG, "w", encoding="utf-8", buffering=1)


def log(msg):
    _logf.write(msg + "\n")
    try:
        print(msg)
    except Exception:
        pass


EnumWindows = ctypes.windll.user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
GetWindowTextW = ctypes.windll.user32.GetWindowTextW
GetClassNameW = ctypes.windll.user32.GetClassNameW
IsWindowVisible = ctypes.windll.user32.IsWindowVisible
GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId
SetForegroundWindow = ctypes.windll.user32.SetForegroundWindow
keybd_event = ctypes.windll.user32.keybd_event


def enum_windows():
    wins = []
    def cb(hwnd, lp):
        if IsWindowVisible(hwnd):
            t = ctypes.create_unicode_buffer(256)
            GetWindowTextW(hwnd, t, 256)
            c = ctypes.create_unicode_buffer(256)
            GetClassNameW(hwnd, c, 256)
            pid = wt.DWORD()
            GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            wins.append((int(hwnd), t.value, c.value, pid.value))
        return True
    EnumWindows(EnumWindowsProc(cb), 0)
    return wins


_cache = {}


def resolve_pids(pids):
    todo = [p for p in pids if p and p not in _cache]
    if not todo:
        return
    filt = " OR ".join(f"ProcessId={p}" for p in todo)
    cmd = ["powershell", "-NoProfile", "-Command",
           "Get-CimInstance Win32_Process -Filter \"" + filt + "\" | "
           "ForEach-Object { \"$($_.ProcessId)|$($_.ParentProcessId)"
           "|$($_.Name)|$($_.CommandLine)\" }"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                             creationflags=subprocess.CREATE_NO_WINDOW).stdout
    except Exception as e:
        log(f"    resolve failed: {e}")
        return
    for line in (out or "").splitlines():
        parts = line.split("|", 3)
        if len(parts) == 4 and parts[0].isdigit():
            _cache[int(parts[0])] = (int(parts[1]), parts[2], parts[3])


def report_pids(pids, label):
    resolve_pids(pids)
    for p in sorted(pids):
        info = _cache.get(p)
        if info:
            ppid, name, cmdline = info
            log(f"    PID {p} = {name}  ppid={ppid}"
                f" ({_cache.get(ppid, ('?', '?', '?'))[1]})")
            log(f"        cmd: {cmdline}")
        else:
            log(f"    PID {p} = (gone or unresolved) [{label}]")


t0 = None


def press(hint, vk):
    log(f">>> sending key [{hint}] ...")
    keybd_event(vk, 0, 0, 0)
def main():
    global t0
    elev = ctypes.windll.shell32.IsUserAnAdmin()
    ver = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         f"(Get-Item '{EXE}').VersionInfo.ProductVersion"],
        capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW).stdout.strip()
    log(f"monitor elevated={bool(elev)}  exe ProductVersion={ver!r}")

    before = {w[0] for w in enum_windows()}
    log(f"BEFORE: {len(before)} visible windows")

    p = subprocess.Popen(
        [EXE, "--server", "1.1.1.1", "--port", "59777", "--no-update-check"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, text=True, encoding="utf-8",
        errors="replace",
        creationflags=subprocess.CREATE_NEW_CONSOLE)
    log(f"exe pid={p.pid} launched (own console)")

    def reader():
        try:
            for line in p.stdout:
                el = (time.time() - t0) if t0 else 0.0
                log(f"   [exe {el:6.1f}s] {line.rstrip()}")
        except Exception:
            pass
    threading.Thread(target=reader, daemon=True).start()

    t0 = time.time()
    new = {}          # hwnd -> (t, pid, cls, title)
    new_pids = set()
    exe_console = None
    pressed_s = False
    pressed_t = False
    last_report = 0.0

    while time.time() - t0 < WATCH:
        now = time.time() - t0
        for hwnd, title, cls, pid in enum_windows():
            if hwnd in before or hwnd in new:
                continue
            new[hwnd] = (now, pid, cls, title)
            new_pids.add(pid)
            log(f"[{now:6.1f}s] NEW window hwnd={hwnd:#x} pid={pid} "
                f"class={cls!r} title={title!r}")
            if cls == "ConsoleWindowClass" and exe_console is None:
                exe_console = hwnd
        if now - last_report >= 5.0 and new_pids:
            last_report = now
            log(f"--- window owners @ {now:.1f}s ---")
            report_pids(set(new_pids), "window owner")
        if not pressed_s and now >= PRESS_S:
            pressed_s = True
            if exe_console:
                SetForegroundWindow(exe_console)
                time.sleep(0.3)
            press("S", 0x53)
        if not pressed_t and now >= PRESS_T:
            pressed_t = True
            if exe_console:
                SetForegroundWindow(exe_console)
                time.sleep(0.3)
            press("T", 0x54)
        time.sleep(0.3)

    log(f"exe poll rc={p.poll()}")
    log("--- FINAL window-owner resolution ---")
    report_pids(set(new_pids), "final")
    subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"],
                   capture_output=True, text=True,
                   creationflags=subprocess.CREATE_NO_WINDOW)
    log("killed exe tree; monitor done")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        log("MONITOR CRASH:\n" + traceback.format_exc())
    time.sleep(0.08)
    keybd_event(vk, 0, 2, 0)  # KEYEVENTF_KEYUP
