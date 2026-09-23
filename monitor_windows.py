import ctypes
import ctypes.wintypes as wtypes
import subprocess
import time
import sys
import codecs
sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)

EnumWindows = ctypes.windll.user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(wtypes.BOOL, wtypes.HWND, wtypes.LPARAM)
GetWindowTextW = ctypes.windll.user32.GetWindowTextW
GetClassNameW = ctypes.windll.user32.GetClassNameW
IsWindowVisible = ctypes.windll.user32.IsWindowVisible
GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId

def enum_windows():
    windows = []
    def enum_proc(hwnd, lParam):
        if IsWindowVisible(hwnd):
            title = ctypes.create_unicode_buffer(256)
            GetWindowTextW(hwnd, title, 256)
            if title.value:
                class_name = ctypes.create_unicode_buffer(256)
                GetClassNameW(hwnd, class_name, 256)
                pid = wtypes.DWORD()
                GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                windows.append((int(hwnd), title.value, class_name.value, pid.value))
        return True
    EnumWindows(EnumWindowsProc(enum_proc), 0)
    return windows

before = enum_windows()
# Filter for console windows
console_before = [w for w in before if 'ConsoleWindowClass' in w[2] or 'TunTop' in w[1]]
print(f"BEFORE: {len(before)} visible windows, {len(console_before)} console/TunTop windows")

# Launch the exe WITHOUT CREATE_NO_WINDOW (simulating double-click from Explorer)
# Use STARTF_USESHOWWINDOW + SW_HIDE for the parent only
p = subprocess.Popen(
    [r"C:\Users\KOOSHAZP\Desktop\releases\dist\TunTop.exe", "--server", "1.1.1.1", "--no-update-check"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
)

time.sleep(5)

after = enum_windows()
console_after = [w for w in after if 'ConsoleWindowClass' in w[2] or 'TunTop' in w[1]]
print(f"\nAFTER: {len(after)} visible windows, {len(console_after)} console/TunTop windows")

before_hwnds = set(w[0] for w in before)
after_hwnds = set(w[0] for w in after)
new_windows = after_hwnds - before_hwnds
console_windows = [w for w in after if w[0] in new_windows and ('ConsoleWindowClass' in w[2] or 'TunTop' in w[1])]
print(f"\nNEW windows: {len(new_windows)}")
for hwnd in new_windows:
    for w in after:
        if w[0] == hwnd:
            print(f"  [{w[3]}] {w[2]} - '{w[1]}'")

p.terminate()
try:
    p.wait(timeout=5)
except:
    p.kill()
print(f"\nProcess exited with code: {p.returncode}")
