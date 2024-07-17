import time
import threading
import ctypes
import win32api
from ctypes import windll, wintypes

from ui.interface import WindowsExecutorInterface
from misc.bootstrapper import Bootstrapper

kernel32 = windll.kernel32
ntdll = windll.ntdll
user32 = windll.user32

def display_alert(message: str, style: int = 0):
    return user32.MessageBoxW(0, message, "WindowsExecutor", style | 0x10 | 0x1000)

def wipe_memory():
    address = ctypes.c_void_p(win32api.GetModuleHandle(None))
    old_protection = wintypes.DWORD()
    kernel32.VirtualProtect(address, 4096, 0x04, ctypes.byref(old_protection))
    ctypes.memset(address, 0, 4096)
    kernel32.VirtualProtect(address, 4096, old_protection.value, ctypes.byref(old_protection))

def obfuscate_threads():
    pid = kernel32.GetCurrentProcessId()
    process_handle = kernel32.OpenProcess(0x1F0FFF, False, pid)
    if process_handle:
        tid = kernel32.GetCurrentThreadId()
        thread_handle = kernel32.OpenThread(0x1F03FF, False, tid)
        if thread_handle:
            ntdll.NtSetInformationThread(thread_handle, 0x11, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int))
            kernel32.CloseHandle(thread_handle)
        kernel32.CloseHandle(process_handle)

def security_thread():
    wipe_memory()
    obfuscate_threads()
    while True:
        time.sleep(0.05)
        if is_debugger_present():
            main_ui.hide()
            response = display_alert("Debugging detected! Terminating process.", 0x01)
            if response == 1:
                terminate_process()
            elif response == 2:
                display_alert("Terminating process anyway.")
                crash_system()

def is_debugger_present():
    return kernel32.IsDebuggerPresent()

def terminate_process():
    kernel32.TerminateProcess(kernel32.GetCurrentProcess(), 1)

def crash_system():
    ctypes.windll.ntdll.RtlAdjustPrivilege(19, True, False, ctypes.byref(wintypes.BOOLEAN()))
    ctypes.windll.ntdll.NtRaiseHardError(0xC000007B, 0, None, None, 6, ctypes.byref(wintypes.DWORD()))

if __name__ == "__main__":
    kernel32.ShowWindow(kernel32.GetConsoleWindow(), 0)
    watchdog = threading.Thread(target=security_thread, daemon=True)
    watchdog.start()
    bootstrap = Bootstrapper()
    print(bootstrap.run())
    main_ui = WindowsExecutorInterface()
    main_ui.start()
