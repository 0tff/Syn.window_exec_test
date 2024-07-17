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

def show_error_message(message: str, style: int = 0):
    return user32.MessageBoxW(0, message, "WindowsExecutor", style | 0x10 | 0x1000 | 0x10000 | 0x40000 | 0x200000)

def clear_pe_header():
    base_address = ctypes.c_void_p(win32api.GetModuleHandle(None))
    old_protection = wintypes.DWORD()
    kernel32.VirtualProtect(base_address, 4096, 0x04, ctypes.byref(old_protection))
    ctypes.memset(base_address, 0, 4096)
    kernel32.VirtualProtect(base_address, 4096, old_protection.value, ctypes.byref(old_protection))

def conceal_threads():
    current_process_id = kernel32.GetCurrentProcessId()
    process_handle = kernel32.OpenProcess(0x1F0FFF, False, current_process_id)
    if process_handle:
        current_thread_id = kernel32.GetCurrentThreadId()
        thread_handle = kernel32.OpenThread(0x1F03FF, False, current_thread_id)
        if thread_handle:
            ntdll.NtSetInformationThread(
                thread_handle, 0x11, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int)
            )
            kernel32.CloseHandle(thread_handle)
        kernel32.CloseHandle(process_handle)

def security_monitor():
    security = security_module.Security(
        enable_anti_debugger=True,
        detect_virtual_machine=True,
        detect_sandbox=True
    )
    clear_pe_header()
    conceal_threads()
    while True:
        time.sleep(0.05)
        if security.is_debugged():
            main_interface.hide()
            response = show_error_message("Debugging detected! Terminating process.", 0x01)
            if response == 1:
                security.terminate_process()
            elif response == 2:
                show_error_message("Terminating process anyway.")
                security.crash_system()

if __name__ == "__main__":
    hwnd = kernel32.GetConsoleWindow()
    user32.ShowWindow(hwnd, 0)
    security_thread = threading.Thread(target=security_monitor, daemon=True)
    security_thread.start()
    bootstrapper = Bootstrapper()
    startup_message = bootstrapper.run()
    print(startup_message)
    main_interface = WindowsExecutorInterface()
    main_interface.start()
