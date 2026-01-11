import os
import logging
import subprocess
import ctypes
import tkinter as tk
from tkinter import messagebox
from threading import Thread
import psutil
import win32api, win32con, win32process
from multiprocessing import Process

# === Lowercase Whitelist ===
WHITELIST = {
    'system idle process', 'system', 'registry', 'memcompression',
    'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'taskhostw.exe',
    'sihost.exe', 'explorer.exe', 'dwm.exe', 'audiodg.exe',
    'ctfmon.exe', 'conhost.exe', 'dllhost.exe', 'spoolsv.exe',
    'textinputhost.exe', 'startmenuexperiencehost.exe',
    'applicationframehost.exe', 'systemsettings.exe',
    'wmiprvse.exe', 'wmiadap.exe', 'wudfhost.exe',
    'useroobebroker.exe', 'aggregatorhost.exe',
    'runtimebroker.exe', 'fontdrvhost.exe',
    'msmpeng.exe', 'mpdefendercoreservice.exe', 'nissrv.exe',
    'securityhealthservice.exe', 'securityhealthsystray.exe',
    'smartscreen.exe',
    'searchindexer.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',
    'python.exe', 'pythonw.exe', 'code.exe', 'notepad.exe'
}

CRITICAL_PROCESSES = {
    'system', 'winlogon.exe', 'lsass.exe', 'csrss.exe', 'smss.exe', 'services.exe'
}

# === Process Suspension ===
def suspend_non_whitelisted():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_name = proc.info['name'].lower()
            if proc_name in WHITELIST or proc_name in CRITICAL_PROCESSES:
                continue

            logging.warning(f"[SUSPEND] Suspending: {proc_name}")
            p = psutil.Process(proc.pid)
            try:
                for thread in p.threads():
                    hThread = win32api.OpenThread(win32con.THREAD_ALL_ACCESS, False, thread.id)
                    ctypes.windll.kernel32.SuspendThread(hThread)
                    ctypes.windll.kernel32.CloseHandle(hThread)
            except Exception as e:
                logging.error(f"[THREAD ERROR] {proc_name}: {e}")

        except Exception as e:
            logging.error(f"[PROCESS ERROR] Failed to suspend: {e}")

# === Lockout GUI ===
def show_lock_gui():
    def attempt_unlock():
        if password_entry.get() == "admin123":
            root.destroy()
            unlock_system()
        else:
            messagebox.showerror("Access Denied", "Incorrect password.")

    root = tk.Tk()
    root.title("System Locked")
    root.attributes("-fullscreen", True)
    root.configure(bg="black")

    tk.Label(root, text="SYSTEM LOCKDOWN ACTIVE", fg="red", bg="black", font=("Arial", 28)).pack(pady=60)
    tk.Label(root, text="All network interfaces are disabled.", fg="white", bg="black", font=("Arial", 16)).pack(pady=5)
    tk.Label(root, text="Enter password to lift lockdown:", fg="white", bg="black", font=("Arial", 14)).pack(pady=20)
    password_entry = tk.Entry(root, show="*", width=30)
    password_entry.pack(pady=5)
    tk.Button(root, text="Unlock", command=attempt_unlock, width=20, height=2, bg="gray").pack(pady=20)
    tk.Button(root, text="Reboot to Safe Mode", command=reboot_to_safe_mode, width=20, height=2, bg="darkred", fg="white").pack(pady=10)

    root.mainloop()

# === Lockout System ===
def lockout_system():
    try:
        subprocess.run("netsh interface set interface name=\"Ethernet0\" admin=disabled", shell=True, check=True)
        with open(r"C:\\RM\\LOCKDOWN.ACTIVE", "w") as f:
            f.write("System lockdown engaged due to ransomware threat.")

        logging.info("[LOCKDOWN] Network disabled and lockdown file created.")

        Process(target=show_lock_gui).start()
        Thread(target=suspend_non_whitelisted, daemon=True).start()

    except Exception as e:
        logging.error(f"[LOCKDOWN ERROR] {e}")

# === Unlock System ===
def unlock_system():
    try:
        subprocess.run("netsh interface set interface name=\"Ethernet0\" admin=enabled", shell=True, check=True)
        if os.path.exists(r"C:\\RM\\LOCKDOWN.ACTIVE"):
            os.remove(r"C:\\RM\\LOCKDOWN.ACTIVE")

        ctypes.windll.user32.MessageBoxW(0, "Lockdown lifted. Network re-enabled.", "Unlocked", 0x40)
        logging.info("[UNLOCK] Lockdown lifted and network re-enabled.")
    except Exception as e:
        logging.error(f"[UNLOCK ERROR] Failed to restore system: {e}")

# === Re-enable Network (Manual) ===
def manual_enable_network():
    try:
        subprocess.run("netsh interface set interface name=\"Ethernet0\" admin=enabled", shell=True, check=True)
        ctypes.windll.user32.MessageBoxW(0, "Network manually re-enabled.", "Network Restored", 0x40)
        logging.info("[MANUAL] Network re-enabled.")
    except Exception as e:
        logging.error(f"[MANUAL ERROR] Failed to re-enable network: {e}")

# === Safe Mode Boot ===
def reboot_to_safe_mode():
    try:
        subprocess.run("bcdedit /set {current} safeboot minimal", shell=True)
        ctypes.windll.user32.MessageBoxW(0, "System will reboot into Safe Mode.", "Rebooting", 0x40)
        subprocess.run("shutdown /r /t 5", shell=True)
    except Exception as e:
        logging.error(f"[SAFE MODE ERROR] {e}")

# === Disable Safe Mode ===
def disable_safe_mode():
    try:
        subprocess.run("bcdedit /deletevalue {current} safeboot", shell=True, check=True)
        logging.info("[INFO] Safe Mode flag removed.")
    except subprocess.CalledProcessError as e:
        logging.error(f"[DISABLE SAFE MODE ERROR] {e}")

# === Monitor Lockdown Flag ===
def monitor_lockdown_flag():
    if not os.path.exists(r"C:\\RM\\LOCKDOWN.ACTIVE"):
        ctypes.windll.user32.MessageBoxW(0, "WARNING: Lockdown file removed! Re-engaging lockdown.", "Lockdown Persistence", 0x30)
        lockout_system()
