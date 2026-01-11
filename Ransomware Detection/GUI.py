#GUI

import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import ctypes
import csv
from response import lockout_system, reboot_to_safe_mode, disable_safe_mode, manual_enable_network

# === GUI Window ===
window = tk.Tk()
window.title("Anti-Ransomware Control Panel")
window.geometry("500x400")
window.configure(bg="#f2f2f2")

# === Password Field ===
tk.Label(window, text="Admin Password:", bg="#f2f2f2").pack(pady=(10, 0))
password_entry = tk.Entry(window, show="*", width=30)
password_entry.pack(pady=(0, 10))

# === Functions ===
def trigger_lockout():
    lockout_system()
    messagebox.showinfo("Lockout", "System lockdown initiated.")

def trigger_safe_mode():
    entered_pw = password_entry.get()
    if entered_pw == "admin123":
        reboot_to_safe_mode(password=entered_pw)
    else:
        messagebox.showerror("Access Denied", "Incorrect password.")

def reset_safe_mode():
    try:
        disable_safe_mode()
        messagebox.showinfo("Reset", "Safe Mode boot flag removed. Please reboot manually.")
    except Exception as e:
        messagebox.showerror("Error", f"Reset failed: {e}")
tk.Button(window, text="Re-enable Network", command=lambda: manual_enable_network(), bg="#00cc99", fg="white", width=30).pack(pady=5)

def open_log():
    log_path = r"C:\\RM\\filesystem_log.csv"
    if os.path.exists(log_path):
        os.startfile(log_path)
    else:
        messagebox.showwarning("Log Missing", "Log file not found.")

def show_recent_threats():
    log_path = r"C:\\RM\\filesystem_log.csv"
    output_text.delete("1.0", tk.END)
    if os.path.exists(log_path):
        try:
            with open(log_path, "r") as f:
                reader = list(csv.reader(f))
                recent_entries = reader[-5:] if len(reader) >= 5 else reader
                for row in recent_entries:
                    output_text.insert(tk.END, ", ".join(row) + "\n")
        except Exception as e:
            output_text.insert(tk.END, f"Failed to load log: {e}\n")
    else:
        output_text.insert(tk.END, "Log file not found.\n")

# === Buttons ===
tk.Button(window, text="Lockout System", command=trigger_lockout, bg="#ff4d4d", fg="white", width=30).pack(pady=5)
tk.Button(window, text="Reboot to Safe Mode", command=trigger_safe_mode, bg="#4da6ff", fg="white", width=30).pack(pady=5)
tk.Button(window, text="Reset Safe Mode Flag", command=reset_safe_mode, bg="#99cc00", fg="black", width=30).pack(pady=5)
tk.Button(window, text="Open Full Threat Log", command=open_log, bg="#cccccc", fg="black", width=30).pack(pady=5)
tk.Button(window, text="Show Recent Threats Below", command=show_recent_threats, bg="#cccccc", fg="black", width=30).pack(pady=5)

# === Output Box ===
output_text = tk.Text(window, height=8, width=58, wrap=tk.WORD)
output_text.pack(pady=(10, 5))

# === Exit Button ===
tk.Button(window, text="Exit", command=window.quit, width=30).pack(pady=5)

# === Main Loop ===
window.mainloop()
