import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
import subprocess
import os
import shutil
import json
import logging
import re

LOG_FILE = r"C:\RM\filesystem_listner_log.txt"  # Path to your filesystem listener log
CACHE_FILE = "recovery_cache.json"  # JSON file to store the cached recovery settings

# --- Utility Functions for Recovery ---
def create_shadow_copy(drive_letter):
    try:
        subprocess.run(f"vssadmin create shadow /for={drive_letter}:", shell=True, check=True)
        messagebox.showinfo("Shadow Copy", f"Shadow copy created for {drive_letter}.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to create shadow copy for {drive_letter}: {e}")

def restore_from_external_backup(external_drive, affected_files):
    try:
        for file in affected_files:
            external_file_path = f"{external_drive}:{file}"
            shutil.copy(external_file_path, file)  # Replace affected files
            messagebox.showinfo("Backup Restore", f"Restored {file} from external drive.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to restore from backup: {e}")

def restore_from_shadow_copy(drive_letter, shadow_copy_id):
    try:
        subprocess.run(f"vssadmin restore shadow {drive_letter}:{shadow_copy_id}", shell=True, check=True)
        messagebox.showinfo("Shadow Copy Restore", f"Restored files from shadow copy {shadow_copy_id}")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to restore from shadow copy: {e}")

def list_shadow_copies():
    try:
        result = subprocess.run("vssadmin list shadows", shell=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to list shadow copies: {e}")
        return ""

def parse_filesystem_log(logfile_path):
    affected_files = []
    try:
        with open(logfile_path, "r") as logfile:
            lines = logfile.readlines()
            for line in lines:
                if "created" in line or "modified" in line or "deleted" in line:
                    match = re.search(r"(C:\\RM\\samples\\.*)", line)
                    if match:
                        file_path = match.group(0)
                        affected_files.append(file_path)
        logging.info(f"[LOG PARSER] Affected files: {affected_files}")
    except Exception as e:
        logging.error(f"[LOG PARSER ERROR] Failed to parse filesystem log: {e}")
    return affected_files

# --- Caching Functions ---
def save_cache(data):
    """Save the selected recovery drive and shadow copies to a cache file (JSON)."""
    try:
        with open(CACHE_FILE, "w") as cache_file:
            json.dump(data, cache_file)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save cache: {e}")

def load_cache():
    """Load the recovery settings (like selected recovery drive and shadow copies) from the cache file."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as cache_file:
                return json.load(cache_file)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load cache: {e}")
    return {}  # Return empty dict if no cache exists

def list_drives():
    drives = []
    for drive_letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if os.path.exists(f"{drive_letter}:\\"):
            drives.append(f"{drive_letter}:\\")
    return drives

# --- RecoveryGUI Class with Setup and Recovery Tabs ---
class RecoveryGUI:
    def __init__(self, after_attack=False):
        self.window = tk.Tk()
        self.window.title("Ransomware Recovery Setup/Restoration")

        self.selected_external_drive = None
        self.selected_drive = None  # For shadow copy selection
        self.remembered_shadow_copies = []

        # Load cached settings (like selected drive, shadow copies, etc.)
        cached_data = load_cache()
        self.selected_external_drive = cached_data.get("selected_external_drive", None)
        self.remembered_shadow_copies = cached_data.get("remembered_shadow_copies", [])

        # --- GUI Layout ---
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(pady=10)

        # --- Setup Tab ---
        self.setup_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.setup_tab, text="Setup")

        self.label = tk.Label(self.setup_tab, text="Setup Process", font=("Arial", 16))
        self.label.pack(pady=10)

        self.select_drive_button = tk.Button(self.setup_tab, text="Select Drive for Shadow Copy", command=self.select_drive)
        self.select_drive_button.pack(pady=5)

        self.select_removable_drive_button = tk.Button(self.setup_tab, text="Select Removable Backup Drive", command=self.select_removable_drive)
        self.select_removable_drive_button.pack(pady=5)

        self.show_shadow_copies_button = tk.Button(self.setup_tab, text="Show Shadow Copies", command=self.show_shadow_copies)
        self.show_shadow_copies_button.pack(pady=5)

        # --- Recovery Tab ---
        self.recovery_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.recovery_tab, text="Recovery")

        self.label_recovery = tk.Label(self.recovery_tab, text="Recovery Process", font=("Arial", 16))
        self.label_recovery.pack(pady=10)

        self.restore_shadow_copy_button = tk.Button(self.recovery_tab, text="Restore from Shadow Copy", command=self.restore_from_shadow_copy)
        self.restore_shadow_copy_button.pack(pady=5)

        self.restore_external_drive_button = tk.Button(self.recovery_tab, text="Restore from External Drive", command=self.restore_from_external_backup)
        self.restore_external_drive_button.pack(pady=5)

        # Recovery log area
        self.log_area_label = tk.Label(self.window, text="Recovery File Contents:", font=("Arial", 12))
        self.log_area_label.pack(pady=10)

        self.log_area = tk.Text(self.window, height=10, width=50)
        self.log_area.pack(pady=10)

        self.window.mainloop()

    def select_drive(self):
        drives = list_drives()
        drive_selection_window = tk.Toplevel(self.window)
        drive_selection_window.title("Select a Drive")
        drive_var = tk.StringVar(drive_selection_window)
        drive_var.set(drives[0])  # Default to the first drive
        drive_menu = ttk.Combobox(drive_selection_window, textvariable=drive_var, values=drives)
        drive_menu.pack(pady=10)

        def on_ok():
            selected_drive = drive_var.get()
            create_shadow_copy(selected_drive)
            self.remembered_shadow_copies.append(selected_drive)
            save_cache({
                "selected_external_drive": self.selected_external_drive,
                "remembered_shadow_copies": self.remembered_shadow_copies
            })
            drive_selection_window.destroy()

        ok_button = tk.Button(drive_selection_window, text="OK", command=on_ok)
        ok_button.pack(pady=10)

    def select_removable_drive(self):
        selected_drive = filedialog.askdirectory(title="Select Removable Backup Drive")
        if selected_drive:
            self.selected_external_drive = selected_drive
            drive_letter = selected_drive[0:2]
            self.log_area.delete(1.0, tk.END)
            files_in_backup = os.listdir(selected_drive)
            log_contents = "\n".join(files_in_backup)
            self.log_area.insert(tk.END, log_contents)
            messagebox.showinfo("Backup Drive", f"Recovery drive set as {drive_letter}")
            save_cache({
                "selected_external_drive": self.selected_external_drive,
                "remembered_shadow_copies": self.remembered_shadow_copies
            })
        else:
            messagebox.showerror("Error", "No removable drive selected.")

    def show_shadow_copies(self):
        shadow_copy_list = list_shadow_copies()
        self.log_area.delete(1.0, tk.END)
        self.log_area.insert(tk.END, shadow_copy_list)

    def restore_from_shadow_copy(self):
        if not self.remembered_shadow_copies:
            messagebox.showerror("Error", "No shadow copies available.")
            return

        shadow_copy_id = "1-abc123"  # Example: You should use the shadow copy ID from the list
        restore_from_shadow_copy(self.selected_drive, shadow_copy_id)

    def restore_from_external_backup(self):
        if not self.selected_external_drive:
            messagebox.showerror("Error", "No external backup drive selected.")
            return

        affected_files = parse_filesystem_log(LOG_FILE)
        restore_from_external_backup(self.selected_external_drive, affected_files)

# --- Main Function to Launch the GUI ---
def main():
    recovery_gui = RecoveryGUI(after_attack=False)

if __name__ == "__main__":
    main()
