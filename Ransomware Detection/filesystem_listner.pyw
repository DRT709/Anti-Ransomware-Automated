import os
import sys
import time
import csv
import yara
import hashlib
import logging
import requests
import psutil
import ctypes
import win32com.client
import wmi
from math import log2
from datetime import datetime
from collections import Counter, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


sys.path.append(r"C:\Users\Mr.Burner\Documents\Ransomware Detection\response.py")

from response import  lockout_system, reboot_to_safe_mode

if not ctypes.windll.shell32.IsUserAnAdmin():
    print("not running as an admin")
else:
    print("running as an admin")

print("response module loaded")

# === CONFIGURATION ===
WATCHED_PATH = r"C:\RM\samples"
LOG_FILE = r"C:\RM\filesystem_listner_log.txt"
CSV_FILE = r"C:\RM\threat_scores.csv"
VT_API_KEY = "15455e0de78947179049632fd699d5ad4dda23dd0bda73cce056de73d853b4af"
MOD_THRESHOLD = 5
TIME_WINDOW = 25

mod_events = deque()
yara_rules = yara.compile(filepath=r"C:\Users\Mr.Burner\Documents\Ransomware Detection\high_entropy.yar.txt")
lockdown_triggered = False

logging.basicConfig(level=logging.INFO)

wmi_interface = wmi.WMI()
shadow_copy_query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_ShadowCopy'"
shadow_copy_creation_query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_ShadowCopy'"
shadow_copy_deletion_query = "SELECT * FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_ShadowCopy'"
# === Logging ===
logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

def popup(msg, title="Anti-Ransomware Shield", icon=0x30):
    ctypes.windll.user32.MessageBoxW(0, msg, title, icon)

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0
    counter = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * log2(count / total) for count in counter.values())
    return entropy

def get_file_sha256(filepath):
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def check_virustotal_hash(sha256):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        positives = stats['malicious'] + stats['suspicious']
        return positives, sum(stats.values())
    elif response.status_code == 404:
        return 0, 0
    else:
        return None, None

def scan_with_yara(filepath):
    try:
        matches = yara_rules.match(filepath)
        return [m.rule for m in matches] if matches else []
    except:
        return []
    


def calculate_threat_score(entropy, yara_results, vt_hits, renamed_suspicious=False):
    score = 0
    if entropy is not None and entropy >= 7.9:
        score += 3
    if yara_results:
        score += 3
    if vt_hits and vt_hits > 0:
        score += 3
    if renamed_suspicious:
        score += 2
    return score

lockdown_triggered = False  
def log_threat_score(file_path, event_type, entropy, yara_results, vt_hits, score):
    global lockdown_triggered
    with open(CSV_FILE, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            event_type,
            file_path,
            f"{entropy:.2f}" if entropy else "N/A",
            yara_results if yara_results else "None",
            vt_hits if vt_hits else "0",
            score
        ])

    if score >= 3 and not lockdown_triggered:
        lockdown_triggered = True  # prevent further lockout attempts
        try:
            #kill_suspicious_process(file_path)
            lockout_system()
        except Exception as e:
            popup(f"Failed to engage lockdown: {e}", icon=0x10)
            logging.error(f"[LOCKDOWN ERROR] {e}")


class RansomwareEventHandler(FileSystemEventHandler):
    filehashes = {}

    def handle_event(self, msg):
        now = time.time()
        mod_events.append(now)
        while mod_events and now - mod_events[0] > TIME_WINDOW:
            mod_events.popleft()

        logging.warning(msg)

        if len(mod_events) >= MOD_THRESHOLD:
            popup(f"ALERT: {len(mod_events)} file events in {TIME_WINDOW}s\nPossible ransomware!", icon=0x10)
            mod_events.clear()

    def is_suspicious_extension(self, path):
        suspicious_exts = ['.locked', '.encrypted', '.enc', '.crypt']
        _, ext = os.path.splitext(path)
        return ext.lower() in suspicious_exts

    def process_file(self, path, event_type, renamed_suspicious=False):
        entropy, yara_results, vt_hits = None, [], 0

        try:
            with open(path, "rb") as f:
                data = f.read()
                entropy = calculate_entropy(data)
                yara_results = scan_with_yara(path)
        except Exception as e:
            logging.error(f"Failed to process file: {path} | {e}")

        if event_type == "Created":
            sha256 = get_file_sha256(path)
            if sha256:
                vt_hits, _ = check_virustotal_hash(sha256)

        score = calculate_threat_score(entropy, yara_results, vt_hits, renamed_suspicious)

        log_threat_score(path, event_type, entropy, yara_results, vt_hits, score)

        if score >= 8:
            self.handle_event(f"[SCORE ALERT] {score} for {path}")
            popup(f"[ALERT] Threat score = {score}\nFile: {path}", icon=0x10)

    def on_created(self, event):
        if not event.is_directory:
            logging.info(f"File created: {event.src_path}")
            self.handle_event(f"File created: {event.src_path}")
            self.process_file(event.src_path, "Created")

    def on_modified(self, event):
        if not event.is_directory:
            logging.info(f"File modified: {event.src_path}")
            self.handle_event(f"File modified: {event.src_path}")
            self.process_file(event.src_path, "Modified")

    def on_moved(self, event):
        if not event.is_directory:
            logging.info(f"File moved: {event.src_path} → {event.dest_path}")
            suspicious = self.is_suspicious_extension(event.dest_path)
            self.process_file(event.dest_path, "Renamed", renamed_suspicious=suspicious)

    def on_deleted(self, event):
        if not event.is_directory:
            logging.info(f"File deleted: {event.src_path}")
            self.handle_event(f"File deleted: {event.src_path}")

    


# === Start Listener ===
if __name__ == "__main__":
    print("🛡️  Starting Anti-Ransomware Listener...")
    event_handler = RansomwareEventHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCHED_PATH, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
