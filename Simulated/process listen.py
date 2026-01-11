import psutil
import os
import time
from datetime import datetime

LOG_PATH = r"C:\RM\process_snapshot.txt.txt"

WHITELIST = {
    'system idle process', 'system', 'registry', 'memcompression',
    'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'taskhostw.exe',
    'sihost.exe', 'explorer.exe', 'dwm.exe', 'audiodg.exe',
    'ctfmon.exe', 'conhost.exe', 'dllhost.exe', 'spoolsv.exe',
    'textinputhost.exe', 'startmenuexperiencehost.exe',
    'applicationframehost.exe', 'systemsettings.exe',
    'wmiprvse.exe', 'useroobebroker.exe', 'aggregatorhost.exe',
    'runtimebroker.exe', 'fontdrvhost.exe', 'wmiadap.exe',

    'msmpeng.exe', 'mpdefendercoreservice.exe', 'nissrv.exe',
    'securityhealthservice.exe', 'securityhealthsystray.exe',
    'smartscreen.exe',

    'searchindexer.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',

    'python.exe', 'pythonw.exe', 'code.exe', 'notepad.exe'
}


def log_all_processes():
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"\n--- Snapshot at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
            try:
                info = proc.info
                name = info['name'].lower()
                tag = "[WHITELISTED]" if name in WHITELIST else "[SUSPEND CANDIDATE]"
                f.write(f"{tag} PID: {info['pid']} | Name: {info['name']} | EXE: {info.get('exe', 'N/A')} | User: {info.get('username', 'N/A')}\n")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

def run_listener_loop(interval=10):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    print(f"🔄 Starting process snapshot loop every {interval}s. Press Ctrl+C to stop.")
    try:
        while True:
            log_all_processes()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("🛑 Monitoring stopped by user.")

if __name__ == "__main__":
    run_listener_loop(interval=10)
