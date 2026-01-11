import os
import time
import random
import string

SAMPLES_DIR = r"C:\RM\samples"
file_path = r"C:\RM\samples\file-sample_1MB.docx"
os.makedirs(SAMPLES_DIR, exist_ok=True)

# 1. Delete existing .bin and .encrypted files to simulate overwriting
print("[*] Cleaning up existing files...")

for i in range(10):
    # Remove existing .bin and .encrypted files
    bin_file = os.path.join(SAMPLES_DIR, f"file_{i}.bin")
    encrypted_file = os.path.join(SAMPLES_DIR, f"file_{i}.bin.encrypted")
    if os.path.exists(bin_file):
        os.remove(bin_file)
    if os.path.exists(encrypted_file):
        os.remove(encrypted_file)

# 2. Create 10 high-entropy files (.bin files)
print("[*] Writing simulated .bin files...")
for i in range(10):
    filepath = os.path.join(SAMPLES_DIR, f"file_{i}.bin")
    with open(filepath, "wb") as f:
        f.write(os.urandom(1024 * 150))  # 150 KB of random bytes
    time.sleep(0.5)

# 3. Rename 3 files to simulate ransomware-style extensions
print("[*] Renaming files to simulate .encrypted extensions...")
for i in range(3):
    old = os.path.join(SAMPLES_DIR, f"file_{i}.bin")
    new = os.path.join(SAMPLES_DIR, f"file_{i}.bin.encrypted")
    os.rename(old, new)
    time.sleep(0.5)

# 4. Write ransom message in a .txt file (for YARA test)
print("[*] Dropping ransom note text...")
ransom_note_path = os.path.join(SAMPLES_DIR, "readme.txt")
with open(ransom_note_path, "w") as f:
    f.write("Your files have been encrypted.\nPlease pay 0.5 BTC to unlock your data.")

print("[✓] Ransomware simulation complete. Monitor your anti-ransomware log/output.")


def generate_random_data(size_in_bytes):
    """Generate random data to overwrite the file."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size_in_bytes))

def destroy_file(file_path):
    """Overwrite the file's content with random data."""
    try:
        # Ensure the file exists
        if os.path.exists(file_path):
            print(f"[*] Overwriting the contents of {file_path}...")

            # Generate random data
            random_data = generate_random_data(1024 * 1024)  # 1MB of random data

            # Open file in write mode and overwrite its content
            with open(file_path, "w") as f:
                f.write(random_data)
            print(f"[✓] File {file_path} has been overwritten with random data.")
        else:
            print(f"[!] The file {file_path} does not exist.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

# Call the function to destroy the file's content
destroy_file(file_path)