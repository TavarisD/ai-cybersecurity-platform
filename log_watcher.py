import time
import os

def tail_file(filepath, callback):
    while not os.path.exists(filepath):
        print(f"[WATCHER] Waiting for log file: {filepath}")
        time.sleep(1)

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            callback(line.strip())