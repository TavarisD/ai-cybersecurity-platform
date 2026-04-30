import json
import os

BLACKLIST_FILE = "blacklist.json"

def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        return {}
    with open(BLACKLIST_FILE, "r") as f:
        return json.load(f)

def save_blacklist(data):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(data, f, indent=2)

def add_to_blacklist(ip):
    data = load_blacklist()
    data[ip] = data.get(ip, 0) + 1
    save_blacklist(data)

def is_blacklisted(ip):
    data = load_blacklist()
    return ip in data

def get_blacklist():
    return load_blacklist()