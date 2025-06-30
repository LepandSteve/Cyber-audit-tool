
import os
import json

HISTORY_FILE = "audit_history.json"

def save_to_history(entry):
    history = load_history()
    if entry not in history:
        history.insert(0, entry)
    history = history[:10]  # Keep only last 10
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f)

def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return []
