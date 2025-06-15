# Logica de carantină 

import os
import shutil
import datetime
import json

QUARANTINE_DIR = "quarantine"
META_FILE = os.path.join(QUARANTINE_DIR, "info.json")

def load_metadata():
    if not os.path.exists(META_FILE):
        return {}
    try:
        with open(META_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def save_metadata(meta):
    with open(META_FILE, 'w') as f:
        json.dump(meta, f, indent=2)

def quarantine_file(file_path, reason=""):  # motiv opțional
    """
    Mută un fișier în carantină
    """
    try:
        # Creează directorul de carantină dacă nu există
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)

        # Generează numele fișierului în carantină
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.basename(file_path)
        quarantine_path = os.path.join(QUARANTINE_DIR, f"{timestamp}_{filename}")

        # Mută fișierul în carantină
        shutil.move(file_path, quarantine_path)
        # Salvează metadate
        meta = load_metadata()
        meta[os.path.basename(quarantine_path)] = {
            "original_path": file_path,
            "reason": reason,
            "date": timestamp
        }
        save_metadata(meta)
        return quarantine_path
    except Exception as e:
        print(f"Eroare la mutarea fișierului în carantină: {str(e)}")
        return None 

def list_quarantine_files():
    files = []
    meta = load_metadata()
    if not os.path.exists(QUARANTINE_DIR):
        return files
    for f in os.listdir(QUARANTINE_DIR):
        if f == "info.json":
            continue
        info = meta.get(f, {})
        files.append({
            "file": f,
            "path": os.path.join(QUARANTINE_DIR, f),
            "original_path": info.get("original_path", "?"),
            "reason": info.get("reason", "?"),
            "date": info.get("date", "?")
        })
    return files

def restore_from_quarantine(filename):
    meta = load_metadata()
    info = meta.get(filename)
    if not info:
        return False
    src = os.path.join(QUARANTINE_DIR, filename)
    dst = info["original_path"]
    try:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(src, dst)
        del meta[filename]
        save_metadata(meta)
        return True
    except Exception as e:
        print(f"Eroare la restaurare: {e}")
        return False

def delete_from_quarantine(filename):
    meta = load_metadata()
    path = os.path.join(QUARANTINE_DIR, filename)
    try:
        if os.path.exists(path):
            os.remove(path)
        if filename in meta:
            del meta[filename]
            save_metadata(meta)
        return True
    except Exception as e:
        print(f"Eroare la ștergere: {e}")
        return False 