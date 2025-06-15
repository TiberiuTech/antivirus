import os
import hashlib
from core.quarantine import quarantine_file
from core.heuristics import heuristic_scan_file

def calculate_md5(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None

def scan_directory(path, signatures, log_file=None):
    infected = []
    suspicious = []

    for root, _, files in os.walk(path):
        for name in files:
            full_path = os.path.join(root, name)
            md5 = calculate_md5(full_path)
            if md5 is None:
                if log_file:
                    log_file.write(f"[Eroare] Nu pot accesa {full_path}\n")
                continue
            # Detecție pe semnătură
            if md5 in signatures:
                if log_file:
                    log_file.write(f"[INFECTAT] {full_path}\n")
                quarantine_path = quarantine_file(full_path, reason="Semnătură detectată")
                if quarantine_path and log_file:
                    log_file.write(f" => Mutat în carantină: {quarantine_path}\n")
                infected.append(full_path)
                continue
            # Detecție euristică
            reasons = heuristic_scan_file(full_path)
            if reasons:
                quarantine_path = quarantine_file(full_path, reason=", ".join(reasons))
                suspicious.append((full_path, reasons, quarantine_path))
                if log_file:
                    log_file.write(f"[SUSPECT] {full_path} => {', '.join(reasons)}\n")
                    if quarantine_path:
                        log_file.write(f" => Mutat în carantină: {quarantine_path}\n")
    return infected, suspicious
