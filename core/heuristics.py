# Logica euristică 

import os

SUSPICIOUS_KEYWORDS = [
    b'powershell', b'cmd.exe', b'rundll32', b'base64', b'vbs', b'jscript', b'ftp', b'curl', b'wget', b'Invoke-', b'Add-MpPreference'
]

def has_double_extension(filename):
    parts = filename.lower().split('.')
    return len(parts) > 2 and parts[-1] in ['exe', 'bat', 'cmd', 'scr', 'js', 'vbs']

def heuristic_scan_file(file_path):
    """
    Returnează o listă cu motivele pentru care fișierul este suspect, sau listă goală dacă nu e suspect.
    """
    reasons = []
    try:
        size = os.path.getsize(file_path)
        if size < 10 * 1024 and file_path.lower().endswith(('.exe', '.bat', '.cmd', '.scr', '.js', '.vbs')):
            reasons.append('Fișier executabil foarte mic (<10KB)')

        if has_double_extension(os.path.basename(file_path)):
            reasons.append('Fișier cu extensie dublă')

        # Caută cuvinte cheie doar în fișiere mici (max 1MB)
        if size < 1024 * 1024:
            with open(file_path, 'rb') as f:
                content = f.read()
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in content:
                        reasons.append(f'Conține cuvânt cheie suspect: {kw.decode()}')
                        break
    except Exception as e:
        reasons.append(f'Eroare la analiza euristică: {str(e)}')
    return reasons 