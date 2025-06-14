# Logica de carantină 

import os
import shutil
import datetime

def quarantine_file(file_path):
    """
    Mută un fișier în carantină
    """
    try:
        # Creează directorul de carantină dacă nu există
        quarantine_dir = "quarantine"
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)

        # Generează numele fișierului în carantină
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.basename(file_path)
        quarantine_path = os.path.join(quarantine_dir, f"{timestamp}_{filename}")

        # Mută fișierul în carantină
        shutil.move(file_path, quarantine_path)
        return quarantine_path
    except Exception as e:
        print(f"Eroare la mutarea fișierului în carantină: {str(e)}")
        return None 