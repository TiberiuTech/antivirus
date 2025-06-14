import os
import requests

def load_signatures(signature_file):
    """
    Încarcă semnăturile din fișierul specificat
    """
    try:
        if not os.path.exists(signature_file):
            print(f"Fișierul de semnături {signature_file} nu există. Se creează unul nou.")
            with open(signature_file, 'w') as f:
                f.write("# Semnături viruși\n")
            return []
            
        with open(signature_file, 'r') as f:
            signatures = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return signatures
    except Exception as e:
        print(f"Eroare la încărcarea semnăturilor: {str(e)}")
        return [] 