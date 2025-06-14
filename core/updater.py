import requests

def update_signatures(
    url="https://raw.githubusercontent.com/TiberiuTech/antivirus/main/signatures.txt",
    local_path="signatures.txt"
):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open(local_path, "w") as f:
                f.write(response.text)
            print("[INFO] Semnăturile au fost actualizate cu succes.")
            return True
        else:
            print(f"[Eroare] Nu s-au putut descărca semnăturile (Status code: {response.status_code})")
            return False
    except Exception as e:
        print(f"[Eroare] Actualizarea semnăturilor a eșuat: {e}")
        return False
