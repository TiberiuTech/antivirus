from core.updater import update_signatures

if __name__ == "__main__":
    rezultat = update_signatures(
        url="https://raw.githubusercontent.com/TiberiuTech/antivirus/main/signatures.txt"
    )
    print("actuallize result", rezultat)
