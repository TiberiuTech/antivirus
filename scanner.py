import sys
import traceback

print("Începe pornirea programului...")

try:
    from gui.interface import launch_gui
    print("Importul GUI-ului a reușit")
except Exception as e:
    print(f"Eroare la importul GUI-ului: {str(e)}")
    traceback.print_exc()
    sys.exit(1)

if __name__ == "__main__":
    try:
        print("Începe lansarea interfeței grafice...")
        launch_gui()
    except Exception as e:
        print(f"Eroare la lansarea GUI-ului: {str(e)}")
        traceback.print_exc()
        sys.exit(1)
