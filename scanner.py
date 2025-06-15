import sys
import traceback

print("Start program...")

try:
    from gui.interface import launch_gui
    print("GUI imported successfully")
except Exception as e:
    print(f"Error importing GUI: {str(e)}")
    traceback.print_exc()
    sys.exit(1)

if __name__ == "__main__":
    try:
        print("Start GUI...")
        launch_gui()
    except Exception as e:
        print(f"Error starting GUI: {str(e)}")
        traceback.print_exc()
        sys.exit(1)
