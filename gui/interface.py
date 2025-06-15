import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import os
from core.scanner_engine import scan_directory
from core.signature_db import load_signatures
from core.updater import update_signatures
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
from core.virustotal import check_hash_virustotal, upload_file_virustotal
import hashlib
from core.quarantine import list_quarantine_files, restore_from_quarantine, delete_from_quarantine
import pickle
from core.ml_features import extract_features

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class AntivirusGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("MyAntivirusPro")
        self.geometry("900x600")
        self.resizable(False, False)

        # Header
        self.header = ctk.CTkFrame(self, height=60)
        self.header.pack(fill="x", side="top")
        self.logo = ctk.CTkLabel(self.header, text="🦠", font=("Arial", 32))
        self.logo.pack(side="left", padx=20, pady=10)
        self.title_label = ctk.CTkLabel(self.header, text="MyAntivirusPro", font=("Arial", 28, "bold"))
        self.title_label.pack(side="left", padx=10)

        # Main frame
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self.main_frame, width=180)
        self.sidebar.pack(side="left", fill="y")
        self.tab_var = tk.StringVar(value="Scanare")
        self.tabs = ["Scanare", "Carantină", "Setări", "Despre"]
        for tab in self.tabs:
            btn = ctk.CTkButton(self.sidebar, text=tab, width=160, command=lambda t=tab: self.show_tab(t), fg_color=("#1a1a1a", "#1a1a1a"), hover_color="#2a2a2a")
            btn.pack(pady=10, padx=10)

        # Content area
        self.content = ctk.CTkFrame(self.main_frame)
        self.content.pack(side="left", fill="both", expand=True)

        # Status bar
        self.status = ctk.CTkLabel(self, text="Gata de scanare.", anchor="w")
        self.status.pack(fill="x", side="bottom")

        # Tab frames
        self.frames = {}
        for tab in self.tabs:
            frame = ctk.CTkFrame(self.content)
            self.frames[tab] = frame
        self.show_tab("Scanare")

        # --- Scanare Tab ---
        scan_frame = self.frames["Scanare"]
        self.folder_path = ""
        self.scan_label = ctk.CTkLabel(scan_frame, text="Selectează folderul de scanat:", font=("Arial", 16))
        self.scan_label.pack(pady=10)
        self.select_button = ctk.CTkButton(scan_frame, text="Alege folder", command=self.select_folder)
        self.select_button.pack(pady=5)
        self.scan_button = ctk.CTkButton(scan_frame, text="Scanează acum", command=self.scan)
        self.scan_button.pack(pady=5)
        self.realtime_button = ctk.CTkButton(scan_frame, text="Pornește scanare în timp real", command=self.toggle_realtime)
        self.realtime_button.pack(pady=5)
        self.update_button = ctk.CTkButton(scan_frame, text="Update Semnături", command=self.update_signatures)
        self.update_button.pack(pady=5)
        self.progress = ctk.CTkProgressBar(scan_frame, width=400)
        self.progress.set(0)
        self.progress.pack(pady=10)
        self.output = ctk.CTkTextbox(scan_frame, width=700, height=250, font=("Consolas", 12))
        self.output.pack(padx=10, pady=10)

        self.observer = None
        self.realtime_running = False

    def show_tab(self, tab):
        for t, frame in self.frames.items():
            frame.pack_forget()
        self.frames[tab].pack(fill="both", expand=True)
        self.tab_var.set(tab)
        self.status.configure(text=f"Tab: {tab}")
        if tab == "Carantină":
            self.show_quarantine()
        elif tab == "Despre":
            self.show_about()
        elif tab == "Setări":
            self.show_settings()

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path = folder
            self.output.insert("end", f"[INFO] Folder selectat: {folder}\n")
            self.status.configure(text=f"Folder selectat: {folder}")

    def scan(self):
        if not self.folder_path:
            messagebox.showwarning("Avertisment", "Selectează un folder mai întâi.")
            return
        self.output.insert("end", f"[SCANARE] Începe scanarea folderului: {self.folder_path}\n")
        self.status.configure(text="Scanare în curs...")
        self.progress.set(0)
        self.update()
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        start_time = time.time()
        # Încarcă modelul AI/ML
        model = None
        try:
            with open("ai_model/model.pkl", "rb") as f:
                model = pickle.load(f)
        except Exception as e:
            self.output.insert("end", f"[AI/ML] Modelul nu a putut fi încărcat: {e}\n")
        # Animatie progres
        for i in range(1, 101):
            self.progress.set(i/100)
            time.sleep(0.01)  # Simulare progres animat
        signatures = load_signatures("signatures.txt")
        infected, suspicious = scan_directory(self.folder_path, signatures, log_file=None)
        alert_message = ""
        all_files = []
        for root, _, files in os.walk(self.folder_path):
            for name in files:
                all_files.append(os.path.join(root, name))
        # AI/ML verdict
        if model:
            self.output.insert("end", f"[AI/ML] Analizez {len(all_files)} fișiere cu modelul AI...\n")
            for file in all_files:
                feats = extract_features(file)
                try:
                    pred = model.predict([feats])[0]
                    if pred == 1:
                        self.output.insert("end", f"  [AI] SUSPICIOS: {file}\n")
                        alert_message += f"[AI] SUSPICIOS: {file}\n"
                except Exception as e:
                    self.output.insert("end", f"  [AI] Eroare la predicție pentru {file}: {e}\n")
        self.output.insert("end", f"[VIRUSTOTAL] Verific hash-urile la {len(all_files)} fișiere...\n")
        for file in all_files:
            try:
                with open(file, 'rb') as f:
                    file_bytes = f.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                vt = check_hash_virustotal(file_hash)
                if vt is None:
                    self.output.insert("end", f"  {file}: Eroare la interogare VirusTotal\n")
                elif vt.get('not_found'):
                    self.output.insert("end", f"  {file}: Hash necunoscut pe VirusTotal. Trimit fișierul spre analiză...\n")
                    link = upload_file_virustotal(file)
                    if link:
                        self.output.insert("end", f"    [UPLOAD] Fișierul a fost trimis. Vezi raportul (poate dura câteva minute): {link}\n")
                    else:
                        self.output.insert("end", f"    [UPLOAD] Eroare la upload către VirusTotal.\n")
                else:
                    self.output.insert("end", f"  {file}: Detectat de {vt['detected']}/{vt['total']} motoare | Detalii: {vt['permalink']}\n")
            except Exception as e:
                self.output.insert("end", f"  {file}: Eroare la calcul hash/VT: {e}\n")
        if not infected:
            self.output.insert("end", "[RESULTAT] Niciun fișier infectat găsit.\n")
        else:
            self.output.insert("end", f"[RESULTAT] Fișiere infectate găsite: {len(infected)}\n")
            for file in infected:
                self.output.insert("end", f"  -> {file}\n")
                alert_message += f"Fișier infectat: {file}\n"
        if suspicious:
            self.output.insert("end", f"[HEURISTIC] Fișiere suspecte găsite: {len(suspicious)}\n")
            for file, reasons, quarantine_path in suspicious:
                self.output.insert("end", f"  -> {file}\n")
                alert_message += f"Fișier suspect: {file}\n"
                for reason in reasons:
                    self.output.insert("end", f"     Motiv: {reason}\n")
                    alert_message += f"     Motiv: {reason}\n"
                if quarantine_path:
                    self.output.insert("end", f"     Mutat în carantină: {quarantine_path}\n")
                    alert_message += f"     Mutat în carantină: {quarantine_path}\n"
        self.output.insert("end", "\n")
        elapsed = time.time() - start_time
        self.progress.set(1)
        self.status.configure(text=f"Scanare finalizată în {elapsed:.2f} secunde.")
        self.output.insert("end", f"[INFO] Timp scanare: {elapsed:.2f} secunde\n")
        if alert_message:
            messagebox.showerror("Avertisment!", alert_message)

    def toggle_realtime(self):
        if not self.folder_path:
            messagebox.showwarning("Avertisment", "Selectează un folder pentru monitorizare.")
            return
        if not self.realtime_running:
            self.start_realtime_scan()
        else:
            self.stop_realtime_scan()

    def start_realtime_scan(self):
        class Handler(FileSystemEventHandler):
            def __init__(self, gui):
                self.gui = gui
            def on_created(self, event):
                if not event.is_directory:
                    self.gui.scan_file_realtime(event.src_path)
            def on_modified(self, event):
                if not event.is_directory:
                    self.gui.scan_file_realtime(event.src_path)
        self.output.insert("end", f"[INFO] Pornesc monitorizarea folderului: {self.folder_path}\n")
        self.realtime_button.configure(text="Oprește scanare în timp real")
        self.realtime_running = True
        self.observer = Observer()
        event_handler = Handler(self)
        self.observer.schedule(event_handler, self.folder_path, recursive=True)
        threading.Thread(target=self.observer.start, daemon=True).start()
        self.status.configure(text="Monitorizare activă.")

    def stop_realtime_scan(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.output.insert("end", f"[INFO] Monitorizarea a fost oprită.\n")
        self.realtime_button.configure(text="Pornește scanare în timp real")
        self.realtime_running = False
        self.status.configure(text="Monitorizare oprită.")

    def scan_file_realtime(self, file_path):
        signatures = load_signatures("signatures.txt")
        infected, suspicious = scan_directory(os.path.dirname(file_path), signatures, log_file=None)
        alert_message = ""
        found = False
        for file in infected:
            if file == file_path:
                found = True
                alert_message += f"Fișier infectat detectat: {file}\n"
        for file, reasons, quarantine_path in suspicious:
            if file == file_path:
                found = True
                alert_message += f"Fișier suspect detectat: {file}\n"
                for reason in reasons:
                    alert_message += f"  Motiv: {reason}\n"
                if quarantine_path:
                    alert_message += f"  Mutat în carantină: {quarantine_path}\n"
        if found:
            self.output.insert("end", alert_message + "\n")
            messagebox.showerror("Avertisment! (Timp real)", alert_message)

    def show_quarantine(self):
        frame = self.frames["Carantină"]
        for widget in frame.winfo_children():
            widget.destroy()
        label = ctk.CTkLabel(frame, text="Fișiere în carantină:", font=("Arial", 16))
        label.pack(pady=10)
        files = list_quarantine_files()
        if not files:
            ctk.CTkLabel(frame, text="Nu există fișiere în carantină.").pack(pady=10)
            return
        for f in files:
            row = ctk.CTkFrame(frame)
            row.pack(fill="x", padx=10, pady=5)
            info = f"{f['file']}\nOriginal: {f['original_path']}\nMotiv: {f['reason']}\nDată: {f['date']}"
            ctk.CTkLabel(row, text=info, width=500, anchor="w", justify="left").pack(side="left", padx=5)
            ctk.CTkButton(row, text="Restaurare", width=100, command=lambda fn=f['file']: self.restore_quarantine(fn)).pack(side="left", padx=5)
            ctk.CTkButton(row, text="Șterge", width=80, fg_color="red", command=lambda fn=f['file']: self.delete_quarantine(fn)).pack(side="left", padx=5)

    def restore_quarantine(self, filename):
        if restore_from_quarantine(filename):
            messagebox.showinfo("Restaurare", "Fișierul a fost restaurat la locația originală.")
        else:
            messagebox.showerror("Eroare", "Restaurarea a eșuat.")
        self.show_quarantine()

    def delete_quarantine(self, filename):
        if delete_from_quarantine(filename):
            messagebox.showinfo("Ștergere", "Fișierul a fost șters definitiv din carantină.")
        else:
            messagebox.showerror("Eroare", "Ștergerea a eșuat.")
        self.show_quarantine()

    def show_about(self):
        frame = self.frames["Despre"]
        for widget in frame.winfo_children():
            widget.destroy()
        label = ctk.CTkLabel(frame, text="MyAntivirusPro\nRealizat de Tiberiu Manolescu\n2024", font=("Arial", 18))
        label.pack(pady=30)
        ctk.CTkLabel(frame, text="Interfață modernă cu customtkinter\nScanare pe semnături și euristică\nCarantină, update semnături, scanare în timp real", font=("Arial", 14)).pack(pady=10)

    def show_settings(self):
        frame = self.frames["Setări"]
        for widget in frame.winfo_children():
            widget.destroy()
        ctk.CTkLabel(frame, text="Setări (în curând)", font=("Arial", 16)).pack(pady=30)

    def update_signatures(self):
        success = update_signatures(
            url="https://raw.githubusercontent.com/TiberiuTech/antivirus/main/signatures.txt"
        )
        if success:
            self.output.insert("end", "[INFO] Semnăturile au fost actualizate.\n")
        else:
            self.output.insert("end", "[Eroare] Actualizarea semnăturilor a eșuat.\n")

def launch_gui():
    app = AntivirusGUI()
    app.mainloop()
