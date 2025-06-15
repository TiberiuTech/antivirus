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
from PIL import Image, ImageTk
import math

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORS = {
    "primary": "#1a73e8",
    "secondary": "#34a853",
    "accent": "#ea4335",
    "background": "#0a0a0a",
    "surface": "#1a1a1a",
    "text": "#ffffff",
    "text_secondary": "#b0b0b0",
    "header": "#1a1a1a"
}

class GradientFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(fg_color="transparent")
        
    def _draw(self):
        self.delete("gradient")
        width = self.winfo_width()
        height = self.winfo_height()
        
        for i in range(height):
            r1, g1, b1 = 26, 115, 232  
            r2, g2, b2 = 52, 168, 83  
            ratio = i / height
            r = r1 + (r2 - r1) * ratio
            g = g1 + (g2 - g1) * ratio
            b = b1 + (b2 - b1) * ratio
            color = f'#{int(r):02x}{int(g):02x}{int(b):02x}'
            self.create_line(0, i, width, i, fill=color, tags="gradient")

class AntivirusGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Antivirus")
        self.geometry("1200x800")
        self.configure(fg_color=COLORS["background"])
        
        self.header = ctk.CTkFrame(self, height=80, fg_color=COLORS["header"])
        self.header.pack(fill="x", side="top", padx=0, pady=0)
        
        self.logo_frame = ctk.CTkFrame(self.header, fg_color="transparent")
        self.logo_frame.pack(side="left", padx=20, pady=10)
        
        self.logo = ctk.CTkLabel(self.logo_frame, text="🛡️", font=("Arial", 40))
        self.logo.pack(side="left", padx=10)
        
        self.title_frame = ctk.CTkFrame(self.logo_frame, fg_color="transparent")
        self.title_frame.pack(side="left", padx=10)
        
        self.title_label = ctk.CTkLabel(self.title_frame, text="Antivirus", 
                                      font=("Segoe UI", 32, "bold"),
                                      text_color=COLORS["text"])
        self.title_label.pack(side="top")
        
        self.subtitle = ctk.CTkLabel(self.title_frame, text="Protect your system",
                                   font=("Segoe UI", 12),
                                   text_color=COLORS["text_secondary"])
        self.subtitle.pack(side="top")

        self.main_frame = ctk.CTkFrame(self, fg_color=COLORS["surface"])
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.sidebar = ctk.CTkFrame(self.main_frame, width=200, fg_color=COLORS["surface"])
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)
        
        self.tab_var = tk.StringVar(value="Scan")
        self.tabs = [
            ("Scan", "🔍"),
            ("Quarantine", "📦"),
            ("Settings", "⚙️"),
            ("About", "ℹ️")
        ]
        
        for tab, icon in self.tabs:
            btn_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
            btn_frame.pack(fill="x", padx=5, pady=5)
            
            btn = ctk.CTkButton(btn_frame, 
                              text=f"{icon} {tab}",
                              width=180,
                              height=40,
                              command=lambda t=tab: self.show_tab(t),
                              fg_color=COLORS["surface"],
                              hover_color=COLORS["primary"],
                              font=("Segoe UI", 14),
                              corner_radius=10)
            btn.pack(fill="x", padx=5)

        self.content = ctk.CTkFrame(self.main_frame, fg_color=COLORS["surface"])
        self.content.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.status_frame = ctk.CTkFrame(self, height=40, fg_color=COLORS["surface"])
        self.status_frame.pack(fill="x", side="bottom", padx=20, pady=(0, 20))
        
        self.status = ctk.CTkLabel(self.status_frame, 
                                 text="System ready for scan",
                                 font=("Segoe UI", 12),
                                 text_color=COLORS["text_secondary"])
        self.status.pack(side="left", padx=10)

        self.frames = {}
        for tab, _ in self.tabs:
            frame = ctk.CTkFrame(self.content, fg_color=COLORS["surface"])
            self.frames[tab] = frame
        self.show_tab("Scan")

        scan_frame = self.frames["Scan"]
        
        scan_header = ctk.CTkFrame(scan_frame, fg_color="transparent")
        scan_header.pack(fill="x", padx=20, pady=20)
        
        self.scan_label = ctk.CTkLabel(scan_header, 
                                     text="Scan System",
                                     font=("Segoe UI", 24, "bold"),
                                     text_color=COLORS["text"])
        self.scan_label.pack(side="left")
        
        action_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        action_frame.pack(fill="x", padx=20, pady=10)
        
        self.folder_path = ""
        self.select_button = ctk.CTkButton(action_frame,
                                         text="📁 Select folder",
                                         command=self.select_folder,
                                         width=200,
                                         height=40,
                                         font=("Segoe UI", 14),
                                         fg_color=COLORS["primary"],
                                         hover_color=COLORS["secondary"])
        self.select_button.pack(side="left", padx=5)
        
        self.scan_button = ctk.CTkButton(action_frame,
                                       text="▶️ Scan now",
                                       command=self.scan,
                                       width=200,
                                       height=40,
                                       font=("Segoe UI", 14),
                                       fg_color=COLORS["secondary"],
                                       hover_color=COLORS["primary"])
        self.scan_button.pack(side="left", padx=5)
        
        self.realtime_button = ctk.CTkButton(action_frame,
                                           text="🔄 Start monitoring",
                                           command=self.toggle_realtime,
                                           width=200,
                                           height=40,
                                           font=("Segoe UI", 14),
                                           fg_color=COLORS["accent"],
                                           hover_color=COLORS["primary"])
        self.realtime_button.pack(side="left", padx=5)
        
        self.update_button = ctk.CTkButton(action_frame,
                                         text="📥 Update signaturess",
                                         command=self.update_signatures,
                                         width=200,
                                         height=40,
                                         font=("Segoe UI", 14),
                                         fg_color=COLORS["surface"],
                                         hover_color=COLORS["primary"])
        self.update_button.pack(side="left", padx=5)

        progress_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        progress_frame.pack(fill="x", padx=20, pady=10)
        
        self.progress = ctk.CTkProgressBar(progress_frame,
                                         width=800,
                                         height=20,
                                         corner_radius=10,
                                         progress_color=COLORS["primary"])
        self.progress.set(0)
        self.progress.pack(pady=10)

        output_frame = ctk.CTkFrame(scan_frame, fg_color=COLORS["background"])
        output_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.output = ctk.CTkTextbox(output_frame,
                                   width=800,
                                   height=400,
                                   font=("Consolas", 12),
                                   fg_color=COLORS["background"],
                                   text_color=COLORS["text"])
        self.output.pack(padx=10, pady=10, fill="both", expand=True)

        self.observer = None
        self.realtime_running = False

    def show_tab(self, tab):
        for t, frame in self.frames.items():
            frame.pack_forget()
        self.frames[tab].pack(fill="both", expand=True)
        self.tab_var.set(tab)
        self.status.configure(text=f"Tab activ: {tab}")
        if tab == "Quarantine":
            self.show_quarantine()
        elif tab == "About":
            self.show_about()
        elif tab == "Settings":
            self.show_settings()

    def show_quarantine(self):
        frame = self.frames["Quarantine"]
        for widget in frame.winfo_children():
            widget.destroy()
            
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=20)
        
        title = ctk.CTkLabel(header,
                           text="Files in Quarantine",
                           font=("Segoe UI", 24, "bold"),
                           text_color=COLORS["text"])
        title.pack(side="left")
        
        files = list_quarantine_files()
        if not files:
            no_files = ctk.CTkLabel(frame,
                                  text="No files in quarantine",
                                  font=("Segoe UI", 16),
                                  text_color=COLORS["text_secondary"])
            no_files.pack(pady=50)
            return
            
        for f in files:
            file_frame = ctk.CTkFrame(frame, fg_color=COLORS["background"])
            file_frame.pack(fill="x", padx=20, pady=5)
            
            info_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
            info_frame.pack(side="left", fill="x", expand=True, padx=10, pady=10)
            
            file_name = ctk.CTkLabel(info_frame,
                                   text=f["file"],
                                   font=("Segoe UI", 14, "bold"),
                                   text_color=COLORS["text"])
            file_name.pack(anchor="w")
            
            details = ctk.CTkLabel(info_frame,
                                 text=f"Original: {f['original_path']}\nMotiv: {f['reason']}\nDată: {f['date']}",
                                 font=("Segoe UI", 12),
                                 text_color=COLORS["text_secondary"])
            details.pack(anchor="w")
            
            button_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
            button_frame.pack(side="right", padx=10, pady=10)
            
            restore_btn = ctk.CTkButton(button_frame,
                                      text="↩️ Restore",
                                      command=lambda fn=f['file']: self.restore_quarantine(fn),
                                      width=120,
                                      height=30,
                                      font=("Segoe UI", 12),
                                      fg_color=COLORS["secondary"])
            restore_btn.pack(side="left", padx=5)
            
            delete_btn = ctk.CTkButton(button_frame,
                                     text="🗑️ Delete",
                                     command=lambda fn=f['file']: self.delete_quarantine(fn),
                                     width=120,
                                     height=30,
                                     font=("Segoe UI", 12),
                                     fg_color=COLORS["accent"])
            delete_btn.pack(side="left", padx=5)

    def show_about(self):
        frame = self.frames["About"]
        for widget in frame.winfo_children():
            widget.destroy()
            
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=20)
        
        title = ctk.CTkLabel(header,
                           text="About Antivirus",
                           font=("Segoe UI", 24, "bold"),
                           text_color=COLORS["text"])
        title.pack(side="left")
        
        content = ctk.CTkFrame(frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=40, pady=20)
        
        logo = ctk.CTkLabel(content,
                          text="🛡️",
                          font=("Arial", 80))
        logo.pack(pady=20)
        
        info = ctk.CTkLabel(content,
                          text="Antivirus\nVersion 1.0\n\nMade by Tiberiu Manolescu\n2024",
                          font=("Segoe UI", 18),
                          text_color=COLORS["text"])
        info.pack(pady=20)
        
        features = ctk.CTkLabel(content,
                              text="• Interfață modernă și intuitivă\n• Scanare pe semnături și euristică\n• Protecție în timp real\n• Carantină automată\n• Integrare cu VirusTotal\n• AI/ML pentru detectare avansată",
                              font=("Segoe UI", 14),
                              text_color=COLORS["text_secondary"])
        features.pack(pady=20)

    def show_settings(self):
        frame = self.frames["Settings"]
        for widget in frame.winfo_children():
            widget.destroy()
            
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=20)
        
        title = ctk.CTkLabel(header,
                           text="Settings",
                           font=("Segoe UI", 24, "bold"),
                           text_color=COLORS["text"])
        title.pack(side="left")
        
        content = ctk.CTkFrame(frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=40, pady=20)
        
        settings = [
            ("Theme", "🌓", "dark"),
            ("Language", "🌍", "română"),
            ("Notifications", "🔔", "activate"),
            ("Auto-update", "🔄", "deactivated")
        ]
        
        for setting, icon, value in settings:
            setting_frame = ctk.CTkFrame(content, fg_color=COLORS["background"])
            setting_frame.pack(fill="x", padx=20, pady=10)
            
            setting_label = ctk.CTkLabel(setting_frame,
                                       text=f"{icon} {setting}",
                                       font=("Segoe UI", 16),
                                       text_color=COLORS["text"])
            setting_label.pack(side="left", padx=20, pady=10)
            
            setting_value = ctk.CTkLabel(setting_frame,
                                       text=value,
                                       font=("Segoe UI", 14),
                                       text_color=COLORS["text_secondary"])
            setting_value.pack(side="right", padx=20, pady=10)

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
        model = None
        try:
            with open("ai_model/model.pkl", "rb") as f:
                model = pickle.load(f)
        except Exception as e:
            self.output.insert("end", f"[AI/ML] Modelul nu a putut fi încărcat: {e}\n")
        for i in range(1, 101):
            self.progress.set(i/100)
            time.sleep(0.01)
        signatures = load_signatures("signatures.txt")
        infected, suspicious = scan_directory(self.folder_path, signatures, log_file=None)
        alert_message = ""
        all_files = []
        for root, _, files in os.walk(self.folder_path):
            for name in files:
                all_files.append(os.path.join(root, name))
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
                    self.output.insert("end", f"  [AI] Error predicting for {file}: {e}\n")
        self.output.insert("end", f"[VIRUSTOTAL] Check hashes for {len(all_files)} files...\n")
        for file in all_files:
            try:
                with open(file, 'rb') as f:
                    file_bytes = f.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                vt = check_hash_virustotal(file_hash)
                if vt is None:
                    self.output.insert("end", f"  {file}: Error querying VirusTotal\n")
                elif vt.get('not_found'):
                    self.output.insert("end", f"  {file}: Hash not found on VirusTotal. Sending file for analysis...\n")
                    link = upload_file_virustotal(file)
                    if link:
                        self.output.insert("end", f"    [UPLOAD] File sent. See report (may take a few minutes): {link}\n")
                    else:
                        self.output.insert("end", f"    [UPLOAD] Error uploading to VirusTotal.\n")
                else:
                    self.output.insert("end", f"  {file}: Detectat de {vt['detected']}/{vt['total']} motoare | Detalii: {vt['permalink']}\n")
            except Exception as e:
                self.output.insert("end", f"  {file}: Error calculating hash/VT: {e}\n")
        if not infected:
            self.output.insert("end", "[RESULT] No infected files found.\n")
        else:
            self.output.insert("end", f"[RESULT] Infected files found: {len(infected)}\n")
            for file in infected:
                self.output.insert("end", f"  -> {file}\n")
                alert_message += f"Infected file: {file}\n"
        if suspicious:
            self.output.insert("end", f"[HEURISTIC] Suspicious files found: {len(suspicious)}\n")
            for file, reasons, quarantine_path in suspicious:
                self.output.insert("end", f"  -> {file}\n")
                alert_message += f"Suspicious file: {file}\n"
                for reason in reasons:
                    self.output.insert("end", f"     Motive: {reason}\n")
                    alert_message += f"     Motive: {reason}\n"
                if quarantine_path:
                    self.output.insert("end", f"     Quarantined: {quarantine_path}\n")
                    alert_message += f"     Quarantined: {quarantine_path}\n"
        self.output.insert("end", "\n")
        elapsed = time.time() - start_time
        self.progress.set(1)
        self.status.configure(text=f"Scan finished in {elapsed:.2f} seconds.")
        self.output.insert("end", f"[INFO] Scan time: {elapsed:.2f} seconds\n")
        if alert_message:
            messagebox.showerror("Avertisment!", alert_message)

    def toggle_realtime(self):
        if not self.folder_path:
            messagebox.showwarning("Avertisment", "Select a folder for monitoring.")
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
        self.realtime_button.configure(text="⏹️ Stop monitoring")
        self.realtime_running = True
        self.observer = Observer()
        event_handler = Handler(self)
        self.observer.schedule(event_handler, self.folder_path, recursive=True)
        threading.Thread(target=self.observer.start, daemon=True).start()
        self.status.configure(text="Monitoring active.")

    def stop_realtime_scan(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            self.output.insert("end", f"[INFO] Monitoring stopped.\n")
        self.realtime_button.configure(text="🔄 Start monitoring")
        self.realtime_running = False
        self.status.configure(text="Monitoring stopped.")

    def scan_file_realtime(self, file_path):
        signatures = load_signatures("signatures.txt")
        infected, suspicious = scan_directory(os.path.dirname(file_path), signatures, log_file=None)
        alert_message = ""
        found = False
        for file in infected:
            if file == file_path:
                found = True
                alert_message += f"Infected file detected: {file}\n"
        for file, reasons, quarantine_path in suspicious:
            if file == file_path:
                found = True
                alert_message += f"Suspicious file detected: {file}\n"
                for reason in reasons:
                    alert_message += f"  Motive: {reason}\n"
                if quarantine_path:
                    alert_message += f"  Quarantined: {quarantine_path}\n"
        if found:
            self.output.insert("end", alert_message + "\n")
            messagebox.showerror("Avertisment! (Real time)", alert_message)

    def update_signatures(self):
        success = update_signatures(
            url="https://raw.githubusercontent.com/TiberiuTech/antivirus/main/signatures.txt"
        )
        if success:
            self.output.insert("end", "[INFO] Signatures updated.\n")
        else:
            self.output.insert("end", "[Error] Failed to update signatures.\n")

def launch_gui():
    app = AntivirusGUI()
    app.mainloop()
