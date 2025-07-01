# gui.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import sys
import os
from PIL import Image, ImageTk
from modules.report import (
    generate_txt_report,
    generate_html_report,
    generate_json_report,
    generate_pdf_report,
)
from modules.main_audit_runner import run_full_audit
import threading
import textwrap
from modules.version_checker import check_latest_version
from modules.auto_updater import run_auto_updater

MODULE_GROUPS = {
    "System & OS": ["system_info", "os_detection", "firewall_check", "antivirus_check"],
    "Network & Ports": ["network_scan", "port_check", "remote_port_activity"],
    "Security Checks": ["credential_check", "brute_force_exposure", "public_exposure", "service_security", "weak_protocols"],
    "Web & HTTP": ["http_headers_check", "tls_inspector", "banner_grabber"],
    "Geolocation": ["ip_geolocation", "geoip_lookup"],
    "Analysis & Lookup": ["whois_lookup", "reverse_DNS", "cve_lookup", "vulnerability_scanner", "ntp_time_skew"]
}

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller EXE """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class CyberAuditGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cybersecurity Audit Tool - DGDI / DSSI")
        self.geometry("1100x760")
        self.resizable(False, False)
        self.is_fullscreen = False
        self.current_theme = "light"
        self.hostname = socket.gethostname()
        self.audit_results = {}
        self.shared_data = {}
        self.final_report_data = []
        self.listbox_indices_headers = []

        self.setup_styles()
        self.create_widgets()

        self.bind("<F11>", self.toggle_fullscreen)
        self.bind("<Escape>", self.exit_fullscreen)

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

    def create_widgets(self):
        self.configure(bg="#f0f0f0")
        self.load_logo()
        self.build_input_frame()
        self.build_module_frame()
        self.build_button_frame()
        self.build_result_display()

    def load_logo(self):
        try:
            logo_path = resource_path("dgdi_logo.png")
            logo = Image.open(logo_path).resize((140, 70))
            self.logo_image = ImageTk.PhotoImage(logo)
            tk.Label(self, image=self.logo_image, bg=self["bg"]).pack(pady=10)
        except Exception as e:
            print(f"[Warning] Logo not loaded: {e}")

    def build_input_frame(self):
        self.input_frame = tk.Frame(self, bg=self["bg"])
        self.input_frame.pack(pady=10, fill=tk.X)

        def lbl(text): return tk.Label(self.input_frame, text=text, bg=self["bg"], font=("Segoe UI", 10))

        lbl("Target IP / Hostname:").grid(row=0, column=0, padx=8, pady=5, sticky="w")
        self.entry_target = tk.Entry(self.input_frame, width=30, font=("Segoe UI", 10))
        self.entry_target.grid(row=0, column=1, padx=5)

        lbl("Language:").grid(row=0, column=2, padx=8)
        self.lang_var = tk.StringVar(value="English")
        ttk.Combobox(self.input_frame, textvariable=self.lang_var, values=["English", "French"], width=10).grid(row=0, column=3)

        lbl("Export Format:").grid(row=0, column=4, padx=8)
        self.export_format = tk.StringVar(value="pdf")
        ttk.Combobox(self.input_frame, textvariable=self.export_format, values=["txt", "json", "html", "pdf"], width=10).grid(row=0, column=5)

    def build_module_frame(self):
        self.module_frame = tk.LabelFrame(self, text="Select Modules to Run", bg=self["bg"], font=("Segoe UI", 10, "bold"))
        self.module_frame.pack(padx=20, pady=10, fill=tk.BOTH)

        self.module_listbox = tk.Listbox(self.module_frame, selectmode=tk.MULTIPLE, width=50, height=16, font=("Segoe UI", 9))
        idx = 0
        for group, modules in MODULE_GROUPS.items():
            self.module_listbox.insert(tk.END, f"--- {group} ---")
            self.listbox_indices_headers.append(idx)
            idx += 1
            for m in modules:
                self.module_listbox.insert(tk.END, f"  {m}")
                idx += 1
        self.module_listbox.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        self.select_all_var = tk.IntVar(value=1)
        self.select_all_cb = tk.Checkbutton(self.module_frame, text="Select All Modules", variable=self.select_all_var,
                                            command=self.toggle_select_all, bg=self["bg"])
        self.select_all_cb.pack(anchor="w", padx=10)
        self.toggle_select_all()

    def build_button_frame(self):
        btn_frame = tk.Frame(self, bg=self["bg"])
        btn_frame.pack(pady=10)

        def add_button(text, cmd, bg, fg="white", width=14):
            return tk.Button(btn_frame, text=text, command=cmd, bg=bg, fg=fg,
                             font=("Segoe UI", 10, "bold"), width=width)

        self.btn_start = add_button("Start Audit", self.perform_audit, "#4caf50")
        self.btn_start.pack(side=tk.LEFT, padx=10)

        self.btn_export = add_button("Export Report", self.export_report, "#2196f3")
        self.btn_export.pack(side=tk.LEFT, padx=10)

        self.btn_dark_mode = add_button("Toggle Dark Mode", self.toggle_dark_mode, "#555")
        self.btn_dark_mode.pack(side=tk.LEFT, padx=10)

        self.btn_fullscreen = add_button("Toggle Fullscreen", self.toggle_fullscreen, "#333")
        self.btn_fullscreen.pack(side=tk.LEFT, padx=10)

        self.btn_quit = add_button("Quit", self.quit, "#f44336")
        self.btn_quit.pack(side=tk.LEFT, padx=10)

        self.btn_check_version = add_button("Check The Version", self.check_version, "#673ab7")
        self.btn_check_version.pack(side=tk.LEFT, padx=10)
        self.btn_update = add_button("Auto Update", self.run_auto_updater, "#ff9800")
        self.btn_update.pack (side=tk.LEFT, padx=10)

        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate", length=800)
        self.progress.pack(pady=10)

    def build_result_display(self):
        result_frame = tk.Frame(self)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.result_text = tk.Text(result_frame, wrap=tk.WORD, font=("Consolas", 10), bg="white", fg="black", undo=True)
        scroll = ttk.Scrollbar(result_frame, command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scroll.set)

        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def toggle_select_all(self):
        if self.select_all_var.get():
            for i in range(self.module_listbox.size()):
                if i not in self.listbox_indices_headers:
                    self.module_listbox.select_set(i)
        else:
            self.module_listbox.select_clear(0, tk.END)

    def get_selected_modules(self):
        return [
            self.module_listbox.get(i).strip()
            for i in self.module_listbox.curselection()
            if i not in self.listbox_indices_headers
        ]

    def disable_buttons(self):
        for widget in [self.btn_start, self.btn_export, self.btn_dark_mode, self.btn_fullscreen, self.btn_quit,
                       self.module_listbox, self.select_all_cb, self.entry_target]:
            widget.config(state=tk.DISABLED)

    def enable_buttons(self):
        for widget in [self.btn_start, self.btn_export, self.btn_dark_mode, self.btn_fullscreen, self.btn_quit,
                       self.module_listbox, self.select_all_cb, self.entry_target]:
            widget.config(state=tk.NORMAL)

    def perform_audit(self):
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showwarning("Input Error", "Please enter a target hostname or IP address.")
            return

        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            messagebox.showerror("Input Error", "Invalid hostname or IP address.")
            return

        selected_modules = self.get_selected_modules()
        if not selected_modules:
            messagebox.showwarning("Selection Error", "Please select at least one audit module.")
            return

        self.result_text.delete("1.0", tk.END)
        self.audit_results.clear()
        self.progress["value"] = 0
        self.shared_data = {"target": target, "hostname": self.hostname}
        self.final_report_data = []
        self.final_score = 0.0
        self.final_status = "Unknown"

        self.disable_buttons()

        stop_event = threading.Event()

        def update_progress(info):
            def update_ui():
                if isinstance(info, tuple):
                    msg, percent = info[0], info[1]
                    self.progress["value"] = percent
                    if len(info) >= 5:
                        self.title(f"Running: {info[2]} ({info[3]}/{info[4]}) - Cybersecurity Audit Tool - DGDI / DSSI")
                    elif len(info) >= 3:
                        self.title(f"Running: {info[2]} - Cybersecurity Audit Tool - DGDI / DSSI")
                else:
                    msg = info
                self.result_text.insert(tk.END, msg + "\n")
                self.result_text.see(tk.END)
                self.update_idletasks()
            self.result_text.after(0, update_ui)

        def audit_thread():
            try:
                results = run_full_audit(
                    target,
                    selected_modules=selected_modules,
                    stop_event=stop_event,
                    progress_callback=update_progress
                )

                module_scores = results.get("module_scores", results)
                self.final_score = results.get("final_score", 0.0)
                self.final_status = results.get("overall_status", "Unknown")

                self.final_report_data = [
                    {"module": name, **data} for name, data in module_scores.items()
                ]

                def update_results():
                    self.title("Cybersecurity Audit Tool - DGDI / DSSI")
                    self.result_text.insert("1.0", f"Final Score: {self.final_score:.2f} ({self.final_status})\n\n")
                    for item in self.final_report_data:
                        self.result_text.insert(tk.END, f"[{item['module']}] - {item.get('status', 'Unknown')}\n{item.get('details', '').strip()}\n\n")
                    self.progress["value"] = 100
                    self.enable_buttons()

                self.result_text.after(0, update_results)

            except Exception as e:
                def show_error():
                    self.title("Cybersecurity Audit Tool - DGDI / DSSI")
                    self.enable_buttons()
                    messagebox.showerror("Audit Error", f"Failed to complete audit:\n{e}")
                self.result_text.after(0, show_error)

        threading.Thread(target=audit_thread, daemon=True).start()

    def export_report(self):
        if not self.final_report_data:
            messagebox.showwarning("Export Error", "Run an audit before exporting a report.")
            return

        target = self.entry_target.get().strip()
        lang = "fr" if self.lang_var.get().lower().startswith("fr") else "en"
        fmt = self.export_format.get().lower()

        filename = filedialog.asksaveasfilename(defaultextension=f".{fmt}",
                                                filetypes=[(f"{fmt.upper()} files", f"*.{fmt}"), ("All files", "*.*")])
        if not filename:
            return

        cleaned_report_data = []
        for item in self.final_report_data:
            cleaned_item = {
                "module": item.get("module", "").strip(),
                "status": item.get("status", "Unknown").strip(),
                "score": round(item.get("score", 0.0), 2),
                "details": textwrap.fill(
                    item.get("details", "").strip().replace("\n\n\n", "\n\n").replace('\r', ''),
                    width=110
                )
            }
            if cleaned_item["module"]:
                cleaned_report_data.append(cleaned_item)

        try:
            exporters = {
                "txt": generate_txt_report,
                "json": generate_json_report,
                "html": generate_html_report,
                "pdf": generate_pdf_report,
            }
            if fmt in exporters:
                exporters[fmt](cleaned_report_data, target, self.hostname, lang, filename)
                messagebox.showinfo("Export Success", f"Report exported successfully to:\n{filename}")
            else:
                raise ValueError(f"Unsupported export format: {fmt}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{e}")

    def check_version(self):
        current_version = "1.1.1"
        version_info_url = "https://raw.githubusercontent.com/LepandSteve/Cyber-audit-tool/main/version.json"

        result = check_latest_version(current_version, version_info_url)
        if result["update_available"]:
            msg = f"{result['message']}\n\nDownload: {result['download_url']}"
            messagebox.showinfo("Update Available", msg)
        else:
            messagebox.showinfo("Version Check", result["message"])

    def run_auto_updater(self):
         run_auto_updater()
        
    def toggle_dark_mode(self):
        dark = self.current_theme == "light"
        self.current_theme = "dark" if dark else "light"
        bg = "#1e1e1e" if dark else "#f0f0f0"
        fg = "#e0e0e0" if dark else "black"
        txt_bg = "#121212" if dark else "white"
        txt_fg = fg
        self.configure(bg=bg)
        self.input_frame.configure(bg=bg)
        self.module_frame.configure(bg=bg)
        self.module_listbox.configure(bg=txt_bg, fg=txt_fg)
        self.result_text.configure(bg=txt_bg, fg=txt_fg, insertbackground=txt_fg)
        self.select_all_cb.configure(bg=bg, fg=fg, selectcolor="#333333" if dark else "white")

    def toggle_fullscreen(self, event=None):
        self.is_fullscreen = not self.is_fullscreen
        self.attributes("-fullscreen", self.is_fullscreen)

    def exit_fullscreen(self, event=None):
        self.is_fullscreen = False
        self.attributes("-fullscreen", False)

if __name__ == "__main__":
    app = CyberAuditGUI()
    app.mainloop()
