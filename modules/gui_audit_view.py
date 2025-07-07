import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import textwrap
import threading
import os
import sys
from PIL import Image, ImageTk

from modules.standard_audit.report import (
    generate_txt_report,
    generate_html_report,
    generate_json_report,
    generate_pdf_report,
)
from modules.standard_audit.runner import run_full_audit

MODULE_GROUPS = {
    "System & OS": ["system_info", "os_detection", "firewall_check", "antivirus_check"],
    "Network & Ports": ["network_scan", "port_check", "remote_port_activity"],
    "Security Checks": ["credential_check", "brute_force_exposure", "public_exposure", "service_security", "weak_protocols"],
    "Web & HTTP": ["http_headers_check", "tls_inspector", "banner_grabber"],
    "Geolocation": ["ip_geolocation", "geoip_lookup"],
    "Analysis & Lookup": ["whois_lookup", "reverse_DNS", "cve_lookup", "vulnerability_scanner", "ntp_time_skew"]
}

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class AuditView(tk.Frame):
    def __init__(self, parent, hostname, dark_mode=False):
        super().__init__(parent)
        self.hostname = hostname
        self.dark_mode_enabled = dark_mode
        self.current_theme = "dark" if dark_mode else "light"
        self.audit_results = {}
        self.shared_data = {}
        self.final_report_data = []
        self.listbox_indices_headers = []

        self.bg = "#1e1e1e" if self.dark_mode_enabled else "#f0f0f0"
        self.fg = "#e0e0e0" if self.dark_mode_enabled else "black"
        self.txt_bg = "#121212" if self.dark_mode_enabled else "white"
        self.txt_fg = self.fg

        self.configure(bg=self.bg)
        self.setup_styles()
        self.create_widgets()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        if self.dark_mode_enabled:
            self.style.configure("Dark.TCombobox",
                                 fieldbackground=self.txt_bg,
                                 background=self.txt_bg,
                                 foreground=self.txt_fg)
            self.style.configure("Dark.TLabelframe",
                                 background=self.bg,
                                 foreground=self.fg)
            self.style.configure("Dark.TLabelframe.Label",
                                 background=self.bg,
                                 foreground=self.fg)
            self.style.configure("Dark.TScrollbar",
                                 background=self.txt_bg)
        else:
            self.style.configure("Light.TCombobox",
                                 fieldbackground="white",
                                 background="white",
                                 foreground="black")
            self.style.configure("Light.TLabelframe",
                                 background=self.bg,
                                 foreground=self.fg)
            self.style.configure("Light.TLabelframe.Label",
                                 background=self.bg,
                                 foreground=self.fg)
            self.style.configure("Light.TScrollbar",
                                 background="white")

    def create_widgets(self):
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
            tk.Label(self, image=self.logo_image, bg=self.bg).pack(pady=10)
        except Exception as e:
            print(f"[Warning] Logo not loaded: {e}")

    def build_input_frame(self):
        self.input_frame = tk.Frame(self, bg=self.bg)
        self.input_frame.pack(pady=10, fill=tk.X)

        def lbl(text): return tk.Label(self.input_frame, text=text, bg=self.bg, fg=self.fg, font=("Segoe UI", 10))

        lbl("Target IP / Hostname:").grid(row=0, column=0, padx=8, pady=5, sticky="w")
        self.entry_target = tk.Entry(self.input_frame, width=30, font=("Segoe UI", 10),
                                     bg=self.txt_bg, fg=self.txt_fg, insertbackground=self.txt_fg)
        self.entry_target.grid(row=0, column=1, padx=5)

        lbl("Language:").grid(row=0, column=2, padx=8)
        self.lang_var = tk.StringVar(value="English")
        ttk.Combobox(self.input_frame, textvariable=self.lang_var,
                     values=["English", "French"], width=10,
                     style="Dark.TCombobox" if self.dark_mode_enabled else "Light.TCombobox").grid(row=0, column=3)

        lbl("Export Format:").grid(row=0, column=4, padx=8)
        self.export_format = tk.StringVar(value="pdf")
        ttk.Combobox(self.input_frame, textvariable=self.export_format,
                     values=["txt", "json", "html", "pdf"], width=10,
                     style="Dark.TCombobox" if self.dark_mode_enabled else "Light.TCombobox").grid(row=0, column=5)

    def build_module_frame(self):
        style_name = "Dark.TLabelframe" if self.dark_mode_enabled else "Light.TLabelframe"
        self.module_frame = ttk.LabelFrame(self, text="Select Modules to Run", style=style_name)
        self.module_frame.pack(padx=20, pady=10, fill=tk.BOTH)
        self.module_frame.configure(style=style_name)

        self.module_listbox = tk.Listbox(self.module_frame, selectmode=tk.MULTIPLE, width=50, height=16,
                                         font=("Segoe UI", 9), bg=self.txt_bg, fg=self.txt_fg, selectbackground="#666666")
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
                                            command=self.toggle_select_all, bg=self.bg, fg=self.fg,
                                            selectcolor=self.txt_bg)
        self.select_all_cb.pack(anchor="w", padx=10)
        self.toggle_select_all()

    def build_button_frame(self):
        btn_frame = tk.Frame(self, bg=self.bg)
        btn_frame.pack(pady=10)

        def add_button(text, cmd, bg, fg="white", width=14):
            return tk.Button(btn_frame, text=text, command=cmd, bg=bg, fg=fg,
                             font=("Segoe UI", 10, "bold"), width=width)

        self.btn_start = add_button("Start Audit", self.perform_audit, "#4caf50")
        self.btn_export = add_button("Export Report", self.export_report, "#2196f3")

        self.btn_start.pack(side=tk.LEFT, padx=8)
        self.btn_export.pack(side=tk.LEFT, padx=8)

        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate", length=800)
        self.progress.pack(pady=10)

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
        for widget in [self.btn_start, self.btn_export,
                       self.module_listbox, self.select_all_cb, self.entry_target]:
            widget.config(state=tk.DISABLED)

    def enable_buttons(self):
        for widget in [self.btn_start, self.btn_export,
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
                    self.result_text.insert("1.0", f"Final Score: {self.final_score:.2f} ({self.final_status})\n\n")
                    for item in self.final_report_data:
                        self.result_text.insert(tk.END, f"[{item['module']}] - {item.get('status', 'Unknown')}\n{item.get('details', '').strip()}\n\n")
                    self.progress["value"] = 100
                    self.enable_buttons()

                self.result_text.after(0, update_results)

            except Exception as e:
                def show_error():
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
                "details": textwrap.fill(item.get("details", "").strip(), width=110)
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

    def build_result_display(self):
        result_frame = tk.Frame(self, bg=self.bg)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.result_text = tk.Text(result_frame, wrap=tk.WORD, font=("Consolas", 10),
                                   bg=self.txt_bg, fg=self.txt_fg,
                                   insertbackground=self.txt_fg, undo=True)
        scroll = ttk.Scrollbar(result_frame, command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scroll.set)

        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
