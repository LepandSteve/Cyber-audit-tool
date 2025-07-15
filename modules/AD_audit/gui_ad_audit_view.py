import tkinter as tk
from tkinter import ttk, messagebox
from modules.AD_audit import runner as ad_runner
from modules.standard_audit import report
AD_MODULES = {
    "ad_enum": "AD Enumeration",
    "kerberos_check": "Kerberos Check",
    "group_policy_check": "Group Policy Check",
    "password_policy": "Password Policy",
    "privileged_users": "Privileged Users",
    "account_lockout": "Account Lockout Policy",
    "inactive_accounts": "Inactive Accounts",
    "service_accounts": "Service Accounts",
    "admin_group_check": "Admin Group Membership Check",
    "delegation_check": "Delegation Rights Check",
    "password_expiry": "Password Expiry Analysis",
    "spn_exposure": "SPN Exposure Check",
    "ou_delegation": "OU Delegation Rights Check",
    "domain_trust": "Domain Trusts",
    "gpo_link_check": "GPO Link Validation",
}

class ADAuditView(tk.Frame):
    def __init__(self, parent, hostname=None, dark_mode=False):
        super().__init__(parent)
        self.hostname = hostname
        self.selected_modules = {}
        self.progress_label = None
        self.progress_bar = None
        self.results_text = None
        self.final_score_label = None
        self.dark_mode = dark_mode
        self.ad_audit_results = None
        self.language = "English"

        # Theme Colors
        self.bg = "#1e1e1e" if self.dark_mode else "#f0f0f0"
        self.fg = "#e0e0e0" if self.dark_mode else "black"
        self.txt_bg = "#121212" if self.dark_mode else "white"
        self.txt_fg = self.fg

        self.configure(bg=self.bg)
        self.setup_styles()
        self.create_widgets()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        if self.dark_mode:
            self.style.configure("Dark.TLabelframe", background=self.bg, foreground=self.fg)
            self.style.configure("Dark.TLabelframe.Label", background=self.bg, foreground=self.fg)
            self.style.configure("Dark.TScrollbar", background=self.txt_bg)
            self.style.configure("Dark.Horizontal.TProgressbar", troughcolor=self.bg, background="#4caf50")
        else:
            self.style.configure("Light.TLabelframe", background=self.bg, foreground=self.fg)
            self.style.configure("Light.TLabelframe.Label", background=self.bg, foreground=self.fg)
            self.style.configure("Light.TScrollbar", background="white")
            self.style.configure("Light.Horizontal.TProgressbar", troughcolor=self.bg, background="#4caf50")

    def create_widgets(self):
        # LDAP Credentials Frame
        creds_frame = ttk.LabelFrame(self, text="LDAP Credentials",
                                     style="Dark.TLabelframe" if self.dark_mode else "Light.TLabelframe")
        creds_frame.pack(fill="x", padx=10, pady=10)

        self.server_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()

        def lbl(parent, text, row):
            tk.Label(parent, text=text, bg=self.bg, fg=self.fg, font=("Segoe UI", 9)).grid(row=row, column=0, sticky="w", padx=5, pady=2)

        def entry(parent, var, row, show=None):
            tk.Entry(parent, textvariable=var, width=40, show=show, bg=self.txt_bg, fg=self.txt_fg,
                     insertbackground=self.txt_fg).grid(row=row, column=1, padx=5, pady=2)

        lbl(creds_frame, "Server:", 0)
        entry(creds_frame, self.server_var, 0)

        lbl(creds_frame, "Username:", 1)
        entry(creds_frame, self.user_var, 1)

        lbl(creds_frame, "Password:", 2)
        entry(creds_frame, self.pass_var, 2, show="*")

        # Module Selection
        modules_frame = ttk.LabelFrame(self, text="Select AD Audit Modules",
                                       style="Dark.TLabelframe" if self.dark_mode else "Light.TLabelframe")
        modules_frame.pack(fill="x", padx=10, pady=10)

        for idx, (mod_key, mod_label) in enumerate(AD_MODULES.items()):
            var = tk.BooleanVar(value=True)
            chk = tk.Checkbutton(modules_frame, text=mod_label, variable=var,
                                 bg=self.bg, fg=self.fg, selectcolor=self.txt_bg,
                                 anchor="w", font=("Segoe UI", 9))
            chk.grid(row=idx // 2, column=idx % 2, sticky="w", padx=5, pady=2)
            self.selected_modules[mod_key] = var

        # Run Button
        run_btn = tk.Button(self, text="Run AD Audit", command=self.run_ad_audit, bg="#4caf50", fg="white",
                            font=("Segoe UI", 10, "bold"))
        run_btn.pack(pady=10)

        # Progress Label
        self.progress_label = tk.Label(self, text="Progress: Idle", bg=self.bg, fg=self.fg, font=("Segoe UI", 9))
        self.progress_label.pack()

        # Progress Bar
        self.progress_bar = ttk.Progressbar(self, length=400, mode='determinate',
                                            style="Dark.Horizontal.TProgressbar" if self.dark_mode else "Light.Horizontal.TProgressbar")
        self.progress_bar.pack(pady=5)

        # Final Score
        self.final_score_label = tk.Label(self, text="", font=("Segoe UI", 11, "bold"), bg=self.bg, fg=self.fg)
        self.final_score_label.pack(pady=5)

        # Results Text Box
        result_frame = tk.Frame(self, bg=self.bg)
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.results_text = tk.Text(result_frame, height=20, wrap="word",
                                    bg=self.txt_bg, fg=self.txt_fg,
                                    insertbackground=self.txt_fg)
        scroll = ttk.Scrollbar(result_frame, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scroll.set)

        self.results_text.pack(side=tk.LEFT, fill="both", expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Export Button
        export_btn = tk.Button(
            self, text="📁 Export Report", command=self.export_report,
            bg="#f39c12", fg="white", font=("Segoe UI", 10, "bold")
        )
        export_btn.pack(pady=(5, 10))


    def update_progress(self, info):
        message, percent, module_name, current, total = info
        self.progress_label.config(text=message)
        self.progress_bar['value'] = percent
        self.update_idletasks()

    def run_ad_audit(self):
        server = self.server_var.get().strip()
        username = self.user_var.get().strip()
        password = self.pass_var.get().strip()

        if not server or not username or not password:
            messagebox.showerror("Missing Credentials", "Please fill in all LDAP credentials.")
            return

        selected_keys = [k for k, v in self.selected_modules.items() if v.get()]
        if not selected_keys:
            messagebox.showerror("No Modules", "Please select at least one audit module.")
            return

        self.results_text.delete("1.0", tk.END)
        self.final_score_label.config(text="")

        try:
            results = ad_runner.run_full_ad_audit(
                ldap_server=server,
                ldap_username=username,
                ldap_password=password,
                selected_modules=selected_keys,
                progress_callback=self.update_progress
            )
            self.ad_audit_results = results  # Store results for potential export

            self.final_score_label.config(
                text=f"✅ Final Score: {results['final_score']} | Status: {results['overall_status']}"
            )

            for mod, data in results["module_scores"].items():
                self.results_text.insert(tk.END, f"🔹 {AD_MODULES.get(mod, mod)}:\n")
                self.results_text.insert(tk.END, f"   - Status: {data['status']}\n")
                self.results_text.insert(tk.END, f"   - Score:  {data['score']}\n")
                self.results_text.insert(tk.END, f"   - Details:\n{data['details']}\n")
                self.results_text.insert(tk.END, f"   - Remediation:\n{data['remediation']}\n")
                self.results_text.insert(tk.END, "-" * 60 + "\n\n")

        except Exception as e:
            messagebox.showerror("Audit Error", f"An error occurred:\n{e}")

    def export_report(self):
        if not self.ad_audit_results:
            messagebox.showwarning("No Results", "Please run the audit before exporting.")
            return

        try:
            report.generate_report(
                results=self.ad_audit_results,
                hostname=self.hostname or "localhost",
                report_type="AD Audit",
                language=self.language  # default: English
            )
            messagebox.showinfo("Export Complete", "✅ Report successfully exported.")
        except Exception as e:
            messagebox.showerror("Export Error", f"❌ Failed to export report:\n{e}")

