# modules/gui_ad_audit_view.py

import tkinter as tk
from tkinter import ttk, messagebox
from modules.AD_audit import runner as ad_runner

AD_MODULES = {
    "ad_enum": "AD Enumeration",
    "kerberos_check": "Kerberos Check",
    "group_policy_check": "Group Policy Check",
    "password_policy": "Password Policy",
    "privileged_users": "Privileged Users",
    "account_lockout": "Account Lockout Policy",
    "inactive_accounts": "Inactive Accounts",
    "service_accounts": "Service Accounts",
}

class ADAuditView(ttk.Frame):
    def __init__(self, parent, hostname=None):
        super().__init__(parent)
        self.hostname = hostname
        self.selected_modules = {}
        self.progress_label = None
        self.progress_bar = None
        self.results_text = None
        self.final_score_label = None

        self.create_widgets()

    def create_widgets(self):
        # AD Credential Inputs
        creds_frame = ttk.LabelFrame(self, text="LDAP Credentials")
        creds_frame.pack(fill="x", padx=10, pady=10)

        self.server_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()

        ttk.Label(creds_frame, text="Server:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(creds_frame, textvariable=self.server_var, width=40).grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(creds_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(creds_frame, textvariable=self.user_var, width=40).grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(creds_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(creds_frame, textvariable=self.pass_var, show="*", width=40).grid(row=2, column=1, padx=5, pady=2)

        # Module Selection
        modules_frame = ttk.LabelFrame(self, text="Select AD Audit Modules")
        modules_frame.pack(fill="x", padx=10, pady=10)

        for idx, (mod_key, mod_label) in enumerate(AD_MODULES.items()):
            var = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(modules_frame, text=mod_label, variable=var)
            chk.grid(row=idx // 2, column=idx % 2, sticky="w", padx=5, pady=2)
            self.selected_modules[mod_key] = var

        # Run Button
        run_btn = ttk.Button(self, text="Run AD Audit", command=self.run_ad_audit)
        run_btn.pack(pady=10)

        # Progress Bar and Label
        self.progress_label = ttk.Label(self, text="Progress: Idle")
        self.progress_label.pack()

        self.progress_bar = ttk.Progressbar(self, length=400, mode='determinate')
        self.progress_bar.pack(pady=5)

        # Final Score
        self.final_score_label = ttk.Label(self, text="", font=("Segoe UI", 11, "bold"))
        self.final_score_label.pack(pady=5)

        # Results Text Box
        self.results_text = tk.Text(self, height=20, wrap="word")
        self.results_text.pack(fill="both", expand=True, padx=10, pady=10)

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
