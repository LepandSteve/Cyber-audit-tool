import requests
import os
import sys
import subprocess
import tempfile
from pathlib import Path
from tkinter import messagebox
from modules.standard_audit.version_checker import check_latest_version

APP_VERSION = "2.1.0"  # Update this on each release
VERSION_URL = "https://raw.githubusercontent.com/LepandSteve/Cyber-audit-tool/main/version.json"

def run_auto_updater():
    update_info = check_latest_version(APP_VERSION, VERSION_URL)
    print(f"Current app version: {APP_VERSION}")
    print(f"Latest version from server: {update_info.get('latest_version')}")
    print(f"Update available? {update_info.get('update_available')}")

    if update_info["update_available"]:
        proceed = messagebox.askyesno(
            "Update Available",
            f"{update_info['message']}\n\nDo you want to download and install it now?"
        )
        if proceed:
            try:
                download_url = update_info["download_url"]
                if not download_url:
                    raise Exception("No download URL provided.")

                # ✅ Download to Downloads folder
                downloads_dir = Path.home() / "Downloads"
                downloads_dir.mkdir(parents=True, exist_ok=True)
                installer_path = downloads_dir / "CyberAuditInstaller.exe"

                # ✅ Download the installer file
                with requests.get(download_url, stream=True) as r:
                    r.raise_for_status()
                    with open(installer_path, "wb") as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)

                # ✅ Create a temporary Python script that launches the installer after delay
                temp_script = tempfile.NamedTemporaryFile(delete=False, suffix=".py")
                temp_script.write(f"""
import time
import subprocess

time.sleep(3)  # Wait a bit for the current app to fully exit
subprocess.run(["{installer_path}"], shell=True)
""".encode('utf-8'))
                temp_script.close()

                # ✅ Launch the temp script with system Python
                subprocess.Popen(["python", temp_script.name], shell=True)

                # ✅ Exit the current app
                messagebox.showinfo("Installer Starting", "Installer will launch shortly. Please follow the on-screen instructions.")
                sys.exit(0)

            except Exception as e:
                messagebox.showerror("Update Error", f"Failed to download or run installer:\n{e}")
    else:
        messagebox.showinfo("No Update", update_info["message"])

def download_and_execute_latest_release():
    """Wrapper for GUI to trigger update."""
    try:
        run_auto_updater()
        return True
    except Exception as e:
        print(f"[Updater Error] {e}")
        return False
