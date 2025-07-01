import requests
import os
import subprocess
from pathlib import Path
from tkinter import messagebox
from modules.version_checker import check_latest_version

APP_VERSION = "1.1.1"  # Change this for every new release
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

                # Save installer to user's Downloads folder
                downloads_dir = Path.home() / "Downloads"
                downloads_dir.mkdir(parents=True, exist_ok=True)
                installer_path = downloads_dir / "CyberAuditInstaller.exe"

                # Download the installer file
                with requests.get(download_url, stream=True) as r:
                    r.raise_for_status()
                    with open(installer_path, "wb") as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)

                # Confirm download success
                messagebox.showinfo("Installer Downloaded", f"Installer saved to: {installer_path}")

                # Launch installer in new process (must be done BEFORE we exit)
                subprocess.Popen(["start", "", str(installer_path)], shell=True)

                # Gracefully and safely exit app to avoid DLL loading issues
                os._exit(0)

            except Exception as e:
                messagebox.showerror("Update Error", f"❌ Failed to download or run installer:\n\n{e}")
    else:
        messagebox.showinfo("No Update", update_info["message"])
