import platform
import subprocess
from typing import Optional, Tuple, Dict

def is_remote_mode(ip: Optional[str], is_private: Optional[bool]) -> bool:
    return ip is not None and not is_private and ip != "127.0.0.1"

def check_antivirus_status_local() -> Tuple[Optional[bool], str, str]:
    system = platform.system()

    try:
        if system == "Windows":
            result = subprocess.run(
                ["wmic", "/namespace:\\\\root\\SecurityCenter2", "path", "AntivirusProduct", "get", "displayName,productState"],
                capture_output=True, text=True, check=True
            )
            output = result.stdout.strip()
            if "AntivirusProduct" in output and output:
                return True, f"🛡️ Antivirus Status (Windows):\n{output}", "✅ No action needed."
            else:
                return False, "❌ No antivirus product detected on Windows.", (
                    "🔧 Remediation:\n"
                    "- Install and enable a trusted antivirus solution, such as:\n"
                    "  • Microsoft Defender (built-in)\n"
                    "  • Avast, Bitdefender, or a similar tool"
                )

        elif system == "Linux":
            result = subprocess.run(["systemctl", "is-active", "clamav-daemon"], capture_output=True, text=True)
            status = result.stdout.strip()
            if status == "active":
                return True, "🛡️ ClamAV Status: Active ✅", "✅ No action needed."
            else:
                return False, "❌ ClamAV Status: Inactive ❌", (
                    "🔧 Remediation:\n"
                    "- Install and activate ClamAV:\n"
                    "  • `sudo apt install clamav`\n"
                    "  • `sudo systemctl start clamav-daemon`"
                )

        elif system == "Darwin":
            return None, (
                "🛡️ macOS antivirus status cannot be verified via command-line tools.\n"
                "Use system preferences or trusted third-party tools."
            ), (
                "🔧 Remediation:\n"
                "- Install a reputable macOS antivirus such as:\n"
                "  • Malwarebytes, Norton, or equivalent\n"
                "- Verify status via System Preferences or the AV software UI."
            )

        else:
            return None, (
                f"🛡️ Antivirus status check not supported on {system}."
            ), (
                "🔧 Remediation:\n"
                "- Use OS-specific antivirus tools that support CLI or API.\n"
                "- Consider manual inspection or third-party monitoring solutions."
            )

    except subprocess.CalledProcessError as e:
        return False, f"❌ Error checking antivirus: {e}", (
            "🔧 Remediation:\n"
            "- Ensure antivirus tools are installed.\n"
            "- Run script with elevated privileges if needed."
        )

    except FileNotFoundError:
        return False, "❌ Required antivirus tools not found on this system.", (
            "🔧 Remediation:\n"
            "- Make sure antivirus software is installed and accessible in your system PATH."
        )

def run_audit(
    ip: Optional[str] = None,
    banners: Optional[list] = None,
    is_private: Optional[bool] = None,
    open_ports: Optional[list] = None,
    shared_data: Optional[dict] = None
) -> Dict:
    try:
        if is_remote_mode(ip, is_private):
            return {
                "score": 5.0,
                "status": "Warning",
                "details": (
                    "🌐 Remote system antivirus status cannot be directly verified.\n"
                    "However, indirect signs like filtered ports or security banners may suggest antivirus presence."
                ),
                "remediation": (
                    "🔍 Attempt banner grabbing or OS fingerprinting for more context.\n"
                    "🛡️ Ensure endpoint protection is installed and actively monitoring remote hosts."
                )
            }

        detected, details, remediation = check_antivirus_status_local()

        if detected is True:
            return {
                "score": 10.0,
                "status": "Pass",
                "details": details,
                "remediation": remediation
            }
        elif detected is False:
            return {
                "score": 0.0,
                "status": "Fail",
                "details": details,
                "remediation": remediation
            }
        else:
            # Changed from Warning to Info when detection is inconclusive
            return {
                "score": 5.0,
                "status": "Info",
                "details": details,
                "remediation": remediation
            }

    except Exception as e:
        return {
            "score": 0.0,
            "status": "Error",
            "details": f"❌ Exception occurred during antivirus check: {str(e)}",
            "remediation": (
                "🔧 Make sure the script is compatible with your OS and has permission to execute system commands.\n"
                "Check for missing dependencies or tools."
            )
        }


if __name__ == "__main__":
    result = run_audit()
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
