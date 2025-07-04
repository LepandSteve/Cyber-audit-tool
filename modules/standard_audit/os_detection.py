import subprocess
from collections import Counter
from typing import List, Tuple, Optional, Dict
from modules.standard_audit.reverse_DNS import reverse_dns_lookup
from utils.ip_utils import is_private_ip

def detect_os_from_banners(banner_list: List[Tuple[int, str]]) -> Tuple[Optional[Tuple[str, int]], str]:
    os_guesses = []

    for port, banner in banner_list:
        banner_lower = banner.lower()
        if "windows" in banner_lower or "microsoft-iis" in banner_lower:
            os_guesses.append("Windows Server")
        elif "ubuntu" in banner_lower:
            os_guesses.append("Linux (Ubuntu)")
        elif "debian" in banner_lower:
            os_guesses.append("Linux (Debian)")
        elif "centos" in banner_lower:
            os_guesses.append("Linux (CentOS)")
        elif "red hat" in banner_lower or "rhel" in banner_lower:
            os_guesses.append("Linux (Red Hat)")
        elif "freebsd" in banner_lower:
            os_guesses.append("FreeBSD")
        elif "mac os" in banner_lower or "darwin" in banner_lower:
            os_guesses.append("macOS")
        elif "linux" in banner_lower or "unix" in banner_lower:
            os_guesses.append("Generic Linux/Unix")
        else:
            os_guesses.append("Unknown")

    if not os_guesses:
        return None, "❓ Could not determine operating system from service banners."

    most_common = Counter(os_guesses).most_common(1)[0]
    return most_common, f"🖥️ Likely Operating System: {most_common[0]} (detected {most_common[1]} time(s))"

def run_nmap_os_fingerprint(ip: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["nmap", "-O", "-Pn", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=45,
            check=True
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "⏰ OS detection with Nmap timed out."
    except FileNotFoundError:
        return "❌ Nmap not found. Install it and ensure it’s in your PATH."
    except subprocess.CalledProcessError as e:
        return e.stderr.strip() or e.stdout.strip()
    except Exception as e:
        return f"❌ Unexpected error: {e}"

def run_audit(
    ip: Optional[str] = None,
    banners: Optional[List[Tuple[int, str]]] = None,
    is_private: Optional[bool] = None,
    open_ports: Optional[List[int]] = None,
    shared_data: Optional[Dict] = None
) -> dict:
    banner_list = banners or []
    extra_note = ""
    active_result = ""
    os_from_nmap = None

    if ip and not (is_private or (shared_data and shared_data.get("is_private")) or is_private_ip(ip)):
        try:
            dns_result = reverse_dns_lookup(ip)
            if dns_result["status"] == "Pass":
                hostname = dns_result["details"].split("→ Hostname:")[-1].strip()
                extra_note = f"🌐 Reverse DNS Suggests: {hostname}"

                hostname_lower = hostname.lower()
                if "windows" in hostname_lower:
                    banner_list.append((0, "Windows Reverse DNS"))
                elif "ubuntu" in hostname_lower:
                    banner_list.append((0, "Ubuntu Reverse DNS"))
                elif "linux" in hostname_lower:
                    banner_list.append((0, "Linux Reverse DNS"))
                elif "centos" in hostname_lower:
                    banner_list.append((0, "CentOS Reverse DNS"))
        except Exception as e:
            extra_note = f"⚠️ Reverse DNS check failed: {e}"

    # 🔍 Try Nmap -O
    if ip:
        active_result = run_nmap_os_fingerprint(ip)
        if shared_data is not None:
            shared_data["os_nmap_output"] = active_result

        if "OS details:" in active_result:
            lines = active_result.splitlines()
            os_lines = [line.strip() for line in lines if line.strip().startswith("OS details:")]
            if os_lines:
                os_from_nmap = os_lines[0].replace("OS details: ", "").strip()

    try:
        most_common, banner_details = detect_os_from_banners(banner_list)
    except Exception as e:
        return {
            "score": 4.0,
            "status": "Warning",
            "details": f"❗ Exception during OS detection: {e}",
            "remediation": "💡 Check banners and consider enabling active detection (Nmap -O)."
        }

    details = ""

    if os_from_nmap:
        details += f"🧠 Active OS Detection (Nmap): {os_from_nmap}\n\n"
    else:
        details += banner_details + "\n\n"

    if extra_note:
        details += extra_note + "\n"

    remediation = (
        "🔍 Consider verifying OS using multiple techniques.\n"
        "- Enable banner grabbing on all services\n"
        "- Allow Nmap OS scan permissions (root/admin)\n"
        "- Use reverse DNS + known fingerprint tools"
    )

    if os_from_nmap:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": details.strip(),
            "remediation": "✅ OS identified successfully with active fingerprinting."
        }
    elif most_common is None or most_common[0] == "Unknown":
        return {
            "score": 6.0,
            "status": "Info",
            "details": details.strip(),
            "remediation": "⚠️ Unable to determine OS confidently. Use Nmap (-O) or verify manually."
        }
    else:
        score = 8.0 if most_common[1] < 2 else 10.0
        status = "Info" if score < 10 else "Pass"
        return {
            "score": score,
            "status": status,
            "details": details.strip(),
            "remediation": remediation
        }

if __name__ == "__main__":
    banners = [
        (80, "Apache/2.4.41 (Ubuntu)"),
        (22, "OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"),
    ]
    res = run_audit(ip="8.8.8.8", banners=banners)
    print(f"Score: {res['score']}")
    print(f"Status: {res['status']}")
    print(f"Details:\n{res['details']}")
    print(f"Remediation:\n{res['remediation']}")
