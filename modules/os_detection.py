"""
os_detection.py

Attempts to infer the target operating system based on service banners and reverse DNS hostname.
"""

from collections import Counter
from typing import List, Tuple, Optional, Dict
from modules.reverse_DNS import reverse_dns_lookup  # ✅ Import reverse DNS
from utils.ip_utils import is_private_ip  # Ensure you have this to confirm IP type

def detect_os_from_banners(banner_list: List[Tuple[int, str]]) -> Tuple[Optional[Tuple[str, int]], str]:
    """
    Analyze service banners to guess the most likely operating system.
    """
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

def run_audit(
    ip: Optional[str] = None,
    banners: Optional[List[Tuple[int, str]]] = None,
    is_private: Optional[bool] = None,
    open_ports: Optional[List[int]] = None,
    shared_data: Optional[Dict] = None
) -> dict:
    """
    Audit entry point for OS detection based on service banners and optional reverse DNS enhancement.
    """
    banner_list = banners or []
    extra_note = ""

    if ip and not (is_private or (shared_data and shared_data.get("is_private")) or is_private_ip(ip)):
        try:
            dns_result = reverse_dns_lookup(ip)
            if dns_result["status"] == "Pass":
                hostname = dns_result["details"].split("→ Hostname:")[-1].strip()
                extra_note = f"🌐 Reverse DNS Suggests: {hostname}"

                # Try inferring OS from the hostname
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

    try:
        most_common, details = detect_os_from_banners(banner_list)
    except Exception as e:
        return {
            "score": 4.0,
            "status": "Warning",
            "details": f"❗ Exception during OS detection: {e}",
            "remediation": (
                "Check banner data format and audit environment.\n"
                "Consider using active OS fingerprinting tools like `nmap -O`."
            )
        }

    if extra_note:
        details += f"\n\n{extra_note}"

    if most_common is None or most_common[0] == "Unknown":
        return {
            "score": 6.0,
            "status": "Info",
            "details": details,
            "remediation": (
                "⚠️ Service banners appear generic or OS could not be identified.\n"
                "💡 Use active fingerprinting tools like Nmap (-O) or check reverse DNS manually."
            )
        }

    if most_common[1] >= 2:
        score = 10.0
        status = "Pass"
        remediation = "✅ OS consistently identified across multiple sources. No action needed."
    else:
        score = 8.0
        status = "Info"
        remediation = (
            "ℹ️ OS inferred from limited information.\n"
            "🔍 Consider verifying with SMB, SSH, RDP, or Nmap (-O)."
        )

    return {
        "score": round(score, 2),
        "status": status,
        "details": details,
        "remediation": remediation
    }

if __name__ == "__main__":
    test_banners = [
        (80, "Apache/2.4.41 (Ubuntu)"),
        (22, "OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"),
        (443, "nginx/1.18.0 (Ubuntu)")
    ]
    result = run_audit(ip="8.8.8.8", banners=test_banners)
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
