"""
os_detection.py

Attempts to infer the target operating system based on service banners.
"""

from collections import Counter
from typing import List, Tuple, Optional, Dict

def detect_os_from_banners(banner_list: List[Tuple[int, str]]) -> Tuple[Optional[Tuple[str, int]], str]:
    """
    Analyze service banners to guess the most likely operating system.

    Args:
        banner_list: List of tuples (port, banner_string).

    Returns:
        A tuple:
          - Most common OS guess and its count, or None if no guess.
          - A human-readable details string.
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
    Audit entry point for OS detection based on service banners.

    Returns a dictionary with score, status, details, and remediation.
    """
    banner_list = banners or []

    try:
        most_common, details = detect_os_from_banners(banner_list)
    except Exception as e:
        return {
            "score": 4.0,
            "status": "Warning",
            "details": f"❗ Exception during OS detection: {e}",
            "remediation": (
                "Check banner data format and audit environment.\n"
                "Consider using active OS fingerprinting tools like nmap -O."
            )
        }

    if most_common is None:
        return {
            "score": 5.0,
            "status": "Info",
            "details": details,
            "remediation": (
                "⚠️ Unable to infer OS from available service banners.\n"
                "🔍 Use active OS fingerprinting (e.g., `nmap -O`) or increase banner verbosity."
            )
        }

    if most_common[0] == "Unknown":
        return {
            "score": 6.0,
            "status": "Info",
            "details": details,
            "remediation": (
                "⚠️ Service banners appear generic or intentionally obfuscated.\n"
                "💡 Consider relaxing banner restrictions during internal audits or use advanced fingerprinting."
            )
        }

    if most_common[1] >= 2:
        score = 10.0
        status = "Pass"
        remediation = "✅ OS consistently identified across multiple services. No further action needed."
    else:
        score = 8.0
        status = "Info"
        remediation = (
            "ℹ️ OS inferred from only one banner.\n"
            "🔍 Validate using complementary methods like SMB, SSH, RDP, or tools like Nmap."
        )

    return {
        "score": round(score, 2),
        "status": status,
        "details": details,
        "remediation": remediation
    }

if __name__ == "__main__":
    # Example usage
    test_banners = [
        (80, "Apache/2.4.41 (Ubuntu)"),
        (22, "OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"),
        (443, "nginx/1.18.0 (Ubuntu)")
    ]
    result = run_audit(banners=test_banners)
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
