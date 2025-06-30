# modules/system_info.py
import platform
import socket
from typing import Optional, Dict


def get_primary_local_ip() -> str:
    """
    Retrieves the primary IP address of the host in a platform-safe way.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def is_local_ip(ip: str) -> bool:
    """
    Determine if the given IP refers to this local machine.
    """
    try:
        local_ips = ["127.0.0.1", "::1", get_primary_local_ip()]
        return ip in local_ips
    except Exception:
        return False


def get_system_info() -> str:
    """
    Gather basic system information.
    """
    try:
        info = [
            f"🖥️ Hostname     : {socket.gethostname()}",
            f"🧩 OS           : {platform.system()} {platform.release()}",
            f"🏗️ Architecture : {platform.machine()}",
            f"🧠 Processor    : {platform.processor()}",
            f"🌐 IP Address   : {get_primary_local_ip()}",
        ]
        return "\n".join(info)
    except Exception as e:
        return f"❌ Error fetching system info: {e}"


def run_audit(
    ip: Optional[str] = None,
    banners: Optional[list] = None,
    is_private: Optional[bool] = None,
    open_ports: Optional[list] = None,
    shared_data: Optional[dict] = None,  # 👈 Added to accept shared_data
) -> Dict:
    """
    Run the System Info audit. Only runs if the target IP is the local machine.
    """
    if not ip:
        return {
            "score": 0.0,
            "status": "Error",
            "details": "❌ No IP address provided for system info audit.",
            "remediation": "📥 Pass the local machine's IP address to run_audit(ip=...).",
        }

    if not is_local_ip(ip):
        return {
            "score": 10.0,
            "status": "Info",
            "details": (
                f"ℹ️ System Info audit skipped: {ip} is not recognized as a local IP.\n"
                "✅ This module is designed to collect host-level data only when auditing the local machine."
            ),
            "remediation": "🔁 Use 127.0.0.1 or the machine’s real IP to get system info from the local host.",
        }

    details = get_system_info()
    return {
        "score": 10.0,
        "status": "Pass",
        "details": details,
        "remediation": "🩺 Ensure your OS and all software components are regularly updated with the latest security patches.",
    }


if __name__ == "__main__":
    test_ip = "127.0.0.1"
    result = run_audit(ip=test_ip)
    print(f"Score: {result['score']}\nStatus: {result['status']}")
    print("Details:\n" + result["details"])
    print("Remediation:\n" + result["remediation"])
