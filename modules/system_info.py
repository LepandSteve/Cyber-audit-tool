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


def get_local_system_info() -> str:
    """
    Gather basic system information for the local machine.
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
    shared_data: Optional[dict] = None,
) -> Dict:
    """
    Run the System Info audit.
    Shows local system details if IP is local; otherwise, reports hostname of remote target.
    """
    if not ip:
        return {
            "score": 0.0,
            "status": "Error",
            "details": "❌ No IP address provided for system info audit.",
            "remediation": "📥 Pass the local machine's IP address to run_audit(ip=...).",
        }

    if is_local_ip(ip):
        details = get_local_system_info()
        return {
            "score": 10.0,
            "status": "Pass",
            "details": details,
            "remediation": "🩺 Ensure your OS and all software components are regularly updated with the latest security patches.",
        }

    # For remote IPs, show hostname from shared_data if available
    hostname = ip
    if shared_data and "target_hostname" in shared_data:
        hostname = shared_data["target_hostname"]

    details = (
        f"ℹ️ System Info audit skipped: {ip} is not recognized as a local IP.\n"
        f"📡 Target Hostname: {hostname}\n"
        "✅ This module only collects host-level data on the local machine."
    )

    return {
        "score": 10.0,
        "status": "Info",
        "details": details,
        "remediation": "🔁 Use 127.0.0.1 or your own IP to audit system-level information on this machine.",
    }


if __name__ == "__main__":
    test_ip = "127.0.0.1"
    result = run_audit(ip=test_ip)
    print(f"Score: {result['score']}\nStatus: {result['status']}")
    print("Details:\n" + result["details"])
    print("Remediation:\n" + result["remediation"])
