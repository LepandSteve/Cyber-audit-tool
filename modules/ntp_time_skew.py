import socket
import struct
import time
from typing import Optional, Tuple, Dict
from utils.ip_utils import is_private_ip  # Make sure this is available

def get_ntp_time(host: str) -> Optional[int]:
    port = 123
    buf = 1024
    address = (host, port)
    msg = b'\x1b' + 47 * b'\0'

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5)
        client.sendto(msg, address)
        msg, _ = client.recvfrom(buf)
        if msg:
            t = struct.unpack("!12I", msg)[10]
            return t - 2208988800
    except Exception:
        return None

def ntp_time_skew_check(ip: str) -> Tuple[Optional[int], str]:
    try:
        remote_time = get_ntp_time(ip)
        if remote_time is None:
            return None, (
                "ℹ️ NTP Time Skew Check: Skipped or service unreachable.\n"
                "🔧 Remediation: Ensure the NTP service is running and accessible on the remote host."
            )

        local_time = int(time.time())
        skew = abs(local_time - remote_time)

        if skew > 300:
            status_line = "⚠️ Significant time difference detected (possible VM, proxy, or sync issue)"
        else:
            status_line = "✅ Time is reasonably synchronized"

        details = (
            f"🕒 NTP Time Skew Check:\n"
            f"- Local Time:  {time.ctime(local_time)}\n"
            f"- Remote Time: {time.ctime(remote_time)}\n"
            f"- Time Skew:   {skew} seconds\n"
            f"- {status_line}"
        )
        return skew, details

    except Exception as e:
        return None, (
            f"ℹ️ NTP Time Skew Check: Skipped or failed due to internal error.\n"
            f"Error: {e}\n"
            "🔧 Remediation: Verify network connectivity and socket permissions."
        )

def run_audit(
    ip: Optional[str] = None,
    banners=None,
    open_ports=None,
    is_private: Optional[bool] = None,
    shared_data=None
) -> Dict:
    """
    Run the NTP time skew audit.
    """
    ip = ip or "time.google.com"

    if is_private or is_private_ip(ip):
        return {
            "score": 10.0,
            "status": "Info",
            "details": (
                f"🛡️ Skipped NTP check for internal/private IP: {ip}\n"
                "✅ Internal hosts are not expected to expose NTP publicly."
            ),
            "remediation": "No action needed for private/internal IP addresses."
        }

    skew, details = ntp_time_skew_check(ip)

    if skew is None:
        score = 5.0
        status = "Warning"
        remediation = (
            "⚠️ Unable to determine NTP time skew.\n"
            "📡 Check if the NTP service is enabled on the remote host.\n"
            "🔐 Ensure firewall rules allow UDP port 123."
        )
    elif skew <= 300:
        score = 10.0
        status = "Pass"
        remediation = "✅ No action required. System time appears well synchronized."
    else:
        score = 5.0
        status = "Warning"
        remediation = (
            "⚠️ Large time skew detected.\n"
            "🕹️ Ensure the host uses a valid and accurate NTP source.\n"
            "🔍 Check for virtualization-induced clock drift or proxy use."
        )

    return {
        "score": score,
        "status": status,
        "details": details,
        "remediation": remediation
    }

if __name__ == "__main__":
    result = run_audit(ip="pool.ntp.org")
    print(
        f"Score: {result['score']}\n"
        f"Status: {result['status']}\n"
        f"Details:\n{result['details']}\n"
        f"Remediation:\n{result['remediation']}"
    )
