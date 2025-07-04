import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

# Common ports to service names mapping for quick reference
COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy",
}

_target_ip: Optional[str] = None  # Holds the target IP address


def set_target_ip(ip: str) -> None:
    """Set the global target IP address."""
    global _target_ip
    _target_ip = ip


def grab_banner(ip: str, port: int, timeout: float = 2) -> str:
    """Try to retrieve a banner from an open port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(1024).decode(errors='ignore').strip()
                return banner if banner else "No banner received"
            except socket.timeout:
                return "No banner received (timeout)"
    except Exception:
        return "Error grabbing banner"


def scan_port(ip: str, port: int, timeout: float = 1) -> Optional[Tuple[int, str, str]]:
    """Check if a port is open and grab its banner if possible."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port, timeout)
                service = COMMON_PORTS.get(port, "Unknown Service")
                return port, service, banner
    except Exception:
        pass
    return None


def remote_port_activity(ip: str, ports: Optional[List[int]] = None) -> List[Tuple[int, str, str]]:
    """Scan for open ports and collect banners."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports: List[Tuple[int, str, str]] = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)

    for result in results:
        if result:
            open_ports.append(result)

    return open_ports


def run_audit(
    ip: Optional[str] = None,
    open_ports: Optional[List[int]] = None,
    **kwargs
) -> dict:
    """Run the remote port activity audit and return results."""
    global _target_ip
    if ip:
        _target_ip = ip

    if not _target_ip:
        return {
            "score": 0.0,
            "status": "Error",
            "details": "❌ No target IP set for Remote Port Activity.",
            "remediation": "Call `set_target_ip(ip)` or pass `ip` to `run_audit()`."
        }

    # Scan specified ports or default common ports
    if open_ports and all(isinstance(p, int) for p in open_ports):
        results = remote_port_activity(_target_ip, open_ports)
    else:
        results = remote_port_activity(_target_ip)

    if not results:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": f"✅ No common ports are open on {_target_ip}.",
            "remediation": "No action needed; the system is not exposing any common services."
        }

    # Format details for display
    details = f"🔎 Remote Port Activity for {_target_ip}:\n\n"
    for port, service, banner in sorted(results):
        details += f"🔸 Port {port} ({service}): OPEN\n"
        details += f"   → Banner: {banner}\n\n"

    # Scoring: deduct 0.5 per open port, minimum score 2.0
    score = max(2.0, 10.0 - len(results) * 0.5)
    status = "Warning" if score < 8.0 else "Pass"

    remediation = (
        "🔐 Review and restrict access to the following services:\n"
        + "\n".join(f"- Port {p} ({s})" for p, s, _ in results)
        + "\n\nRecommended Actions:\n"
        "- Close unused ports\n"
        "- Apply strict firewall or security group rules\n"
        "- Use strong authentication (e.g., SSH keys, MFA)\n"
        "- Limit access to sensitive services using VPN or internal-only exposure"
    )

    return {
        "score": round(score, 2),
        "status": status,
        "details": details.strip(),
        "remediation": remediation.strip()
    }


if __name__ == "__main__":
    test_ip = "8.8.8.8"
    set_target_ip(test_ip)
    result = run_audit()
    print(
        f"Score: {result['score']}\n"
        f"Status: {result['status']}\n"
        f"Details:\n{result['details']}\n"
        f"Remediation:\n{result['remediation']}"
    )
