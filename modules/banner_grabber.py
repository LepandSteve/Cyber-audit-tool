import socket
from utils.ip_utils import is_private_ip
from typing import Optional, List, Tuple


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a banner from a specific port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(1024).decode(errors='ignore').strip()
                return banner or "No banner received"
            except socket.timeout:
                return "No banner received (timeout)"
    except Exception as e:
        return f"Error grabbing banner: {e}"


def get_banners(ip: str, ports: Optional[List[int]] = None, timeout: float = 1.0) -> List[Tuple[int, str]]:
    """Return a list of (port, banner) tuples for the given IP and ports."""
    if ports is None:
        ports = [22, 80, 443, 3389]

    banners = []
    for port in ports:
        banner = grab_banner(ip, port, timeout)
        banners.append((port, banner))
    return banners


def get_remote_system_info(ip: str, common_ports: Optional[list] = None, timeout: float = 1.0) -> str:
    """Probe a set of common ports for additional banners and return formatted string."""
    if common_ports is None:
        common_ports = [22, 80, 443, 3389]

    info = []
    for port in common_ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                banner = sock.recv(1024).decode(errors='ignore').strip()
                if banner:
                    info.append(f"Port {port} banner: {banner}")
        except Exception:
            continue

    return "\n".join(info) if info else "No remote system info available from common ports."


def run_audit(
    ip: Optional[str] = None,
    banners=None,
    is_private: bool = False,
    open_ports=None,
    shared_data: Optional[dict] = None  # <-- Accept shared_data
) -> dict:
    """Banner-grabbing audit."""
    target = ip or "127.0.0.1"

    # Skip on private/internal IPs
    if is_private_ip(target) or is_private:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": f"ℹ️ Banner grabbing skipped for private/internal IP {target}.",
            "remediation": "✅ No action required. Run this check only on public IPs for meaningful banner analysis."
        }

    # Grab the HTTP banner on port 80
    banner = grab_banner(target, 80)

    # Probe additional common ports
    system_info = get_remote_system_info(target)

    details = (
        f"🛰️ Banner on port 80:\n{banner}\n\n"
        f"🔍 Remote System Info:\n{system_info}"
    )

    # Determine score and remediation
    if "Error" not in banner and "No banner received" not in banner:
        score = 10.0
        status = "Pass"
        remediation = "✅ No issues detected. Banner exposure is likely intentional for public-facing services."
    elif system_info and system_info != "No remote system info available from common ports.":
        score = 5.0
        status = "Warning"
        remediation = (
            "🔧 Remediation:\n"
            "- Limit service banner exposure via configuration.\n"
            "- Review exposed service details to reduce fingerprinting risks.\n"
            "- Disable or mask version strings where feasible."
        )
    else:
        score = 0.0
        status = "Fail"
        remediation = (
            "🔧 Remediation:\n"
            "- Ensure services are reachable and running.\n"
            "- If excessive hardening blocks visibility, ensure it aligns with audit requirements.\n"
            "- Check firewall/NAT rules and confirm open ports."
        )

    return {
        "score": score,
        "status": status,
        "details": details,
        "remediation": remediation
    }


if __name__ == "__main__":
    target_ip = "8.8.8.8"

    banners = get_banners(target_ip)
    print("Banners (port, banner):")
    for port, banner in banners:
        print(f"Port {port}: {banner}")

    result = run_audit(ip=target_ip)
    print(f"\nAudit Score: {result['score']}")
    print(f"Audit Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
