import socket
from concurrent.futures import ThreadPoolExecutor
from modules.banner_grabber import grab_banner
from typing import List, Optional, Tuple

_target_ip: Optional[str] = None
_is_private: bool = False
MIN_SCORE = 2.0
DEFAULT_TIMEOUT = 0.5

RISKY_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 445, 3389, 5900, 8080]

def set_target_ip(ip: str) -> None:
    global _target_ip
    _target_ip = ip

def set_is_private(flag: bool) -> None:
    global _is_private
    _is_private = flag

def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Optional[Tuple[int, str]]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port)
                return port, (banner.strip() if banner else '')
    except Exception:
        pass
    return None

def remote_port_scan(
    ip: str,
    ports: Optional[List[int]] = None,
    stop_event=None,
    progress_callback=None,
    timeout: float = DEFAULT_TIMEOUT
) -> List[Tuple[int, str]]:
    if ports is None:
        default_ports = [p for p in range(1, 201) if p not in RISKY_PORTS]
        ports = RISKY_PORTS + default_ports

    open_ports: List[Tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        count = 0
        last_update = 0
        total_ports = len(ports)

        for future in futures:
            if stop_event and stop_event.is_set():
                if progress_callback:
                    progress_callback("Port scan cancelled.")
                break

            result = future.result()
            count += 1

            if result:
                open_ports.append(result)

            if progress_callback and (count - last_update >= 10 or count == total_ports):
                progress_callback(f"Scanned {count}/{total_ports} ports...")
                last_update = count

    return open_ports

def run_audit(
    ip: Optional[str] = None,
    banners: Optional[dict] = None,
    is_private: Optional[bool] = None,
    open_ports: Optional[List[Tuple[int, str]]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    shared_data: Optional[dict] = None,
) -> dict:
    ip = ip or _target_ip
    is_private = is_private if is_private is not None else _is_private

    if ip is None:
        return {
            "score": 0.0,
            "status": "Error",
            "details": "❗ No target IP specified for port scan.",
            "remediation": "Set target IP using set_target_ip() before running audit."
        }

    if open_ports is None:
        open_ports = remote_port_scan(ip, timeout=timeout)

    if not open_ports:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": f"✅ No open ports found on {ip}.",
            "remediation": "No action needed. System has no exposed open ports."
        }

    score = max(MIN_SCORE, 10.0 - len(open_ports) * 0.5)
    status = "Warning" if len(open_ports) > 5 else "Info"

    details = f"🔍 Open Ports Detected on {ip} (Total: {len(open_ports)}):\n"
    for port_entry in sorted(open_ports):
        if isinstance(port_entry, (list, tuple)) and len(port_entry) == 2:
            port, banner = port_entry
        else:
            port = port_entry
            banner = ""
    details += f"  → Port {port}: OPEN\n"
    details += f"     Banner: {banner or 'No banner retrieved'}\n"

    remediation = (
        "Close unnecessary ports to reduce your attack surface.\n"
        "Recommended actions:\n"
        "- Disable unused services\n"
        "- Configure firewall rules to restrict access\n"
        "- Move critical services behind a VPN or reverse proxy\n"
        "- Enable service-specific security configurations (e.g., SSH key auth, RDP Network Level Authentication)"
    )

    if not is_private:
        remediation += "\n⚠️ Public exposure increases risk. Harden or close services immediately."
    else:
        remediation += "\nNote: Internal exposure still poses risk. Audit and secure local services."

    return {
        "score": round(score, 2),
        "status": status,
        "details": details.strip(),
        "remediation": remediation
    }

if __name__ == "__main__":
    test_ip = "127.0.0.1"
    set_target_ip(test_ip)
    result = run_audit()
    print(
        f"Score: {result['score']}\n"
        f"Status: {result['status']}\n"
        f"Details:\n{result['details']}\n"
        f"Remediation:\n{result['remediation']}"
    )
