## `main.py`
# main.py
# === Import Audit Modules with run_audit where available ===
# main_audit_runner.py

import socket
import re
from modules import (
    banner_grabber,
    ip_geolocation,
    geoip_lookup,
    http_headers_check,
    ntp_time_skew,
    os_detection,
    whois_lookup,
    reverse_DNS,
    tls_inspector,
    public_exposure,
    brute_force_exposure,
    vulnerability_scanner,
    service_security
)
from main_audit import run_all_audits

def is_private_ip(ip: str) -> bool:
    private_ranges = [
        ("10.0.0.0",   "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0","192.168.255.255"),
    ]
    parts = list(map(int, ip.split('.')))
    for start, end in private_ranges:
        s = list(map(int, start.split('.')))
        e = list(map(int, end.split('.')))
        if s <= parts <= e:
            return True
    return False

def resolve_target(target: str) -> str | None:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def run_full_audit(target: str, stop_event=None, progress_callback=None):
    # Step 1: DNS resolution
    ip = resolve_target(target)
    if not ip:
        return {
            "final_score": 0.0,
            "overall_status": "Error",
            "module_scores": {},
            "error": f"Cannot resolve target: {target}"
        }

    private = is_private_ip(ip)
    if progress_callback:
        progress_callback(f"🎯 Resolved {target} → {ip} (private={private})")

    # Step 2: Banner grabbing
    if progress_callback:
        progress_callback("🔍 Banner grabbing...")
    banner_res = banner_grabber.run_audit(
        ip=ip,
        banners=None,
        is_private=private,
        open_ports=None
    )
    banner_raw = banner_res.get("details", "")
    banners = banner_raw.splitlines() if isinstance(banner_raw, str) else banner_raw

    # Open ports are not collected here — handled by port scan module later
    open_ports = []

    # Step 3: Shared data injection
    for m in (ip_geolocation, geoip_lookup, http_headers_check,
              ntp_time_skew, os_detection, whois_lookup, reverse_DNS, tls_inspector):
        if hasattr(m, "set_target_ip"):
            m.set_target_ip(ip)

    for m in (public_exposure, brute_force_exposure):
        if hasattr(m, "set_open_ports"):
            m.set_open_ports(open_ports)

    for m in (vulnerability_scanner, service_security):
        if hasattr(m, "set_banner_list"):
            m.set_banner_list(banners)

    # Step 4: Run all audits
    if progress_callback:
        progress_callback("🚀 Launching all audit modules...")

    results = run_all_audits(
        ip_address=ip,
        banners=banners,
        is_private=private,
        open_ports=open_ports
    )

    if progress_callback:
        progress_callback("✅ Audit complete.")
    return results
