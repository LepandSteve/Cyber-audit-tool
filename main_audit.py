from modules import (
    antivirus_check,
    banner_grabber,
    brute_force_exposure,
    credential_check,
    cve_lookup,
    firewall_check,
    geoip_lookup,
    http_headers_check,
    ip_geolocation,
    # local_port_activity,  # Excluded from scoring
    network_scan,
    ntp_time_skew,
    os_detection,
    port_check,
    public_exposure,
    remote_port_activity,
    reverse_DNS,
    service_security,
    system_info,
    tls_inspector,
    vulnerability_scanner,
    weak_protocols,
    whois_lookup,
    report,
)

def run_all_audits(ip_address, banners=None, is_private=False, open_ports=None):
    banners = banners or []
    open_ports = open_ports or []

    results = {}

    # Provide shared data to modules that require it
    public_exposure.set_open_ports(open_ports)
    service_security.set_banner_list(banners)
    vulnerability_scanner.set_banner_list(banners)
    tls_inspector.set_target_ip(ip_address)
    whois_lookup.set_target_ip(ip_address)
    reverse_DNS.set_target_ip(ip_address)

    def safe_run(label, func, required=None):
        """Helper to run audit function with optional data checks."""
        try:
            if required == "banners" and not banners:
                return {
                    "status": "Info",
                    "score": 0.0,
                    "details": f"Skipped {label}: banners data missing.",
                    "remediation": "Ensure banner grabbing runs and passes data."
                }
            if required == "open_ports" and not open_ports:
                return {
                    "status": "Info",
                    "score": 0.0,
                    "details": f"Skipped {label}: open_ports data missing.",
                    "remediation": "Ensure port scanning runs and passes data."
                }
            return func()
        except Exception as e:
            return {
                "status": "Error",
                "score": 0.0,
                "details": f"■ Error running {label}: {e}",
                "remediation": "Check the module implementation or input format."
            }

    audit_plan = {
        "Antivirus Check": (antivirus_check.run_audit, None),
        "Banner Grabber": (lambda: banner_grabber.run_audit(
            ip=ip_address,
            banners=banners,
            is_private=is_private,
            open_ports=open_ports
        ), None),
        "Brute Force Exposure": (lambda: brute_force_exposure.run_audit(ip=ip_address), None),
        "Default Credentials": (credential_check.run_audit, None),
        "CVE Lookup": (lambda: cve_lookup.run_audit(banners=banners), "banners"),
        "Firewall Check": (firewall_check.run_audit, None),
        "GeoIP Lookup": (lambda: geoip_lookup.run_audit(ip=ip_address, is_private=is_private), None),
        "HTTP Headers Check": (lambda: http_headers_check.run_audit(ip=ip_address), None),
        "IP Geolocation": (lambda: ip_geolocation.run_audit(ip=ip_address), None),
        # "Local Port Activity": (local_port_activity.run_audit, None),  # Excluded from scoring
        "Network Scan": (lambda: network_scan.run_audit(ip=ip_address, open_ports=open_ports), "open_ports"),
        "NTP Time Skew": (lambda: ntp_time_skew.run_audit(ip=ip_address, is_private=is_private), None),
        "OS Detection": (lambda: os_detection.run_audit(ip=ip_address), None),
        "Port Check": (lambda: port_check.run_audit(ip=ip_address, open_ports=open_ports), "open_ports"),
        "Public Exposure": (public_exposure.run_audit, None),
        "Remote Port Activity": (lambda: remote_port_activity.run_audit(ip=ip_address), None),
        "Reverse DNS Lookup": (reverse_DNS.run_audit, None),
        "Service Security": (service_security.run_audit, None),
        "System Info": (system_info.run_audit, None),
        "TLS Inspector": (tls_inspector.run_audit, None),
        "Vulnerability Scanner": (vulnerability_scanner.run_audit, None),
        "Weak Protocols": (lambda: weak_protocols.run_audit(banners=banners), "banners"),
        "WHOIS Lookup": (whois_lookup.run_audit, None),
    }

    for label, (func, required) in audit_plan.items():
        result = safe_run(label, func, required=required)
        print(f"[DEBUG] {label} → {type(result)} → {result}")
        results[label] = result

    return report.calculate_final_score(results)


if __name__ == "__main__":
    # Example usage
    test_ip = "8.8.8.8"
    test_banners = [
        (80, "nginx/1.18.0"),
        (22, "OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"),
    ]
    test_open_ports = [22, 80]

    final_report = run_all_audits(test_ip, banners=test_banners, is_private=False, open_ports=test_open_ports)
    print("Final Audit Report:")
    for module, res in final_report.items():
        print(f"{module}: {res['status']} (Score: {res['score']})")

