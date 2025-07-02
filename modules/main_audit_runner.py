# main_audit_runner.py
import inspect
from modules import (
    antivirus_check, banner_grabber, brute_force_exposure, credential_check,
    cve_lookup, firewall_check, geoip_lookup, http_headers_check, ip_geolocation,
    network_scan, ntp_time_skew, os_detection, port_check,
    public_exposure, remote_port_activity, report, reverse_DNS, service_security,
    system_info, tls_inspector, vulnerability_scanner, weak_protocols, whois_lookup,
)

MODULES_MAP = {
    "antivirus_check": antivirus_check,
    "banner_grabber": banner_grabber,
    "brute_force_exposure": brute_force_exposure,
    "credential_check": credential_check,
    "cve_lookup": cve_lookup,
    "firewall_check": firewall_check,
    "geoip_lookup": geoip_lookup,
    "http_headers_check": http_headers_check,
    "ip_geolocation": ip_geolocation,
    "network_scan": network_scan,
    "ntp_time_skew": ntp_time_skew,
    "os_detection": os_detection,
    "port_check": port_check,
    "public_exposure": public_exposure,
    "remote_port_activity": remote_port_activity,
    "report": report,
    "reverse_DNS": reverse_DNS,
    "service_security": service_security,
    "system_info": system_info,
    "tls_inspector": tls_inspector,
    "vulnerability_scanner": vulnerability_scanner,
    "weak_protocols": weak_protocols,
    "whois_lookup": whois_lookup,
}

def run_full_audit(target_ip: str, selected_modules=None, stop_event=None, progress_callback=None) -> dict:
    if selected_modules is None:
        selected_modules = list(MODULES_MAP.keys())

    results = {}
    shared_data = {}

    total_modules = len(selected_modules)

    def send_progress(message, percent, module_name=None, current=0, total=0):
        if progress_callback:
            progress_callback((message, percent, module_name, current, total))

    send_progress(f"Starting audit on target: {target_ip}", 0, None, 0, total_modules)

    # Pre-fetch banners
    try:
        banners = banner_grabber.get_banners(target_ip)
        if not isinstance(banners, (list, dict)):
            banners = []
        shared_data['banners'] = banners
        send_progress("✅ Banners collected.", 5, "banner_grabber", 0, total_modules)
    except Exception as e:
        shared_data['banners'] = []
        send_progress(f"⚠️ Banner grabbing failed: {e}", 5, "banner_grabber", 0, total_modules)

    # Pre-fetch open ports using network_scan or fallback to port_check
    open_ports = []
    try:
        scan_result = network_scan.run_audit(ip=target_ip)
        open_ports = scan_result.get("open_ports", [])
        if not isinstance(open_ports, list):
            open_ports = []
        shared_data['scan_result'] = scan_result
        shared_data['open_ports'] = open_ports
        send_progress("✅ Network scan completed.", 10, "network_scan", 0, total_modules)
    except Exception:
        try:
            port_result = port_check.run_audit(ip=target_ip)
            open_ports = port_result.get("open_ports", [])
            if not isinstance(open_ports, list):
                open_ports = []
            shared_data['open_ports'] = open_ports
            shared_data['port_result'] = port_result
            send_progress("✅ Port check fallback completed.", 10, "port_check", 0, total_modules)
        except Exception as e:
            shared_data['open_ports'] = []
            send_progress(f"⚠️ Could not detect open ports: {e}", 10, "port_check", 0, total_modules)

    # ✅ Reverse DNS hostname resolution
    try:
        from modules.reverse_DNS import reverse_dns_lookup
        reverse_result = reverse_dns_lookup(target_ip)
        if reverse_result.get("status") == "Pass":
            hostname_line = reverse_result.get("details", "").split("→ Hostname:")[-1].strip()
            shared_data["target_hostname"] = hostname_line
        else:
            shared_data["target_hostname"] = target_ip  # fallback to IP if no hostname
    except Exception:
        shared_data["target_hostname"] = target_ip

    # Run each selected module
    for idx, module_name in enumerate(selected_modules, start=1):
        if stop_event and stop_event.is_set():
            for m in selected_modules:
                if m not in results:
                    results[m] = {
                        "score": 0.0,
                        "status": "Cancelled",
                        "details": "⏹️ Audit cancelled by user.",
                        "remediation": "Rerun audit to analyze this module."
                    }
            send_progress("Audit cancelled.", 100, None, idx, total_modules)
            break

        try:
            percent = int((idx - 1) / total_modules * 90) + 10
            send_progress(f"Running {module_name} ({idx}/{total_modules})", percent, module_name, idx, total_modules)

            module = MODULES_MAP[module_name]
            run_func = getattr(module, "run_audit", None)

            if not callable(run_func):
                raise ValueError("No run_audit() function found.")

            sig = inspect.signature(run_func)
            supported_args = sig.parameters.keys()

            all_kwargs = {
                "ip": target_ip,
                "banners": shared_data.get("banners", []),
                "open_ports": shared_data.get("open_ports", []),
                "shared_data": shared_data
            }
            filtered_kwargs = {k: v for k, v in all_kwargs.items() if k in supported_args}

            audit_result = run_func(**filtered_kwargs)
            if not isinstance(audit_result, dict):
                raise ValueError("Module did not return a dictionary.")

            results[module_name] = audit_result

            percent = int(idx / total_modules * 90) + 10
            send_progress(f"✅ Completed {module_name}", percent, module_name, idx, total_modules)

        except Exception as e:
            results[module_name] = {
                "score": 0.0,
                "status": "Error",
                "details": f"❌ Error running audit: {e}",
                "remediation": "Check module for expected arguments and return structure."
            }
            send_progress(f"⚠️ {module_name} failed.", int(idx / total_modules * 90) + 10, module_name, idx, total_modules)

    send_progress("✅ Audit complete.", 100, None, total_modules, total_modules)

    # Compute final score and status
    valid_scores = [m["score"] for m in results.values() if isinstance(m, dict) and "score" in m]
    final_score = round(sum(valid_scores) / len(valid_scores), 2) if valid_scores else 0.0
    overall_status = (
        "Fail" if final_score < 4.0 else
        "Warning" if final_score < 7.0 else
        "Pass"
    )

    return {
        "module_scores": results,
        "final_score": final_score,
        "overall_status": overall_status
    }
