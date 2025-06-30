# modules/brute_force_exposure.py
# For modules that take a list of open ports (e.g. public_exposure.py, brute_force_exposure.py):

"""
brute_force_exposure.py

Detects common services exposed on ports that are frequent brute-force targets.
"""

from typing import Optional, List, Tuple, Dict

def run_audit(
    ip: Optional[str] = None,
    banners: Optional[List[str]] = None,
    is_private: Optional[bool] = None,
    open_ports: Optional[List[Tuple[int, str]]] = None,
    shared_data: Optional[Dict] = None
) -> dict:
    brute_force_ports = {
        21: "FTP (21/tcp)",
        22: "SSH (22/tcp)",
        23: "Telnet (23/tcp)",
        25: "SMTP (25/tcp)",
        110: "POP3 (110/tcp)",
        143: "IMAP (143/tcp)",
        3389: "RDP (3389/tcp)",
    }

    if is_private:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": "Brute-force exposure check skipped for private/internal IP.",
            "remediation": "No action needed for internal-only hosts."
        }

    if not open_ports:
        return {
            "score": 0.0,
            "status": "Fail",
            "details": "Missing input: open_ports is required by brute_force_exposure module.",
            "remediation": "Ensure port scanning runs first and populates open_ports before running this check."
        }

    findings = []
    remediation_steps = []

    for entry in open_ports:
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            port, banner = entry
        else:
            port = entry
            banner = ""

        if port in brute_force_ports:
            svc = brute_force_ports[port]
            findings.append(f"{svc} exposed (port {port}) — Banner: {banner or 'No banner'}")
            remediation_steps.append(
                f"{svc} (port {port}):\n"
                "- Restrict access via firewall or IP allow-listing\n"
                "- Enforce strong authentication (e.g., SSH keys, complex passwords)\n"
                "- Apply rate limiting or use an intrusion detection/prevention system (IDS/IPS)\n"
                "- Consider using a VPN or jump server for secure access"
            )

    if not findings:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": "No brute-force susceptible services exposed on common ports.",
            "remediation": "No action needed."
        }

    score = max(0.0, 10.0 - 2.0 * len(findings))
    status = "Fail" if score < 10.0 else "Pass"

    return {
        "score": round(score, 2),
        "status": status,
        "details": "Brute-Force Exposure Risks:\n" + "\n\n".join(findings),
        "remediation": "Recommended Actions:\n" + "\n\n".join(remediation_steps)
    }

if __name__ == "__main__":
    test_ports = [(22, "OpenSSH 7.4"), (80, "nginx"), (3389, "RDP Service")]
    result = run_audit(open_ports=test_ports)
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
