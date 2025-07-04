# public_exposure.py

# Module to check for dangerous services exposed to the public internet

"""
public_exposure.py

Analyzes open ports and flags services that are risky to expose publicly.
"""

from typing import Optional, List, Tuple, Dict

def check_public_exposure(open_ports: List[Tuple[int, str]]) -> List[str]:
    risky_ports = {
        21: "FTP is exposed – insecure and often misconfigured.",
        23: "Telnet exposed – very insecure and deprecated.",
        25: "SMTP exposed – check for open relay configuration.",
        3389: "RDP (Remote Desktop) is exposed – a common brute-force target.",
        3306: "MySQL database port exposed – ensure it's firewalled and access-controlled.",
        5432: "PostgreSQL database port exposed – restrict to internal networks.",
        27017: "MongoDB port exposed – can lead to data leaks if unsecured.",
        6379: "Redis port exposed – frequently exploited if unsecured.",
        9200: "Elasticsearch exposed – could result in full data access.",
    }

    findings = []
    for entry in open_ports:
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            port, banner = entry
        else:
            port = entry
            banner = ""
        if port in risky_ports:
            findings.append(
                f"Port {port}: {risky_ports[port]}\nBanner: {banner or 'No banner retrieved'}"
            )
    return findings

def run_audit(
    ip: Optional[str] = None,
    banners: Optional[List[str]] = None,
    is_private: Optional[bool] = None,
    open_ports: Optional[List[Tuple[int, str]]] = None,
    shared_data: Optional[Dict] = None
) -> dict:
    if not open_ports:
        return {
            "score": 0.0,
            "status": "Error",
            "details": "No open ports provided for public exposure audit.",
            "remediation": "Ensure port scanning runs before this check and passes 'open_ports' to run_audit()."
        }

    findings = check_public_exposure(open_ports)

    if not findings:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": f"No obviously dangerous services are publicly exposed on {ip or 'target'}.",
            "remediation": "No action needed. Continue monitoring and reviewing open ports regularly."
        }

    score = max(2.0, 10.0 - len(findings) * 1.5)
    status = "Fail" if len(findings) >= 3 else "Warning"

    details = f"Public Exposure Risks Detected on {ip or 'target'}:\n" + "\n\n".join(findings)
    remediation = (
        "Remediation recommendations:\n"
        "- Restrict critical services using firewalls, VPNs, or security groups\n"
        "- Disable unused services\n"
        "- Move services behind a reverse proxy\n"
        "- Implement strong authentication (MFA, key-based SSH, etc.)\n"
        "- Use network segmentation for databases and admin interfaces\n"
        "- Monitor and alert on exposure of critical ports"
    )

    return {
        "score": round(score, 2),
        "status": status,
        "details": details.strip(),
        "remediation": remediation
    }

if __name__ == "__main__":
    test_ports = [
        (21, "vsftpd 3.0.3"),
        (80, "Apache 2.4"),
        (3389, "Microsoft Terminal Services"),
    ]
    result = run_audit(ip="192.168.1.1", open_ports=test_ports)
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
