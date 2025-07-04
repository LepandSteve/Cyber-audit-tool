"""
reverse_DNS.py

Performs a reverse DNS lookup to determine the hostname associated with an IP.
"""

import socket
from typing import Optional, List, Tuple, Dict
from utils.ip_utils import is_private_ip

def reverse_dns_lookup(ip: str) -> dict:
    """
    Perform a reverse DNS lookup on the given IP.
    Returns a dictionary with score, status, details, and remediation.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        details = (
            f"🔁 Reverse DNS Lookup for {ip}:\n"
            f"  → Hostname: {hostname}"
        )
        remediation = (
            "🔒 Ensure reverse DNS entries do not reveal sensitive or internal naming schemes.\n"
            "💡 Use generic or anonymized naming where possible."
        )
        return {
            "score": 10.0,
            "status": "Pass",
            "details": details,
            "remediation": remediation
        }
    except socket.herror:
        details = (
            f"⚠️ No reverse DNS record found for {ip}.\n"
            "Reverse DNS can improve network traceability."
        )
        remediation = (
            "🛠️ Configure PTR (Pointer) records for your public IPs to enable reverse DNS resolution.\n"
            "This aids in reputation, mail server verification, and troubleshooting."
        )
        return {
            "score": 7.0,
            "status": "Warning",
            "details": details,
            "remediation": remediation
        }
    except socket.gaierror:
        details = (
            f"❌ DNS resolution error while looking up {ip}.\n"
            "This may indicate a misconfigured or unreachable DNS server."
        )
        remediation = (
            "📡 Check network connectivity and ensure your DNS settings are correct."
        )
        return {
            "score": 4.0,
            "status": "Fail",
            "details": details,
            "remediation": remediation
        }
    except Exception as e:
        details = (
            f"❌ Unexpected error during reverse DNS lookup for {ip}.\n"
            f"Error: {e}"
        )
        remediation = (
            "📡 Check your DNS configuration, ensure the IP is reachable, and verify DNS server availability."
        )
        return {
            "score": 4.0,
            "status": "Fail",
            "details": details,
            "remediation": remediation
        }

def run_audit(
    ip: Optional[str] = None,
    banners: Optional[List[str]] = None,
    is_private: Optional[bool] = None,
    open_ports: Optional[List[Tuple[int, str]]] = None,
    shared_data: Optional[Dict] = None
) -> dict:
    """
    Standardized audit interface.
    Performs reverse DNS lookup unless IP is private.
    """
    if not ip:
        return {
            "score": 0.0,
            "status": "Error",
            "details": "❌ No target IP provided for Reverse DNS lookup.",
            "remediation": "Pass the IP as an argument to run_audit(ip=...)."
        }

    if is_private or is_private_ip(ip):
        return {
            "score": 10.0,
            "status": "Info",
            "details": (
                f"🔍 Reverse DNS Lookup skipped: {ip} is a private/internal IP.\n"
                "✅ No external DNS exposure risk."
            ),
            "remediation": "No action needed for private/internal IP addresses."
        }

    return reverse_dns_lookup(ip)

if __name__ == "__main__":
    # Example test
    result = run_audit(ip="8.8.8.8")
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
