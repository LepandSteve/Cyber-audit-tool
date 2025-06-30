# modules/whois_lookup.py

import whois
from utils.ip_utils import is_private_ip

def perform_whois_lookup(ip: str) -> dict:
    """
    Perform a WHOIS lookup for a given IP address or domain.

    Args:
        ip (str): IP address or domain name to query.

    Returns:
        dict: Contains keys: score, status, details, remediation.
    """
    try:
        w = whois.whois(ip)

        # Check if WHOIS returned meaningful data
        if not w or all(v in [None, '', [], {}] for v in w.values()):
            raise ValueError("WHOIS returned no usable data.")

        details = f"📄 WHOIS data for {ip}:\n"
        for key, value in w.items():
            if value:
                details += f"• {key}: {value}\n"

        return {
            "score": 10.0,
            "status": "Pass",
            "details": details.strip(),
            "remediation": "✅ WHOIS data found. Review domain registration and ownership as needed."
        }

    except Exception as e:
        return {
            "score": 4.0,
            "status": "Fail",
            "details": f"❌ WHOIS lookup failed for {ip}.\nError: {e}",
            "remediation": (
                "• Ensure the input is a valid public IP or domain.\n"
                "• Check your DNS and internet connectivity.\n"
                "• WHOIS data might not be available for some TLDs or newly registered domains."
            )
        }


def run_audit(ip=None, banner=None, is_private=None, open_ports=None, **kwargs) -> dict:
    """
    Main entry point for the WHOIS lookup audit module.

    Args:
        ip (str): Target IP address or domain.

    Returns:
        dict: Audit result dictionary.
    """
    if not ip:
        return {
            "score": 0.0,
            "status": "Error",
            "details": "❌ No IP or domain provided for WHOIS lookup.",
            "remediation": "📥 Pass the target IP or domain via the `ip` parameter."
        }

    if is_private_ip(ip):
        return {
            "score": 10.0,
            "status": "Skipped",
            "details": (
                f"🔍 WHOIS lookup skipped: {ip} is a private/internal IP.\n"
                "No WHOIS data needed."
            ),
            "remediation": "✅ No action required for private IP addresses."
        }

    return perform_whois_lookup(ip)


if __name__ == "__main__":
    # Example test run
    test_ip = "8.8.8.8"
    result = run_audit(ip=test_ip)
    print(f"Score: {result['score']}\nStatus: {result['status']}")
    print("Details:\n" + result["details"])
    print("Remediation:\n" + result["remediation"])
