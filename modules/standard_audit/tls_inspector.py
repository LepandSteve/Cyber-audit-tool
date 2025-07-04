import socket
import ssl
from datetime import datetime
from utils.ip_utils import is_private_ip


def inspect_tls_certificate(ip_or_hostname: str, port: int = 443) -> dict:
    if is_private_ip(ip_or_hostname):
        return {
            "score": 10.0,
            "status": "Info",
            "details": (
                f"🔒 TLS inspection skipped for private IP: {ip_or_hostname}\n"
                "✅ No external exposure risk."
            ),
            "remediation": "No TLS inspection required for private/internal IPs.",
        }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip_or_hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip_or_hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return {
                "score": 2.0,
                "status": "Warning",
                "details": f"⚠️ No certificate returned by server at {ip_or_hostname}.",
                "remediation": "🛠️ Check the TLS configuration and ensure a valid certificate is presented.",
            }

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issued_to = subject.get("commonName", "Unknown")
        issued_by = issuer.get("commonName", "Unknown")
        not_before = cert.get("notBefore", "Unknown")
        not_after = cert.get("notAfter", "Unknown")

        try:
            exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_date - datetime.utcnow()).days
        except Exception:
            days_left = None

        findings = [
            "🔐 TLS/SSL Certificate Info:",
            f"   → Issued To       : {issued_to}",
            f"   → Issued By       : {issued_by}",
            f"   → Valid From      : {not_before}",
            f"   → Valid Until     : {not_after}",
            f"   → Days Remaining  : {days_left if days_left is not None else 'Unknown'}",
        ]

        score = 10.0
        status = "Pass"

        if days_left is None:
            findings.append("⚠️ Could not determine certificate expiration.")
            score = 5.0
            status = "Warning"
        elif days_left < 30:
            findings.append("⚠️ Certificate is expiring soon!")
            score = 5.0
            status = "Warning"

        return {
            "score": score,
            "status": status,
            "details": "\n".join(findings),
            "remediation": (
                "📆 Monitor certificate expiration dates and renew early.\n"
                "🔐 Use strong TLS configurations (TLS 1.2+ and secure ciphers).\n"
                "✅ Test your server using tools like Qualys SSL Labs for compliance."
            ),
        }

    except ssl.SSLError as e:
        return {
            "score": 0.0,
            "status": "Fail",
            "details": f"❌ SSL Error during TLS inspection: {e}",
            "remediation": (
                "❗ Ensure a valid TLS certificate is installed.\n"
                "🔍 Review your SSL/TLS settings to avoid handshake failures."
            ),
        }

    except Exception as e:
        return {
            "score": 0.0,
            "status": "Fail",
            "details": f"❌ Failed to inspect TLS certificate for {ip_or_hostname}.\nError: {e}",
            "remediation": (
                "📡 Ensure the server is reachable on port 443 and supports TLS.\n"
                "🧪 You can verify manually with `openssl s_client -connect <host>:443`."
            ),
        }


def run_audit(ip=None, banners=None, is_private=None, open_ports=None, shared_data=None):
    if not ip:
        return {
            "score": 0.0,
            "status": "Error",
            "details": "❌ No target IP or hostname provided for TLS inspection.",
            "remediation": "Pass `ip=...` to the run_audit() function.",
        }

    return inspect_tls_certificate(ip)


if __name__ == "__main__":
    result = run_audit(ip="google.com")
    print(f"Score: {result['score']}\nStatus: {result['status']}")
    print("Details:\n" + result["details"])
    print("Remediation:\n" + result["remediation"])
