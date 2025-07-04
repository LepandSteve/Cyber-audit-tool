# modules/weak_protocols.py

# modules/weak_protocols.py

# modules/weak_protocols.py

def detect_weak_protocols(banner_list):
    """
    Detect weak or deprecated protocols in the provided banner list.

    Args:
        banner_list (list of tuples): List of (port, banner) tuples.

    Returns:
        dict: Audit result with score, status, details, and remediation advice.
    """
    weak_protocols = {
        "ftp": {
            "warning": "⚠️ FTP detected – use SFTP instead.",
            "remediation": "Disable FTP and use SFTP or FTPS."
        },
        "telnet": {
            "warning": "⚠️ Telnet detected – use SSH instead.",
            "remediation": "Disable Telnet and use SSH for remote access."
        },
        "http": {
            "warning": "⚠️ HTTP detected – use HTTPS where possible.",
            "remediation": "Implement HTTPS using valid TLS certificates."
        },
        "rlogin": {
            "warning": "⚠️ rlogin is insecure – avoid using it.",
            "remediation": "Disable rlogin and prefer SSH."
        },
        "snmp": {
            "warning": "⚠️ SNMPv1 detected – consider using SNMPv3.",
            "remediation": "Upgrade to SNMPv3 for secure device management."
        }
    }

    findings = []
    remediations = set()

    for port, banner in banner_list:
        lower_banner = banner.lower()
        for keyword, data in weak_protocols.items():
            if keyword in lower_banner:
                findings.append(
                    f"🔎 Port {port}: {data['warning']}\n   → Banner: {banner}"
                )
                remediations.add(data["remediation"])

    if not findings:
        return {
            "score": 5.0,
            "status": "Pass",
            "details": "✅ No weak or deprecated protocols detected.",
            "remediation": "🛡️ No action needed. All identified protocols are secure."
        }

    return {
        "score": 1.0,
        "status": "Fail",
        "details": "🚩 Weak Protocols Detected:\n" + "\n".join(findings),
        "remediation": "🔧 Remediation Suggestions:\n" + "\n".join(f"- {r}" for r in remediations)
    }


def run_audit(ip=None, banners=None, is_private=None, open_ports=None, shared_data=None):
    """
    Run the weak protocol detection audit.

    Args:
        banners (list): List of (port, banner) tuples.

    Returns:
        dict: Audit result dictionary.
    """
    banner_list = banners if banners else []

    if not banner_list:
        return {
            "score": 0.0,
            "status": "Error",
            "details": "❌ No banner list provided for weak protocol detection.",
            "remediation": "📥 Pass `banners` to `run_audit()`."
        }

    return detect_weak_protocols(banner_list)


if __name__ == "__main__":
    test_banners = [
        (21, "vsFTPd 3.0.3"),
        (23, "Telnet Server"),
        (80, "Apache HTTPD"),
        (443, "nginx/1.21.0 (https)"),
    ]
    result = run_audit(banners=test_banners)
    print(f"Score: {result['score']}\nStatus: {result['status']}")
    print("Details:\n" + result["details"])
    print("Remediation:\n" + result["remediation"])
