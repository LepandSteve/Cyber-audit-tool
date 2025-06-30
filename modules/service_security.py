from typing import List, Optional, Tuple, Dict

def run_audit(banners: Optional[List[Tuple[int, str]]] = None, **kwargs) -> Dict:
    """
    Evaluate service banners for potentially insecure or misconfigured services.
    Expects a list of (port, banner) tuples from the banner_grabber module.
    """

    if not banners or not isinstance(banners, list):
        return {
            "score": 0.0,
            "status": "Error",
            "details": "❌ Missing or invalid input: expected a list of (port, banner) tuples.",
            "remediation": (
                "🔧 Ensure the banner_grabber module returns a proper list of "
                "(port, banner) tuples under the key 'banners'."
            )
        }

    risky_keywords = [
        "telnet", "ftp", "vnc", "rlogin", "proxy", "rdp", "smb", "netbios",
        "remote desktop", "anonymous", "public", "admin", "default", "debug",
        "test", "demo", "apache", "nginx", "iis", "openssh", "outdated", "2.2", "2.4"
    ]

    risky_findings = []
    for entry in banners:
        try:
            port, banner = entry
            if not banner:
                continue
            banner_lower = banner.lower()
            if any(keyword in banner_lower for keyword in risky_keywords):
                risky_findings.append((port, banner))
        except (ValueError, TypeError):
            continue  # Skip malformed entries

    if not risky_findings:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": "✅ No risky or outdated service banners detected.",
            "remediation": "No action required. All exposed services appear secure."
        }

    details = "⚠️ Potentially risky services detected:\n"
    for port, banner in risky_findings:
        details += f"  → Port {port}: {banner}\n"

    remediation = (
        "🔧 Remediation steps:\n"
        "- Disable or restrict access to legacy services (e.g., FTP, Telnet).\n"
        "- Replace or update deprecated services (e.g., Apache 2.2 → 2.4+).\n"
        "- Mask or disable version banners in configurations (Apache, NGINX, etc).\n"
        "- Enforce access controls and firewall restrictions.\n"
        "- Apply latest patches to exposed services."
    )

    score = max(2.0, 10.0 - len(risky_findings) * 1.5)

    return {
        "score": round(score, 2),
        "status": "Warning",
        "details": details.strip(),
        "remediation": remediation.strip()
    }


if __name__ == "__main__":
    sample_banners = [
        (21, "vsFTPd 2.3.4"),
        (80, "Apache/2.2.22 (Ubuntu)"),
        (3389, "Remote Desktop Protocol"),
        (139, "Samba smbd 3.6.3"),
    ]
    result = run_audit(banners=sample_banners)
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
