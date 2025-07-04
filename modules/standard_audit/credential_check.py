"""
credential_check.py

Detects services exposing default or weak credentials via their banners.
"""

from typing import Optional, List, Tuple


def run_audit(
    ip: Optional[str] = None,
    banners: Optional[List[Tuple[int, str]]] = None,
    is_private: Optional[bool] = None,
    open_ports=None,
    shared_data: Optional[dict] = None  # ✅ Added for consistency with audit orchestrator
) -> dict:
    """
    Checks banners for signs of default or weak credentials.

    Args:
      ip:         Target IP (ignored here).
      banners:    List of (port:int, banner:str) tuples.
      is_private: If True, skip check.
      open_ports: Ignored here.
      shared_data: Optional shared data dict.

    Returns:
      dict with score, status, details, remediation.
    """
    default_keywords = [
        "default password", "default credentials",
        "admin:admin", "root:root",
        "username: admin", "password: admin", "login: admin",
        "user: admin", "pass: admin"
    ]

    if is_private:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": "ℹ️ Default credentials check skipped for private/internal IP.",
            "remediation": "✅ No action needed for internal-only hosts."
        }

    if not banners:
        return {
            "score": 0.0,
            "status": "Fail",
            "details": "❌ Missing input: banners list is required by credential_check module.",
            "remediation": "🔧 Ensure banner grabbing runs first and passes data into this module."
        }

    findings = []
    for port, banner in banners:
        if any(keyword in banner.lower() for keyword in default_keywords):
            findings.append((port, banner))

    if not findings:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": "✅ No known default credentials detected in service banners.",
            "remediation": "✅ No action needed."
        }

    details_lines = [
        f"🔑 Default credentials exposed on port {port} — Banner: {banner}"
        for port, banner in findings
    ]

    return {
        "score": 0.0,
        "status": "Fail",
        "details": "🚨 Default Credentials Findings:\n" + "\n\n".join(details_lines),
        "remediation": (
            "🔐 Remediation Steps:\n"
            "- Immediately change or disable any default credentials.\n"
            "- Enforce strong, unique passwords for each service.\n"
            "- Audit all user accounts and remove unused or legacy credentials.\n"
            "- Enable multi-factor authentication (MFA) where feasible."
        )
    }


if __name__ == "__main__":
    test_banners = [
        (21, "Welcome to FTP server - login: admin password: admin"),
        (80, "Apache Server"),
        (22, "OpenSSH 7.9")
    ]
    result = run_audit(banners=test_banners)
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
