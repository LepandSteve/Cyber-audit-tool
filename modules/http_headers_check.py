# modules/http_headers_check.py
import requests
from utils.ip_utils import is_private_ip

COMMON_SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps prevent SSL stripping attacks",
    "Content-Security-Policy": "Mitigates XSS and data injection attacks",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks",
    "X-Frame-Options": "Protects against clickjacking attacks",
    "Referrer-Policy": "Controls amount of referrer information sent",
    "Permissions-Policy": "Restricts use of browser features"
}

def check_http_security_headers(ip_address):
    try:
        url = f"http://{ip_address}"
        response = requests.get(url, timeout=5)
        headers = response.headers
        findings = []

        for header, purpose in COMMON_SECURITY_HEADERS.items():
            if header in headers:
                findings.append(f"✅ {header}: Present — {purpose}")
            else:
                findings.append(f"❌ {header}: Missing — {purpose}")

        return {
            "success": True,
            "findings": findings
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"❌ HTTP headers check failed: {e}"
        }

def run_audit(ip=None, banners=None, is_private=None, open_ports=None, shared_data=None):  # ✅ Added shared_data
    target_ip = ip if ip else "8.8.8.8"

    if is_private_ip(target_ip):
        return {
            "score": 10.0,
            "status": "Info",
            "details": f"ℹ️ HTTP headers check skipped for private/internal IP {target_ip}.",
            "remediation": "✅ No action needed for internal-only web services."
        }

    result = check_http_security_headers(target_ip)

    if not result["success"]:
        return {
            "score": 0.0,
            "status": "Error",
            "details": result["error"],
            "remediation": (
                "🔍 Check if the target IP is hosting a web service on port 80.\n"
                "🌐 Ensure it's accessible and responding to HTTP requests."
            )
        }

    findings = result["findings"]
    present_count = sum(1 for f in findings if f.startswith("✅"))
    total_headers = len(COMMON_SECURITY_HEADERS)
    score = (present_count / total_headers) * 10

    status = (
        "Pass" if present_count == total_headers else
        "Warning" if present_count >= total_headers / 2 else
        "Fail"
    )

    details = "🔐 HTTP Security Headers Check:\n" + "\n".join(findings)

    if status == "Pass":
        remediation = "✅ No action needed. All essential HTTP security headers are present."
    else:
        missing_headers = [
            f"- {header}: {COMMON_SECURITY_HEADERS[header]}"
            for header in COMMON_SECURITY_HEADERS
            if not any(f.startswith(f"✅ {header}") for f in findings)
        ]
        remediation = (
            "🛠️ Implement the following missing HTTP security headers on the web server:\n" +
            "\n".join(missing_headers)
        )

    return {
        "score": round(score, 2),
        "status": status,
        "details": details,
        "remediation": remediation
    }

if __name__ == "__main__":
    test_ip = "8.8.8.8"
    result = run_audit(test_ip)
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
