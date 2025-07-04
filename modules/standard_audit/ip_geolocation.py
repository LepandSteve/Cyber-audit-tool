from utils.ip_utils import is_private_ip
import requests

_target_ip = None

def set_target_ip(ip: str):
    """
    Optionally set a global target IP address.
    """
    global _target_ip
    _target_ip = ip

def run_audit(ip=None, banners=None, is_private=None, open_ports=None, shared_data=None):  # ✅ Added shared_data
    target_ip = ip or _target_ip or "8.8.8.8"

    if is_private_ip(target_ip):
        return {
            "score": 10.0,
            "status": "Info",
            "details": (
                f"🌐 IP {target_ip} is private/internal and does not require geolocation.\n"
                "✅ No public exposure detected."
            ),
            "remediation": "No geolocation required for private/internal IP addresses."
        }

    try:
        url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,regionName,city,zip,lat,lon,org,as"
        response = requests.get(url, timeout=7)
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "success":
            return {
                "score": 0.0,
                "status": "Fail",
                "details": f"❌ Geolocation lookup failed for {target_ip}: {data.get('message', 'Unknown error')}",
                "remediation": (
                    "🛠️ Verify the IP address is correct and public.\n"
                    "🌐 Check if the geolocation API service is reachable or rate-limited."
                )
            }

        details = (
            f"🌍 IP Geolocation for {target_ip}:\n"
            f"- Country: {data.get('country', 'N/A')}\n"
            f"- City/Region: {data.get('city', 'N/A')}, {data.get('regionName', 'N/A')} {data.get('zip', '')}\n"
            f"- Coordinates: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}\n"
            f"- Organization: {data.get('org', 'N/A')} | ASN: {data.get('as', 'N/A')}"
        )

        remediation = (
            "🔍 Review geolocation results for accuracy.\n"
            "💡 If the IP resolves to an unexpected location, investigate use of VPNs, proxies, or compromised systems."
        )

        return {
            "score": 10.0,
            "status": "Pass",
            "details": details,
            "remediation": remediation
        }

    except requests.Timeout:
        return {
            "score": 0.0,
            "status": "Fail",
            "details": f"❌ Geolocation lookup timed out for {target_ip}.",
            "remediation": "Check network connectivity and retry the audit."
        }
    except requests.RequestException as e:
        return {
            "score": 0.0,
            "status": "Fail",
            "details": f"❌ Geolocation lookup error for {target_ip}: {e}",
            "remediation": "Check API endpoint availability and your internet connection."
        }
    except Exception as e:
        return {
            "score": 0.0,
            "status": "Fail",
            "details": f"❌ Unexpected error during geolocation lookup: {e}",
            "remediation": "Review logs and retry. Consider updating dependencies or API URLs."
        }

if __name__ == "__main__":
    test_ip_public = "8.8.8.8"
    test_ip_private = "192.168.1.1"

    print(run_audit(test_ip_public))
    print(run_audit(test_ip_private))
