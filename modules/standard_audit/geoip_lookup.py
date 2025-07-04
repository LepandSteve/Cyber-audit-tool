# modules/geoip_lookup.py

import requests
from utils.ip_utils import is_private_ip


def geoip_lookup(ip):
    if is_private_ip(ip):
        return {
            "score": 10.0,
            "status": "Info",
            "details": f"🌐 IP {ip} is private/internal and does not require GeoIP lookup.\n✅ No public exposure detected.",
            "remediation": "✅ No action needed for internal IP addresses."
        }

    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code != 200:
            return {
                "score": 5.0,
                "status": "Warning",
                "details": (
                    f"⚠️ GeoIP service returned status code {response.status_code}.\n"
                    "📡 External lookup may be limited or temporarily unavailable."
                ),
                "remediation": (
                    "🔧 Check internet access and API rate limits.\n"
                    "💡 Consider switching to a different GeoIP provider if issues persist."
                )
            }

        data = response.json()
        country = data.get("country_name", "Unknown")
        region = data.get("region", "Unknown")
        city = data.get("city", "Unknown")
        isp = data.get("org", "Unknown")

        details = (
            f"🌍 GeoIP Lookup for {ip}:\n"
            f"- Country: {country}\n"
            f"- Region: {region}\n"
            f"- City: {city}\n"
            f"- ISP/Org: {isp}"
        )

        remediation = (
            "🔍 Review the geographic location of your public IP.\n"
            "💡 If the location is unexpected, verify with your ISP or investigate potential use of proxies or VPNs."
        )

        return {
            "score": 10.0,
            "status": "Pass",
            "details": details,
            "remediation": remediation
        }

    except requests.RequestException as e:
        return {
            "score": 4.0,
            "status": "Fail",
            "details": f"❌ Failed to perform GeoIP lookup for {ip}.\nError: {e}",
            "remediation": (
                "🔧 Ensure the host has internet access.\n"
                "🛡️ Check if outbound HTTP(S) traffic is being blocked by a firewall or proxy."
            )
        }


def run_audit(ip=None, banners=None, is_private=None, open_ports=None, shared_data=None):  # ✅ Added shared_data
    target_ip = ip if ip else "8.8.8.8"
    return geoip_lookup(target_ip)


if __name__ == "__main__":
    test_ip = "8.8.8.8"
    result = run_audit(test_ip)
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
