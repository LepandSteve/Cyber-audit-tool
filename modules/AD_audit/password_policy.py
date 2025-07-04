from ldap3 import Server, Connection, NTLM, ALL
from typing import Dict

def run_audit(ip: str, shared_data: Dict) -> Dict:
    domain = shared_data.get("domain")
    username = shared_data.get("username")
    password = shared_data.get("password")
    base_dn = shared_data.get("base_dn")

    try:
        server = Server(ip, get_info=ALL)
        conn = Connection(
            server,
            user=f"{domain}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True
        )

        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=domain)",
            attributes=[
                "minPwdLength",
                "pwdProperties",
                "pwdHistoryLength",
                "maxPwdAge",
                "lockoutThreshold"
            ]
        )

        if not conn.entries:
            raise Exception("No domain policy found.")

        entry = conn.entries[0]
        details = []

        def format_duration(windows_duration):
            # Convert Windows ticks to days
            try:
                days = abs(int(windows_duration)) // (10 ** 7 * 60 * 60 * 24)
                return f"{days} days"
            except:
                return "Unknown"

        details.append("🔐 Domain Password Policy:")
        details.append(f"• Minimum Password Length: {entry.minPwdLength.value}")
        details.append(f"• Password History Length: {entry.pwdHistoryLength.value}")
        details.append(f"• Max Password Age: {format_duration(entry.maxPwdAge.value)}")
        details.append(f"• Lockout Threshold: {entry.lockoutThreshold.value}")

        # Decode pwdProperties (bitwise flags)
        pwd_props = int(entry.pwdProperties.value)
        complexity_enabled = bool(pwd_props & 1)
        details.append(f"• Password Complexity: {'Enabled' if complexity_enabled else 'Disabled'}")

        status = "Pass" if complexity_enabled and entry.minPwdLength.value >= 8 else "Warning"
        score = 10.0 if status == "Pass" else 5.0

        remediation = (
            "✅ Password policy appears secure."
            if status == "Pass" else
            "🔧 Consider enabling complexity and increasing minimum length to at least 8 characters."
        )

        return {
            "score": score,
            "status": status,
            "details": "\n".join(details),
            "remediation": remediation
        }

    except Exception as e:
        return {
            "score": 0.0,
            "status": "Error",
            "details": f"❌ Failed to retrieve password policy.\nError: {e}",
            "remediation": "Ensure valid domain credentials and connectivity to the domain controller."
        }
