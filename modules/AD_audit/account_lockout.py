# modules.AD_audit.account_lockout.py

from ldap3 import Connection
from typing import Dict, Optional
from datetime import datetime, timedelta

def run_audit(shared_data: Optional[dict] = None, **kwargs) -> Dict:
    """
    Audit AD for currently locked-out accounts.
    """
    score = 10.0
    status = "Pass"
    details = ""
    remediation = ""

    try:
        if not shared_data or "ldap_connection" not in shared_data:
            raise ValueError("Missing LDAP connection in shared_data.")
        
        conn: Connection = shared_data["ldap_connection"]
        base_dn = conn.server.info.other['defaultNamingContext'][0]

        # Search for users with lockoutTime set (greater than zero)
        conn.search(
            search_base=base_dn,
            search_filter="(&(objectClass=user)(lockoutTime>=1))",
            attributes=["sAMAccountName", "lockoutTime"]
        )

        locked_users = []
        for entry in conn.entries:
            username = entry.sAMAccountName.value
            lockout_time_raw = entry.lockoutTime.value
            lockout_time = convert_windows_timestamp(lockout_time_raw) if lockout_time_raw else "Unknown"
            locked_users.append(f"🔐 {username} (Locked out at: {lockout_time})")

        if locked_users:
            status = "Warning"
            score = 5.0 if len(locked_users) <= 5 else 3.0
            details = "\n".join(locked_users)
            remediation = (
                "⚠️ Several accounts are locked out.\n"
                "🔍 Investigate possible brute-force attempts or misconfigured systems.\n"
                "📜 Review Event Logs (4625, 4740) and Account Lockout Policy."
            )
        else:
            details = "✅ No locked-out accounts detected."
            remediation = "✅ No action required."

    except Exception as e:
        score = 0.0
        status = "Error"
        details = f"❌ Error occurred during account lockout enumeration:\n{e}"
        remediation = "📡 Check LDAP connection and permissions."

    return {
        "score": score,
        "status": status,
        "details": details,
        "remediation": remediation
    }

def convert_windows_timestamp(timestamp: int) -> str:
    """
    Convert Windows FILETIME to human-readable time.
    """
    try:
        epoch_start = datetime(1601, 1, 1)
        seconds = int(timestamp) / 10_000_000
        return str(epoch_start + timedelta(seconds=seconds))
    except Exception:
        return "Unknown"

if __name__ == "__main__":
    print("Run through AD audit runner or standalone with LDAP connection.")
