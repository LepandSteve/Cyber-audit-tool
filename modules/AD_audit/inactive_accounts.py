# modules.AD_audit.inactive_accounts.py

from ldap3 import Connection
from datetime import datetime, timedelta
from typing import Dict, Optional

INACTIVITY_THRESHOLD_DAYS = 90

def run_audit(shared_data: Optional[dict] = None, **kwargs) -> Dict:
    """
    Find user accounts that have not logged in within the inactivity threshold.
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

        # Search for enabled users
        conn.search(
            search_base=base_dn,
            search_filter="(&(objectClass=user)(lastLogonTimestamp=*))",
            attributes=["sAMAccountName", "lastLogonTimestamp"]
        )

        stale_users = []
        threshold_date = datetime.now() - timedelta(days=INACTIVITY_THRESHOLD_DAYS)

        for entry in conn.entries:
            username = entry.sAMAccountName.value
            raw_timestamp = entry.lastLogonTimestamp.value

            if not raw_timestamp:
                continue

            last_login = convert_windows_timestamp(raw_timestamp)
            if last_login and last_login < threshold_date:
                stale_users.append(f"🛑 {username} (Last login: {last_login.strftime('%Y-%m-%d')})")

        if stale_users:
            status = "Warning"
            score = 5.0 if len(stale_users) <= 10 else 3.0
            details = (
                f"🧓 Inactive users detected (> {INACTIVITY_THRESHOLD_DAYS} days):\n" +
                "\n".join(stale_users)
            )
            remediation = (
                f"⚠️ These accounts haven't logged in for over {INACTIVITY_THRESHOLD_DAYS} days.\n"
                "🧹 Consider disabling or removing them after verification.\n"
                "🛡️ Review HR and deprovisioning procedures."
            )
        else:
            details = f"✅ No user account has been inactive for more than {INACTIVITY_THRESHOLD_DAYS} days."
            remediation = "✅ No action required."

    except Exception as e:
        score = 0.0
        status = "Error"
        details = f"❌ Failed to check inactive accounts: {e}"
        remediation = "📡 Verify LDAP connection and ensure required permissions."

    return {
        "score": score,
        "status": status,
        "details": details,
        "remediation": remediation
    }

def convert_windows_timestamp(timestamp: int) -> Optional[datetime]:
    """
    Convert AD timestamp to datetime.
    """
    try:
        base_time = datetime(1601, 1, 1)
        return base_time + timedelta(seconds=int(timestamp) / 10_000_000)
    except Exception:
        return None

if __name__ == "__main__":
    print("Run through AD audit runner with shared LDAP connection.")
