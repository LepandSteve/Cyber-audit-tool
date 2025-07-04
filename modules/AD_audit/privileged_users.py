# modules.AD_audit.privileged_users.py

from ldap3 import Server, Connection, ALL, NTLM
from typing import Dict, Optional
import socket

PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Account Operators",
    "Schema Admins",
    "Backup Operators"
]

def get_base_dn(conn: Connection) -> str:
    return conn.server.info.other['defaultNamingContext'][0]

def get_users_in_group(conn: Connection, base_dn: str, group_name: str) -> list:
    search_filter = f"(&(objectClass=group)(cn={group_name}))"
    conn.search(search_base=base_dn, search_filter=search_filter, attributes=['member'])
    if not conn.entries:
        return []

    members = conn.entries[0].member.values if 'member' in conn.entries[0] else []
    usernames = []

    for dn in members:
        conn.search(search_base=dn, search_filter="(objectClass=*)", attributes=['sAMAccountName'])
        if conn.entries and 'sAMAccountName' in conn.entries[0]:
            usernames.append(conn.entries[0]['sAMAccountName'].value)
    return usernames

def run_audit(shared_data: Optional[dict] = None, **kwargs) -> Dict:
    """
    Check AD for privileged users in sensitive groups.
    """
    details = ""
    remediation = ""
    score = 10.0
    status = "Pass"

    try:
        if not shared_data or "ldap_connection" not in shared_data:
            raise ValueError("Missing LDAP connection in shared_data.")

        conn = shared_data["ldap_connection"]
        base_dn = get_base_dn(conn)

        summary = []
        total_admins = 0

        for group in PRIVILEGED_GROUPS:
            users = get_users_in_group(conn, base_dn, group)
            total_admins += len(users)
            summary.append(f"🔐 {group}:\n  - " + "\n  - ".join(users) if users else f"🔐 {group}: (No members)")

        details = "\n\n".join(summary)

        if total_admins > 10:
            score = 4.0
            status = "Warning"
            remediation = (
                "⚠️ Too many privileged accounts.\n"
                "🧹 Review group membership for over-privilege.\n"
                "🔐 Apply least privilege principle."
            )
        elif total_admins == 0:
            score = 5.0
            status = "Info"
            remediation = (
                "ℹ️ No privileged users detected in default groups.\n"
                "👀 Verify if custom privileged groups are used."
            )
        else:
            remediation = "✅ Privileged group membership is within acceptable range."

    except Exception as e:
        score = 0.0
        status = "Error"
        details = f"❌ Failed to enumerate privileged users: {e}"
        remediation = "Check LDAP connection and credentials."

    return {
        "score": score,
        "status": status,
        "details": details,
        "remediation": remediation
    }

if __name__ == "__main__":
    print("Run through AD audit runner or standalone with LDAP connection.")
