# modules.AD_audit.service_accounts.py

from ldap3 import Connection
from typing import Dict, Optional

def run_audit(shared_data: Optional[dict] = None, **kwargs) -> Dict:
    score = 10.0
    status = "Pass"
    details = ""
    remediation = ""

    try:
        if not shared_data or "ldap_connection" not in shared_data:
            raise ValueError("Missing LDAP connection in shared_data.")
        
        conn: Connection = shared_data["ldap_connection"]
        base_dn = conn.server.info.other['defaultNamingContext'][0]

        # Heuristic filter: Accounts with 'svc', 'service', or 'sa' in their name
        conn.search(
            search_base=base_dn,
            search_filter="(&(objectClass=user)(|(sAMAccountName=*svc*)(sAMAccountName=*service*)(sAMAccountName=*sa*)))",
            attributes=["sAMAccountName", "description", "userAccountControl"]
        )

        accounts = []
        for entry in conn.entries:
            username = entry.sAMAccountName.value
            desc = entry.description.value if entry.description else "No description"
            accounts.append(f"🔧 {username} — {desc}")

        if accounts:
            score = 6.0
            status = "Warning"
            details = (
                f"🔍 Service accounts found by heuristic search:\n" +
                "\n".join(accounts)
            )
            remediation = (
                "🛠 Review these accounts to ensure:\n"
                "- 🔐 They follow the principle of least privilege.\n"
                "- 🔄 Their credentials are rotated regularly.\n"
                "- 📜 They're not used for interactive logins unless justified.\n"
                "- 🔍 Their usage is logged and monitored."
            )
        else:
            details = "✅ No service accounts matched common patterns (e.g. svc*, service*, sa*)."
            remediation = "✅ No action required."

    except Exception as e:
        score = 0.0
        status = "Error"
        details = f"❌ Failed to detect service accounts: {e}"
        remediation = "📡 Verify LDAP connectivity and search permissions."

    return {
        "score": score,
        "status": status,
        "details": details,
        "remediation": remediation
    }

if __name__ == "__main__":
    print("Run this module using the AD audit runner.")
