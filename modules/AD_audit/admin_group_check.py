from ldap3 import Server, Connection, ALL, NTLM
import os

# List of high-privilege groups to audit
SENSITIVE_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Administrators"
]

def run_audit(server_address=None, domain=None, username=None, password=None):
    try:
        # Load from env if not passed
        server_address = server_address or os.getenv("LDAP_SERVER")
        domain = domain or os.getenv("LDAP_DOMAIN")
        username = username or os.getenv("LDAP_USERNAME")
        password = password or os.getenv("LDAP_PASSWORD")

        if not all([server_address, domain, username, password]):
            return {
                "score": 0,
                "status": "Error",
                "details": "Missing LDAP connection credentials.",
                "remediation": "Ensure LDAP_SERVER, LDAP_DOMAIN, LDAP_USERNAME, and LDAP_PASSWORD are set."
            }

        server = Server(server_address, get_info=ALL)
        user = f"{domain}\\{username}"
        conn = Connection(server, user=user, password=password, authentication=NTLM, auto_bind=True)

        base_dn = conn.server.info.other['defaultNamingContext'][0]

        drift_issues = []

        for group in SENSITIVE_GROUPS:
            search_filter = f"(&(objectClass=group)(cn={group}))"
            conn.search(base_dn, search_filter, attributes=["member"])

            if not conn.entries:
                continue

            members_dns = conn.entries[0]["member"].values if "member" in conn.entries[0] else []

            for dn in members_dns:
                # Try to extract just the CN or sAMAccountName for display
                conn.search(dn, "(objectClass=*)", attributes=["sAMAccountName"])
                if conn.entries:
                    user_id = conn.entries[0]["sAMAccountName"].value
                    drift_issues.append(f"{group}: {user_id}")

        if not drift_issues:
            return {
                "score": 10.0,
                "status": "Pass",
                "details": "✅ No unauthorized or unexpected users found in critical admin groups.",
                "remediation": "No action needed."
            }

        score = max(0, 10.0 - len(drift_issues) * 2)
        status = "Warning" if score > 4 else "Fail"

        return {
            "score": round(score, 2),
            "status": status,
            "details": "⚠️ Unexpected members found in sensitive admin groups:\n" + "\n".join(f" - {entry}" for entry in drift_issues),
            "remediation": (
                "Review membership of Domain Admins, Enterprise Admins, and Administrators groups.\n"
                "Remove any accounts that are not explicitly approved."
            )
        }

    except Exception as e:
        return {
            "score": 0,
            "status": "Error",
            "details": f"LDAP query failed: {e}",
            "remediation": "Ensure connection to LDAP is valid and credentials have access to read group memberships."
        }
