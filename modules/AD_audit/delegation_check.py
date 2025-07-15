from ldap3 import Server, Connection, ALL, NTLM
import os

def run_audit(server_address=None, domain=None, username=None, password=None):
    try:
        # Use environment variables if not provided
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

        # Unconstrained Delegation: userAccountControl bit 0x80000 (524288)
        conn.search(
            search_base=conn.server.info.other['defaultNamingContext'][0],
            search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
            attributes=['cn', 'userAccountControl']
        )
        unconstrained = [entry['attributes']['cn'] for entry in conn.entries]

        # Constrained Delegation: msDS-AllowedToDelegateTo present
        conn.search(
            search_base=conn.server.info.other['defaultNamingContext'][0],
            search_filter='(msDS-AllowedToDelegateTo=*)',
            attributes=['cn', 'msDS-AllowedToDelegateTo']
        )
        constrained = []
        for entry in conn.entries:
            cn = entry['attributes']['cn']
            targets = entry['attributes'].get('msDS-AllowedToDelegateTo', [])
            constrained.append(f"{cn} → {', '.join(targets)}")

        total_issues = len(unconstrained) + len(constrained)

        if total_issues == 0:
            return {
                "score": 10.0,
                "status": "Pass",
                "details": "✅ No accounts with delegation rights found.",
                "remediation": "No action needed."
            }
        else:
            details = ""
            if unconstrained:
                details += f"❗ Unconstrained Delegation Accounts ({len(unconstrained)}):\n"
                details += "\n".join(f" - {u}" for u in unconstrained) + "\n\n"

            if constrained:
                details += f"⚠️ Constrained Delegation Accounts ({len(constrained)}):\n"
                details += "\n".join(f" - {c}" for c in constrained)

            score = max(0, 10.0 - total_issues * 1.5)
            status = "Warning" if score > 4 else "Fail"

            return {
                "score": round(score, 2),
                "status": status,
                "details": details.strip(),
                "remediation": (
                    "Review the listed accounts with delegation rights. "
                    "Remove unconstrained delegation where not absolutely needed. "
                    "Use constrained delegation carefully and only to trusted services."
                )
            }

    except Exception as e:
        return {
            "score": 0,
            "status": "Error",
            "details": f"LDAP connection or query failed: {e}",
            "remediation": "Ensure credentials are valid and the domain controller is reachable."
        }
