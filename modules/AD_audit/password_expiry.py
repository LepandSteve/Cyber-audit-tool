# modules/AD_audit/password_expiry.py

from ldap3 import Server, Connection, ALL, NTLM
import traceback

def run_audit(ldap_server, ldap_username, ldap_password):
    try:
        server = Server(ldap_server, get_info=ALL)
        conn = Connection(server, user=ldap_username, password=ldap_password, authentication=NTLM, auto_bind=True)

        # LDAP_MATCHING_RULE_BIT_AND = 1.2.840.113556.1.4.803
        # To find accounts with PASSWD_NOTREQD (0x0020) or DONT_EXPIRE_PASSWD (0x10000) flags
        search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=65536)"  # DONT_EXPIRE_PASSWD

        conn.search(
            search_base=conn.server.info.other["defaultNamingContext"][0],
            search_filter=search_filter,
            attributes=["sAMAccountName", "userAccountControl"]
        )

        accounts = [entry["sAMAccountName"].value for entry in conn.entries]

        if not accounts:
            return {
                "score": 10,
                "status": "Pass",
                "details": "No accounts with 'Password Never Expires' were found.",
                "remediation": "No remediation needed."
            }

        details = "Accounts with non-expiring passwords:\n" + "\n".join(f"- {acc}" for acc in accounts)

        return {
            "score": 3,
            "status": "Fail",
            "details": details,
            "remediation": (
                "Avoid setting passwords to never expire for user accounts. "
                "Enforce a password expiration policy through Group Policy. "
                "Review and update affected accounts."
            )
        }

    except Exception as e:
        return {
            "score": 0,
            "status": "Fail",
            "details": f"Error checking password expiry: {str(e)}\n\n{traceback.format_exc()}",
            "remediation": "Ensure LDAP credentials have permission to query user attributes."
        }
