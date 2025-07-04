import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from typing import Dict

def run_audit(ip: str = "", shared_data=None) -> Dict:
    details = ""
    risky_users = []

    try:
        domain = shared_data.get("domain", "")
        username = shared_data.get("username", "")
        password = shared_data.get("password", "")
        base_dn = shared_data.get("base_dn", "")

        server = Server(ip, get_info=ALL)
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)

        conn.search(
            search_base=base_dn,
            search_filter="(&(objectClass=user)(!(objectClass=computer)))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "userAccountControl", "msDS-SupportedEncryptionTypes"]
        )

        for entry in conn.entries:
            user = entry["sAMAccountName"].value
            uac = int(entry["userAccountControl"].value)
            enc_types = entry["msDS-SupportedEncryptionTypes"].value

            # Check for AS-REP Roasting risk (no preauth required)
            if uac & 0x00400000:  # DONT_REQ_PREAUTH
                risky_users.append(user)

            if enc_types is None:
                enc_info = "N/A"
            else:
                enc_info = f"{enc_types} (may include RC4 or DES)"

            details += f"🧑 User: {user}\n"
            details += f"   ↳ UAC Flags: {uac}\n"
            details += f"   ↳ Encryption: {enc_info}\n"
            if user in risky_users:
                details += "   ⚠️ No Preauth Required (AS-REP Roasting risk)\n"
            details += "\n"

        conn.unbind()

        if risky_users:
            status = "Warning"
            score = 5.0
            remediation = (
                "⚠️ Some accounts allow logon without Kerberos preauthentication.\n"
                "➡️ Mitigation:\n"
                " - Remove 'Do not require Kerberos preauthentication' flag on user accounts.\n"
                " - Audit and rotate passwords for these accounts."
            )
        else:
            status = "Pass"
            score = 10.0
            remediation = "✅ No risky Kerberos settings detected."

    except Exception as e:
        status = "Error"
        score = 0.0
        details = f"❌ Kerberos audit failed: {e}"
        remediation = (
            "❌ Could not query Kerberos settings.\n"
            "➡️ Verify:\n"
            " - LDAP connection to the domain controller.\n"
            " - Correct domain credentials in shared_data.\n"
            " - NTLM auth is enabled."
        )

    return {
        "score": score,
        "status": status,
        "details": details.strip(),
        "remediation": remediation
    }
