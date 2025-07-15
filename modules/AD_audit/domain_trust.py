# modules/AD_audit/domain_trusts.py

from ldap3 import Server, Connection, ALL, NTLM
import traceback

def run_audit(ldap_server, ldap_username, ldap_password):
    try:
        server = Server(ldap_server, get_info=ALL)
        conn = Connection(server, user=ldap_username, password=ldap_password, authentication=NTLM, auto_bind=True)

        conn.search(
            search_base="CN=System," + conn.server.info.other["defaultNamingContext"][0],
            search_filter="(objectClass=trustedDomain)",
            attributes=["cn", "trustPartner", "trustDirection", "trustType", "trustAttributes"]
        )

        trusts = []
        for entry in conn.entries:
            trust_info = {
                "Name": str(entry.cn),
                "Partner": str(entry.trustPartner),
                "Direction": str(entry.trustDirection),
                "Type": str(entry.trustType),
                "Attributes": str(entry.trustAttributes)
            }
            trusts.append(trust_info)

        if not trusts:
            return {
                "score": 10,
                "status": "Pass",
                "details": "No domain trust relationships were found.",
                "remediation": "No remediation needed."
            }

        trust_details = "\n".join(
            [f"- Trust with {t['Partner']}: Type {t['Type']}, Direction {t['Direction']}, Attributes {t['Attributes']}" for t in trusts]
        )

        return {
            "score": 5,
            "status": "Warning",
            "details": f"Found domain trust relationships:\n{trust_details}",
            "remediation": (
                "Review each trust relationship to ensure it's still required. "
                "Remove or disable any unnecessary or unverified trusts. "
                "Verify trust types and directions align with security policy."
            )
        }

    except Exception as e:
        return {
            "score": 0,
            "status": "Fail",
            "details": f"Error querying domain trusts: {str(e)}\n\n{traceback.format_exc()}",
            "remediation": "Ensure the LDAP credentials have permissions to query trustedDomain objects."
        }
