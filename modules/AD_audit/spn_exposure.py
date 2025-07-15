# modules/AD_audit/spn_exposure.py

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE


def run_ad_audit(domain_controller, domain_name, username, password):
    results = {
        "score": 10.0,
        "status": "Pass",
        "details": "",
        "remediation": ""
    }

    try:
        server = Server(domain_controller, get_info=ALL)
        conn = Connection(
            server,
            user=f"{domain_name}\\{username}",
            password=password,
            authentication=NTLM,
            auto_bind=True
        )

        search_base = f"DC={'DC='.join(domain_name.split('.'))}"
        search_filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"

        conn.search(search_base, search_filter, search_scope=SUBTREE, attributes=["cn", "servicePrincipalName"])

        spn_accounts = []
        for entry in conn.entries:
            spn_accounts.append({
                "cn": str(entry.cn),
                "spns": [str(spn) for spn in entry.servicePrincipalName]
            })

        if spn_accounts:
            results["score"] = 5.0
            results["status"] = "Warning"
            results["details"] = (
                f"⚠️ {len(spn_accounts)} user accounts have SPNs set and may be vulnerable to Kerberoasting:\n\n" +
                "\n".join([f"- {acct['cn']}: {', '.join(acct['spns'])}" for acct in spn_accounts[:10]]) +
                ("\n...and more." if len(spn_accounts) > 10 else "")
            )
            results["remediation"] = (
                "Review accounts with SPNs and ensure they are necessary. Use managed service accounts "
                "or gMSAs where possible. Monitor for unusual SPN requests in logs."
            )
        else:
            results["details"] = "✅ No user accounts with SPNs detected. No exposure to Kerberoasting."
            results["remediation"] = "No action needed."

        conn.unbind()

    except Exception as e:
        results["score"] = 0.0
        results["status"] = "Error"
        results["details"] = f"❌ Error checking SPN exposure: {e}"
        results["remediation"] = "Ensure the domain controller is reachable and credentials are valid."

    return results
