# modules/AD_audit/ou_delegation.py

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control

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
        search_filter = "(objectClass=organizationalUnit)"

        # Request security descriptor in search
        controls = security_descriptor_control(sdflags=0x04)  # DACL_SECURITY_INFORMATION
        conn.search(
            search_base,
            search_filter,
            search_scope=SUBTREE,
            attributes=["name", "distinguishedName", "nTSecurityDescriptor"],
            controls=controls
        )

        flagged_ous = []

        for entry in conn.entries:
            dn = str(entry.distinguishedName)
            sd = entry["nTSecurityDescriptor"].raw_values[0] if entry["nTSecurityDescriptor"].raw_values else None

            if sd and b"GenericAll" in sd:
                flagged_ous.append(dn)

        if flagged_ous:
            results["score"] = 4.5
            results["status"] = "Warning"
            results["details"] = (
                f"⚠️ {len(flagged_ous)} Organizational Units have delegation entries with high privileges:\n\n" +
                "\n".join(f"- {dn}" for dn in flagged_ous[:10]) +
                ("\n...and more." if len(flagged_ous) > 10 else "")
            )
            results["remediation"] = (
                "Review and audit delegated permissions on OUs. Avoid granting full control (GenericAll) "
                "to standard users or groups. Use role-based delegation cautiously."
            )
        else:
            results["details"] = "✅ No dangerous OU delegations detected."
            results["remediation"] = "No action required."

        conn.unbind()

    except Exception as e:
        results["score"] = 0.0
        results["status"] = "Error"
        results["details"] = f"❌ Failed to check OU delegation: {e}"
        results["remediation"] = (
            "Ensure the domain controller is reachable and credentials are valid. "
            "Check LDAP permissions and network connectivity."
        )

    return results
