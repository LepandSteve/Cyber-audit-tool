# modules/AD_audit/gpo_link_check.py

from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPException
import socket

def run_ad_audit(server_address=None, username=None, password=None, domain=None):
    results = {
        "score": 10.0,
        "status": "Pass",
        "details": "All GPOs appear to be properly linked to organizational units.",
        "remediation": "No action required. All GPOs are properly linked."
    }

    try:
        # Auto-detect server if not specified
        if not server_address:
            server_address = socket.getfqdn()

        # Establish connection
        server = Server(server_address, get_info=ALL)
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)

        # Get domain base DN
        conn.search(search_base='', search_filter='(objectClass=*)', search_scope='BASE', attributes=['defaultNamingContext'])
        base_dn = conn.entries[0].defaultNamingContext.value

        # Step 1: Get all GPOs
        conn.search(
            search_base="CN=Policies,CN=System," + base_dn,
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=["name", "displayName"]
        )
        all_gpos = conn.entries
        gpo_dict = {gpo.entry_dn.lower(): gpo.displayName.value for gpo in all_gpos}

        # Step 2: Check where GPOs are linked (in OUs)
        conn.search(
            search_base=base_dn,
            search_filter="(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
            attributes=["gPLink"]
        )

        linked_gpos = set()
        for entry in conn.entries:
            gp_links = entry.gPLink.value
            if gp_links:
                # Extract DN references
                links = [l.split("[")[0] for l in gp_links.strip().split("]") if l]
                linked_gpos.update([link.strip("<> ").lower() for link in links])

        # Step 3: Find unlinked GPOs
        unlinked = []
        for dn, name in gpo_dict.items():
            if dn not in linked_gpos:
                unlinked.append(name or dn)

        if unlinked:
            results["score"] = 4.0
            results["status"] = "Warning"
            results["details"] = f"The following GPOs are not linked to any OU:\n\n" + "\n".join(unlinked)
            results["remediation"] = "Review unlinked GPOs and link them to appropriate OUs if needed, or delete unused GPOs."

        conn.unbind()

    except LDAPException as e:
        results["score"] = 0.0
        results["status"] = "Fail"
        results["details"] = f"LDAP connection error: {e}"
        results["remediation"] = "Ensure the domain controller is reachable and credentials are valid."

    except Exception as ex:
        results["score"] = 0.0
        results["status"] = "Error"
        results["details"] = f"Unexpected error during GPO link check: {ex}"
        results["remediation"] = "Verify the LDAP connection parameters and retry the audit."

    return results
