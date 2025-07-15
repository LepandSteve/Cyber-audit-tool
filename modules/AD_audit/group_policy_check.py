# modules/AD_audit/group_policy_check.py

from ldap3 import Connection
from typing import Dict

def run_audit(shared_data=None) -> Dict:
    """
    Audit Group Policy Objects via LDAP.
    """

    if not shared_data or "ldap_conn" not in shared_data:
        return {
            "score": 0.0,
            "status": "Skipped",
            "details": "❌ No LDAP connection found in shared data.",
            "remediation": "Ensure LDAP enumeration is performed before this module."
        }

    conn: Connection = shared_data["ldap_conn"]
    domain_base = shared_data.get("ldap_base_dn", "")

    findings = []
    score = 10.0
    flagged = False

    try:
        conn.search(
            search_base=f"CN=Policies,CN=System,{domain_base}",
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=["displayName", "gPCFileSysPath", "whenChanged"]
        )

        if not conn.entries:
            return {
                "score": 10.0,
                "status": "Pass",
                "details": "✅ No GPOs found or GPO container is empty.",
                "remediation": "No issues detected."
            }

        for entry in conn.entries:
            name = entry.displayName.value
            path = entry.gPCFileSysPath.value
            date = entry.whenChanged.value

            # Simple heuristic checks
            issues = []
            if path and ("\\scripts" in path.lower() or "\\netlogon" in path.lower()):
                issues.append("📁 GPO contains script path (check for login scripts).")

            if "cpassword" in str(entry):
                issues.append("🔑 Potential embedded password (cpassword) found in GPO.")

            if issues:
                flagged = True
                findings.append(f"❗ GPO: {name}\nPath: {path}\nChanged: {date}\nIssues:\n- " + "\n- ".join(issues) + "\n")
                score -= 2.5  # Reduce score per issue group
            else:
                findings.append(f"✅ GPO: {name} - No known risky patterns detected.")

        status = "Warning" if flagged else "Pass"
        score = max(0.0, score)

        return {
            "score": score,
            "status": status,
            "details": "\n\n".join(findings),
            "remediation": (
                "🛡️ Review GPOs containing login scripts or cpassword values.\n"
                "✔️ Avoid embedding passwords in SYSVOL.\n"
                "🧼 Sanitize or remove legacy GPOs that are unused or unsafe."
            )
        }

    except Exception as e:
        return {
            "score": 0.0,
            "status": "Error",
            "details": f"❌ Exception during GPO enumeration: {e}",
            "remediation": "Verify LDAP connectivity and privileges."
        }

