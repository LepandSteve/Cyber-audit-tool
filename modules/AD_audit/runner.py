# modules.AD_audit.runner.py

import inspect
from typing import Optional, Callable, Dict
from ldap3 import Server, Connection, ALL, NTLM

from modules.AD_audit import (
    ad_enum,
    kerberos_check,
    group_policy_check,
    password_policy,
    privileged_users,
    account_lockout,
    inactive_accounts,
    service_accounts,
    admin_group_check,
    delegation_check,
    password_expiry,
    spn_exposure,
    ou_delegation,
    domain_trust,
    gpo_link_check
)

MODULES_MAP = {
    "ad_enum": ad_enum,
    "kerberos_check": kerberos_check,
    "group_policy_check": group_policy_check,
    "password_policy": password_policy,
    "privileged_users": privileged_users,
    "account_lockout": account_lockout,
    "inactive_accounts": inactive_accounts,
    "service_accounts": service_accounts,
    "admin_group_check": admin_group_check,
    "delegation_check": delegation_check,
    "password_expiry": password_expiry,
    "spn_exposure": spn_exposure,
    "ou_delegation": ou_delegation,
    "domain_trust": domain_trust,
    "gpo_link_check": gpo_link_check
}


def connect_to_ldap(server_address: str, username: str, password: str) -> Optional[Connection]:
    try:
        server = Server(server_address, get_info=ALL)
        conn = Connection(server, user=username, password=password, authentication=NTLM, auto_bind=True)
        return conn
    except Exception as e:
        print(f"❌ LDAP connection failed: {e}")
        return None

def run_full_ad_audit(
    ldap_server: str,
    ldap_username: str,
    ldap_password: str,
    selected_modules=None,
    progress_callback: Optional[Callable] = None,
    stop_event=None
) -> Dict:

    if selected_modules is None:
        selected_modules = list(MODULES_MAP.keys())

    results = {}
    shared_data = {}

    # Step 1: Connect to LDAP
    conn = connect_to_ldap(ldap_server, ldap_username, ldap_password)
    if not conn:
        return {
            "final_score": 0.0,
            "overall_status": "Fail",
            "module_scores": {
                mod: {
                    "score": 0.0,
                    "status": "Error",
                    "details": "❌ LDAP connection failed.",
                    "remediation": "🔑 Check server address, credentials, and firewall access."
                } for mod in selected_modules
            }
        }

    shared_data["ldap_connection"] = conn

    total_modules = len(selected_modules)

    def send_progress(message, percent, module_name=None, current=0, total=0):
        if progress_callback:
            progress_callback((message, percent, module_name, current, total))

    send_progress("🔍 Starting AD audit...", 0, None, 0, total_modules)

    for idx, mod_name in enumerate(selected_modules, start=1):
        if stop_event and stop_event.is_set():
            for m in selected_modules:
                if m not in results:
                    results[m] = {
                        "score": 0.0,
                        "status": "Cancelled",
                        "details": "⏹️ Audit cancelled by user.",
                        "remediation": "Restart the audit to complete this module."
                    }
            send_progress("Audit cancelled by user.", 100, None, idx, total_modules)
            break

        try:
            percent = int((idx - 1) / total_modules * 90) + 10
            send_progress(f"🔄 Running {mod_name} ({idx}/{total_modules})", percent, mod_name, idx, total_modules)

            module = MODULES_MAP[mod_name]
            run_func = getattr(module, "run_audit", None)

            if not callable(run_func):
                raise ValueError(f"{mod_name} has no valid run_audit() function.")

            sig = inspect.signature(run_func)
            supported_args = sig.parameters.keys()
            all_kwargs = {"shared_data": shared_data}
            filtered_kwargs = {k: v for k, v in all_kwargs.items() if k in supported_args}

            result = run_func(**filtered_kwargs)
            if not isinstance(result, dict):
                raise ValueError("run_audit() did not return a dictionary")

            results[mod_name] = result
            send_progress(f"✅ Completed {mod_name}", int(idx / total_modules * 90) + 10, mod_name, idx, total_modules)

        except Exception as e:
            results[mod_name] = {
                "score": 0.0,
                "status": "Error",
                "details": f"❌ Error in module {mod_name}: {e}",
                "remediation": "⚙️ Check module logic and input compatibility."
            }
            send_progress(f"⚠️ {mod_name} failed.", int(idx / total_modules * 90) + 10, mod_name, idx, total_modules)

    send_progress("🎯 AD Audit complete.", 100, None, total_modules, total_modules)

    # Compute final score and status
    valid_scores = [m["score"] for m in results.values() if isinstance(m, dict) and "score" in m]
    final_score = round(sum(valid_scores) / len(valid_scores), 2) if valid_scores else 0.0
    overall_status = (
        "Fail" if final_score < 4.0 else
        "Warning" if final_score < 7.0 else
        "Pass"
    )

    return {
        "final_score": final_score,
        "overall_status": overall_status,
        "module_scores": results
    }

if __name__ == "__main__":
    # Example manual test
    results = run_full_ad_audit(
        ldap_server="ldap://your.domain.com",
        ldap_username="DOMAIN\\admin_user",
        ldap_password="your_password"
    )
    from pprint import pprint
    pprint(results)
