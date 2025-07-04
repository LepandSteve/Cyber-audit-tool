from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from datetime import datetime, timedelta
from typing import Optional, Dict

def run_audit(ip: str = None, username: str = '', password: str = '', domain: str = '', **kwargs) -> Dict:
    try:
        server = Server(ip, get_info=ALL)
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)

        # Base DN extraction
        default_naming_context = server.info.other['defaultNamingContext'][0]

        # Fetch some AD objects
        conn.search(
            search_base=default_naming_context,
            search_filter='(objectClass=organizationalUnit)',
            search_scope=SUBTREE,
            attributes=['ou']
        )
        ous = [entry['attributes']['ou'] for entry in conn.entries]

        conn.search(
            search_base=default_naming_context,
            search_filter='(objectClass=user)',
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'userPrincipalName', 'lastLogonTimestamp']
        )
        users = []
        for entry in conn.entries:
            attrs = entry.entry_attributes_as_dict
            users.append({
                'username': attrs.get('sAMAccountName', ''),
                'principal': attrs.get('userPrincipalName', ''),
                'lastLogon': convert_windows_timestamp(attrs.get('lastLogonTimestamp'))
            })

        conn.search(
            search_base=default_naming_context,
            search_filter='(objectClass=computer)',
            search_scope=SUBTREE,
            attributes=['cn']
        )
        computers = [entry['attributes']['cn'] for entry in conn.entries]

        conn.search(
            search_base=default_naming_context,
            search_filter='(objectClass=group)',
            search_scope=SUBTREE,
            attributes=['cn']
        )
        groups = [entry['attributes']['cn'] for entry in conn.entries]

        details = (
            f"🌐 Domain Info: {default_naming_context}\n\n"
            f"📁 OUs Found: {len(ous)}\n"
            f"👥 Users Found: {len(users)}\n"
            f"💻 Computers Found: {len(computers)}\n"
            f"🛡️ Groups Found: {len(groups)}\n"
        )

        remediation = (
            "🔍 Review OU structure for excessive nesting.\n"
            "👤 Verify inactive or stale user accounts.\n"
            "🛡️ Check group memberships for privilege overuse."
        )

        return {
            "score": 10.0,
            "status": "Pass",
            "details": details,
            "remediation": remediation,
            "objects": {
                "ous": ous,
                "users": users,
                "computers": computers,
                "groups": groups
            }
        }

    except Exception as e:
        return {
            "score": 0.0,
            "status": "Error",
            "details": f"❌ LDAP Enumeration failed: {e}",
            "remediation": "📡 Ensure valid credentials, domain name, and LDAP port access (389 or 636)."
        }

def convert_windows_timestamp(win_ts):
    try:
        if isinstance(win_ts, list):
            win_ts = int(win_ts[0])
        if isinstance(win_ts, int) and win_ts > 0:
            return (datetime(1601, 1, 1) + timedelta(microseconds=win_ts // 10)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "N/A"
