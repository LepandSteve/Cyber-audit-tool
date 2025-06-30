import platform
import subprocess
import socket
import ipaddress
from utils.ip_utils import is_private_ip


def audit_firewall():
    """
    Check the local firewall status based on OS-specific commands.
    Returns a dict with score, status, details, remediation.
    """
    system = platform.system()

    try:
        if system == "Windows":
            result = subprocess.run([
                "netsh", "advfirewall", "show", "allprofiles"
            ], capture_output=True, text=True, check=True)
            output = result.stdout.lower()

            if "state on" in output:
                detected = True
                details = "🛡️ Windows Firewall is enabled. All profiles show state ON."
                remediation = "✅ No action needed."
            else:
                detected = False
                details = "❌ Windows Firewall appears to be disabled."
                remediation = (
                    "🔧 Remediation:\n"
                    "- GUI: Control Panel > System and Security > Windows Defender Firewall\n"
                    "- CLI: Run `netsh advfirewall set allprofiles state on` in Command Prompt"
                )

        elif system == "Linux":
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            output = result.stdout.lower()
            if "status: active" in output:
                detected = True
                details = "🛡️ UFW Firewall is active on Linux."
                remediation = "✅ No action needed."
            elif "inactive" in output:
                detected = False
                details = "❌ UFW Firewall is inactive."
                remediation = "🔧 Run `sudo ufw enable` to activate UFW, or configure iptables/nftables manually."
            else:
                result = subprocess.run(["iptables", "-L"], capture_output=True, text=True)
                output = result.stdout
                if "Chain" in output:
                    detected = True
                    details = "🛡️ iptables is configured (Linux firewall rules present)."
                    remediation = "✅ No action needed."
                else:
                    detected = False
                    details = "❌ iptables appears unconfigured."
                    remediation = "🔧 Set up iptables rules or enable UFW for easier management."

        elif system == "Darwin":
            result = subprocess.run([
                "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"
            ], capture_output=True, text=True)
            output = result.stdout.lower()
            if "enabled" in output:
                detected = True
                details = "🛡️ macOS Application Firewall is enabled."
                remediation = "✅ No action needed."
            else:
                detected = False
                details = "❌ macOS Firewall appears to be disabled."
                remediation = "🔧 Go to System Settings > Network > Firewall and enable it."
        else:
            detected = None
            details = "⚠️ Firewall check unsupported on this OS."
            remediation = "ℹ️ Use an OS-specific method to verify firewall status."

    except FileNotFoundError:
        detected = False
        details = "❌ Firewall tools not found."
        remediation = "🔧 Ensure tools like `ufw`, `iptables`, or `netsh` are installed and accessible."
    except subprocess.CalledProcessError as e:
        detected = False
        details = f"❌ Error while checking firewall: {e}"
        remediation = "🔧 Manually inspect firewall settings or check script permissions."

    score = 10.0 if detected is True else 0.0 if detected is False else 5.0
    status = "Pass" if detected is True else "Fail" if detected is False else "Warning"

    return {
        "score": score,
        "status": status,
        "details": details,
        "remediation": remediation
    }


def infer_remote_firewall(ip, ports=None):
    if ports is None:
        ports = [22, 80, 443, 3389]

    filtered = []
    responded = []

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    responded.append(port)
                else:
                    filtered.append(port)
        except Exception:
            filtered.append(port)

    if len(filtered) == len(ports):
        score = 10.0
        status = "Pass"
        details = f"🔒 All tested ports appear filtered on {ip}. Firewall likely active."
        remediation = "✅ No action needed unless services are not reachable as expected."
    elif filtered:
        score = 6.0
        status = "Warning"
        details = f"⚠️ Some ports are filtered on {ip}: {filtered}."
        remediation = "🔧 Review firewall rules to ensure only required ports are exposed."
    else:
        score = 2.0
        status = "Fail"
        details = f"❌ No port filtering detected on {ip}. Firewall may not be active."
        remediation = "🔧 Ensure a firewall is in place to block unused or sensitive ports."

    return {
        "score": score,
        "status": status,
        "details": details,
        "remediation": remediation
    }


def is_local_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback
    except ValueError:
        return False


def run_audit(ip=None, banners=None, is_private=None, open_ports=None, shared_data=None):  # ✅ Added shared_data
    if not ip or is_local_ip(ip):
        return audit_firewall()

    if is_private:
        base_result = {
            "score": 8.0,
            "status": "Info",
            "details": f"ℹ️ {ip} is a private/internal IP. Inference is limited.",
            "remediation": "Ensure internal firewalls are configured via network security policy."
        }
        remote_result = infer_remote_firewall(ip, ports=open_ports)
        base_result["details"] += "\n" + remote_result["details"]
        base_result["remediation"] += "\n" + remote_result["remediation"]
        return base_result

    return infer_remote_firewall(ip, ports=open_ports)


if __name__ == "__main__":
    result = run_audit(ip="8.8.8.8", open_ports=[22, 80, 443])
    print(f"Score: {result['score']}")
    print(f"Status: {result['status']}")
    print("Details:\n" + result['details'])
    print("Remediation:\n" + result['remediation'])
