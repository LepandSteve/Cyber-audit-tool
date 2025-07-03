import subprocess
import threading
import os

def get_nmap_path() -> str:
    """
    Determine the path to the Nmap executable.

    Returns:
        str: Full path to nmap.exe or just "nmap" if using system PATH.
    """
    local_path = os.path.join("external", "nmap", "nmap.exe")
    return local_path if os.path.exists(local_path) else "nmap"

def run_nmap_scan(ip_address: str, cancel_event: threading.Event) -> str:
    if cancel_event.is_set():
        return "⏹️ Nmap scan canceled."

    try:
        result = subprocess.run(
            [
                "nmap", "-T4",
                "-p", "21,22,23,25,53,80,110,139,143,443,445,3306,3389,5900,8080",
                "-sS", "-sV", "--script", "vuln", "-n", "-Pn", ip_address
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=90,  # Vulnerability scripts may take longer
            check=True
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "⏰ Nmap scan timed out."
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.strip() if e.stderr else e.stdout.strip()
        return f"❌ Nmap scan error: {error_output}"
    except FileNotFoundError:
        return "❌ Nmap executable not found. Please install Nmap and ensure it is in your PATH."
    except Exception as e:
        return f"❌ Unexpected error running nmap: {e}"


def extract_open_ports(nmap_output: str) -> list[int]:
    """
    Extract open ports from nmap scan output.

    Args:
        nmap_output (str): Raw nmap command output.

    Returns:
        list[int]: List of open port numbers.
    """
    open_ports = []
    lines = nmap_output.splitlines()
    parsing = False
    for line in lines:
        if line.strip().startswith("PORT"):
            parsing = True
            continue
        if parsing:
            if not line.strip():
                break  # End of ports section
            parts = line.split()
            if len(parts) >= 2 and '/' in parts[0] and parts[1].lower() == "open":
                try:
                    port = int(parts[0].split('/')[0])
                    open_ports.append(port)
                except ValueError:
                    continue
    return open_ports

def run_audit(ip=None, banners=None, open_ports=None, shared_data=None, cancel_event=None):
    """
    Run the network scan audit module.

    Args:
        ip (str): Target IP address to scan.
        banners (dict): Optional pre-fetched service banners (unused here).
        open_ports (list): Optional open ports list (unused here).
        shared_data (dict): Shared data dict to store scan results and open ports.
        cancel_event (threading.Event): Event to signal cancellation.

    Returns:
        dict: Audit result containing 'score', 'status', 'details', and 'remediation'.
    """
    if ip is None:
        return {
            "score": 0.0,
            "status": "Error",
            "details": "❗ No IP provided for network scan.",
            "remediation": "Make sure the target IP is passed to the audit module."
        }

    if cancel_event is None:
        cancel_event = threading.Event()

    output = run_nmap_scan(ip, cancel_event)

    output_lower = output.lower()
    if "canceled" in output_lower:
        score = 5.0
        status = "Warning"
        remediation = "⏳ The scan was canceled. Try again to complete it."
    elif any(x in output_lower for x in ["error", "timed out", "not found"]):
        score = 0.0
        status = "Fail"
        remediation = (
            "🛠️ Ensure Nmap is installed and accessible from your system PATH.\n"
            "📁 Or copy Nmap to 'external/nmap/' folder in this project.\n"
            "🌐 Check target availability.\n"
            "⏱️ Increase timeout if target is slow to respond."
        )
    else:
        score = 10.0
        status = "Pass"
        remediation = "✅ No issues found. Review Nmap output for open ports or risky services."

    details = f"🧪 Nmap results for {ip}:\n{output.strip()}"

    # Extract open ports and share with other modules
    if shared_data is not None:
        open_ports_extracted = extract_open_ports(output)
        shared_data['open_ports'] = open_ports_extracted
        shared_data['scan_result'] = {
            "score": score,
            "status": status,
            "details": details,
            "remediation": remediation,
        }

    return {
        "score": score,
        "status": status,
        "details": details,
        "remediation": remediation
    }

if __name__ == "__main__":
    test_ip = "8.8.8.8"
    result = run_audit(ip=test_ip)
    print(f"Score: {result['score']}\nStatus: {result['status']}\nDetails:\n{result['details']}\nRemediation:\n{result['remediation']}")
