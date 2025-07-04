import requests

def check_latest_version(current_version, version_info_url):
    """
    Check if a newer version is available.

    Args:
        current_version (str): Current app version, e.g. "1.0.0"
        version_info_url (str): URL to JSON file with latest version info.

    Returns:
        dict: {
            "update_available": bool,
            "latest_version": str,
            "download_url": str or None,
            "message": str,
        }
    """
    try:
        resp = requests.get(version_info_url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        latest_version = data.get("version", "")
        download_url = data.get("download_url", None)

        def version_tuple(v):
            return tuple(int(x) for x in v.split('.'))

        if version_tuple(latest_version) > version_tuple(current_version):
            return {
                "update_available": True,
                "latest_version": latest_version,
                "download_url": download_url,
                "message": f"New version {latest_version} is available.",
            }
        else:
            return {
                "update_available": False,
                "latest_version": latest_version,
                "download_url": download_url,
                "message": "You are running the latest version.",
            }

    except Exception as e:
        return {
            "update_available": False,
            "latest_version": None,
            "download_url": None,
            "message": f"Failed to check latest version: {e}",
        }
