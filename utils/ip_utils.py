import ipaddress

def is_private_ip(ip):
    """
    Check whether the given IP address is private (RFC1918).
    Returns True for private/internal addresses, False otherwise.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        # Handles invalid IP address strings
        return False
