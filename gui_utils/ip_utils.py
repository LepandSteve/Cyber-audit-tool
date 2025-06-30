
import socket

def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"

def is_valid_ip_or_hostname(value):
    try:
        socket.gethostbyname(value)
        return True
    except:
        return False
