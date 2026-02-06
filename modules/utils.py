import os
import socket

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def wait_for_user():
    input("\nAppuyez sur Entrée pour continuer...")

def detect_os_type(ip):
    """
    tente de deviner l'OS en fonction des ports ouverts
    return : 'linux_ssh', 'windows_remote', 'unknown'
    """
    # liste ports témoins
    PORT_SSH = 22
    PORT_WIN_SMB = 445
    PORT_WIN_RDP = 3389
    
    # test SSH (Linux ?)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1) 
    result = sock.connect_ex((ip, PORT_SSH))
    sock.close()
    
    if result == 0:
        return "linux_ssh"
        
    # test win (SMB ou RDP)
    for port in [PORT_WIN_SMB, PORT_WIN_RDP]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            return "windows_remote"

    return "unknown"