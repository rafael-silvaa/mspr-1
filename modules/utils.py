import os
import socket

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def wait_for_user():
    input("\nAppuyez sur Entrée pour continuer...")

def detect_os_type(ip):
    """
    OS detection using hybrid approach:
    1. TTL-based detection
    2. Multi-port fingerprinting
    return : 'linux_ssh', 'windows_remote', 'unknown'
    """
    import subprocess
    import platform
    import re
    
    # 1: try TTL-based detection
    ttl_result = _detect_by_ttl(ip)
    if ttl_result != 'unknown':
        # verify with port check to avoid false positives
        port_result = _detect_by_ports(ip)
        if port_result != 'unknown':
            return port_result
        return ttl_result
    
    # 2: fallback to multi-port fingerprinting
    return _detect_by_ports(ip)

def _detect_by_ttl(ip):
    """
    detect OS by TTL value in ping response
    windows uses TTL=128, Linux uses TTL=64
    """
    import subprocess
    import platform
    import re
    
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                   capture_output=True, text=True, timeout=2)
            match = re.search(r'TTL=(\d+)', result.stdout, re.IGNORECASE)
        else:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip],
                                   capture_output=True, text=True, timeout=2)
            match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
        
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:
                return "linux_ssh"
            elif ttl >= 100:  # margin for network hops
                return "windows_remote"
    except:
        pass
    
    return "unknown"

def _detect_by_ports(ip):
    """
    multi-port fingerprinting for more accurate OS detection
    checks multiple ports to create a signature
    """
    ports_to_check = {
        22: 'ssh',
        135: 'win_rpc',      # Windows RPC
        139: 'win_netbios',  # NetBIOS
        445: 'smb',          # SMB (both)
        3389: 'rdp',         # RDP
    }
    
    open_ports = {}
    for port, service in ports_to_check.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            open_ports[service] = True
    
    if open_ports.get('win_rpc'):
        return "windows_remote"
    
    if open_ports.get('smb') and open_ports.get('rdp'):
        return "windows_remote"
    
    if open_ports.get('win_netbios') and open_ports.get('smb'):
        return "windows_remote"
    
    if open_ports.get('ssh') and not open_ports.get('win_rpc'):
        return "linux_ssh"
    
    return "unknown"