import socket
import json
import os
import csv
import ipaddress
import platform
import subprocess
import requests
import concurrent.futures
from datetime import datetime, timedelta
from .utils import *

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "configs", "audit.json")
LOGS_DIR = os.path.join(os.path.dirname(BASE_DIR), "logs")

# mapping API endoflife.date
API_MAPPING = {
    "Windows Server 2016": ("windows-server", "2016"),
    "Windows Server 2019": ("windows-server", "2019"),
    "Windows Server 2022": ("windows-server", "2022"),
    "Ubuntu 20.04 LTS": ("ubuntu", "20.04"),
    "CentOS 7": ("centos", "7"),
    "Windows 10": ("windows", "10"),
    "VMware ESXi 6.5": ("vmware-esxi", "6.5-6.7"),
    "pfSense 2.7.2": ("freebsd", "label:stable/14")
}

KNOWN_HOSTS = {
    "192.168.10.10": "Windows Server 2016", # DC01
    "192.168.10.11": "Windows Server 2016",
    "192.168.10.21": "Ubuntu 20.04 LTS",
    "192.168.10.22": "Ubuntu 20.04 LTS",
    "192.168.10.40": "CentOS 7",
    "192.168.10.50": "Windows Server 2019",
    "192.168.10.254": "pfSense 2.7.2"
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"[ERREUR] Config introuvable : {CONFIG_FILE}")
        return None
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERREUR] Lecture JSON : {e}")
        return None

def fetch_eol_date_from_api(product, version):
    url = f"https://endoflife.date/api/v1/products/{product}"

    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            data = response.json()

            releases = []
            if isinstance(data, list):
                releases = data
            elif isinstance(data, dict):
                releases = data.get("result", {}).get("releases", [])

            target_field = "name"
            target_value = str(version)

            if ":" in target_value:
                parts = target_value.split(":", 1)
                target_field = parts[0]
                target_value = parts[1]

            # cherche cycle correspondant (ex: 20.04)
            for release in releases:
                actual_value = release.get(target_field)

                if str(actual_value) == target_value:
                    eol_date = release.get('eolFrom') or release.get('eol')
                    
                    if isinstance(eol_date, str) and len(eol_date) >= 10:
                        return eol_date[:10]
                    
                    return str(eol_date)
    except Exception:
        return None
    return "Erreur API", "N/A"

def get_eol_status(os_name):
    """verif obsolescence via API"""
    if os_name not in API_MAPPING:
        return "INCONNU (Pas de mapping API)", "N/A"
    
    product_slug, version = API_MAPPING[os_name]
    
    # appel API
    eol_date_str = fetch_eol_date_from_api(product_slug, version)
    
    # fallback si API échoue (mode hors ligne ou API down)
    if not eol_date_str:
        return "ERREUR API (Vérifier Internet)", "N/A"

    # comparaison de date
    try:
        eol_date = datetime.strptime(eol_date_str, "%Y-%m-%d")
        today = datetime.now()
        warning = today + timedelta(days=180)
        
        if today > eol_date:
            return "Obsolète", eol_date_str
        elif warning > eol_date:
            return "Bientôt obsolète!", eol_date_str
        else:
            return "Supporté", eol_date_str
    except ValueError:
        return "Date invalide", eol_date_str

def scan_single_host(ip_str, ports_to_scan):
    open_ports = []
    is_alive = False

    # test ports
    for port in ports_to_scan:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        res = sock.connect_ex((ip_str, port))
        sock.close()
        if res == 0:
            is_alive = True
            open_ports.append(port)
            # if port open = host alive

    return ip_str, is_alive, open_ports

def scan_subnet_and_export(profile, ports_to_scan):
    """scan network, OS & EOL + CSV"""
    
    cidr = profile['cidr']
    net_name = profile['network_name']
    
    print(f"\n[*] Démarrage de l'audit sur : {net_name} ({cidr})")
    
    # prep fichier CSV
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
        
    safe_name = "".join([c if c.isalnum() else "_" for c in net_name])
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"AUDIT_{safe_name}_{timestamp}.csv"
    filepath = os.path.join(LOGS_DIR, filename)

    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        print("[!] CIDR invalide.")
        return

    all_hosts = list(network.hosts())
    total_hosts = len(all_hosts)
    print(f"[*] Analyse de {total_hosts} adresses IPs...")

    results_to_write = []

    # scan parallele
    with concurrent.futures.ThreadPoolExecutor(max_workers=127) as executor:
        futures = {executor.submit(scan_single_host, str(ip), ports_to_scan): ip for ip in all_hosts}

        for future in concurrent.futures.as_completed(futures):
            ip_str, is_alive, open_ports = future.result()

            if is_alive:
                # reverse dns
                try :
                    hostname = socket.gethostbyaddr(ip_str)[0]
                except:
                    hostname = "N/A"
                
                # os
                os_detected = KNOWN_HOSTS.get(ip_str, "OS Inconnu")

                # display firewall for pfsense
                if hostname == "N/A" and "pfSense" in os_detected:
                    hostname == "Firewall"

                # eol
                status_eol, date_eol = get_eol_status(os_detected)

                # results
                results_to_write.append({
                    'IP': ip_str,
                    'Nom (DNS)': hostname,
                    'OS Détecté': os_detected,
                    'Statut Support (EOL)': status_eol,
                    'Date Fin Support': date_eol,
                    'Ports Ouverts': str(open_ports)
                })

    results_to_write.sort(key=lambda x: ipaddress.IPv4Address(x['IP']))

    # display
    for res in results_to_write:
        print(f"    [+] {res['IP']:<15} ({res['Nom (DNS)']}) | {res['OS Détecté']} | {res['Statut Support (EOL)']} (Fin: {res['Date Fin Support']})")

    # csv
    try:
        with open(filepath, 'w', newline='', encoding='utf-8-sig') as csvfile:
            fieldnames = ['IP', 'Nom (DNS)', 'OS Détecté', 'Statut Support (EOL)', 'Date Fin Support', 'Ports Ouverts']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
            writer.writeheader()
            writer.writerows(results_to_write)

            print(f"\n\n[OK] Scan terminé. {len(results_to_write)} machines trouvées.")
            print(f"[FICHIER] Rapport généré : {filepath}")
            
    except Exception as e:
        print(f"\n[ERREUR] Problème lors de l'écriture CSV : {e}")

def lookup_os_versions():
    """EOL lookup for given od=s"""
    clear_screen()
    print("\n--- RECHERCHE MANUELLE EOL ---")
    print("Exemples: ubuntu, windows, debian, centos, fedora...")
    target = input("Entrez le nom du produit à vérifier : ").strip().lower()

    if not target:
        return

    url = f"https://endoflife.date/api/v1/products/{target}"
    
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            releases = []

            if isinstance(data, dict):
                if "result" in data and "releases" in data["result"]:
                    releases = data["result"]["releases"]
                elif "releases" in data:
                    releases = data["releases"]
            elif isinstance(data, list):
                releases = data

            if not releases:
                print(f"[!] Pas de versions trouvées pour '{target}' (Format inattendu).")
                wait_for_user()
                return

            # display
            print(f"\nRésultats pour '{target}' :")
            print(f"{'VERSION':<15} | {'FIN DE SUPPORT (EOL)':<15} | {'STATUT ACTUEL'}")
            print("-" * 50)
            
            today = datetime.now().date()
            warning = today + timedelta(days=180)
            
            for release in releases:
                # codename
                version_name = release.get('name', 'N/A')
                codename = release.get('codename')
                if codename and isinstance(codename, str):
                    display_name = f"{version_name} ({codename})"
                else:
                    display_name = version_name
                
                # date eol 
                eol_str = release.get('eolFrom') or release.get('eol')
                
                status = "Supporté"
                display_date = str(eol_str)

                if isinstance(eol_str, str) and len(eol_str) >= 10:
                    try:
                        eol_date = datetime.strptime(eol_str[:10], "%Y-%m-%d").date()
                        
                        if eol_date < today:
                            status = "Obsolète"
                        elif eol_date < warning:
                            status = "Bientôt obsolète"
                        else:
                            status = "Supporté"
                    except ValueError:
                        pass 
                
                if release.get('isEol') is True:
                    status = "Obsolète"

                if eol_str is False or eol_str is None:
                    display_date = "Toujours supporté"
                    status = "Supporté"

                print(f"{display_name:<25} | {display_date:<15} | {status}")

        else:
            print(f"[!] Produit '{target}' introuvable dans l'API (Erreur {response.status_code}).")
            
    except Exception as e:
        print(f"[ERREUR] Problème de connexion ou de parsing : {e}")
    
    wait_for_user()

def scan_menu():
    config = load_config()

    while True:
        clear_screen()
        print("\n--- MODULE AUDIT & OBSOLESCENCE ---")
        
        if not config:
            print("[!] Erreur: Fichier configs/audit.json manquant ou invalide.")
            wait_for_user()
            return

        profiles = config.get("scan_profiles", [])
        for i, profile in enumerate(profiles):
            print(f"{i + 1}. Auditer {profile['network_name']} ({profile['cidr']})")

        opt_index = len(profiles) + 1
        print(f"{opt_index}. Encyclopédie (Recherche EOL d'un OS)")
        
        print("q. Retour")
        
        choice = input("Votre choix : ")

        if choice == str(opt_index):
            lookup_os_versions()

        elif choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(profiles):
                target = profiles[index]
                ports = config.get("ports_to_scan", [21, 22, 80, 445])

                scan_subnet_and_export(target, ports)
                wait_for_user()
            else:
                print("Choix invalide.")
        elif choice == 'q':
            break