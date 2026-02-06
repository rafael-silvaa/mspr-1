import os
import psutil
import platform
import time
import socket
import paramiko
import json
from datetime import datetime
from .utils import *

BASE_DIR = os.path.dirname(__file__)
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "configs", "diagnostic.json")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

def load_inventory():
    """"load config depuis json"""
    if not os.path.exists(CONFIG_FILE):
        print(f"[ERREUR] Le fichier de configuration est introuvable : {CONFIG_FILE}")
        return {}
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[ERREUR] Le fichier JSON est mal formaté : {e}")
        return {}

def save_report_json(machine_name, data):
    """exporter le dic de données -> JSON"""
    if not os.path.exists(LOGS_DIR):
        try:
            os.makedirs(LOGS_DIR)
        except OSError as e:
            print(f"[ERREUR] Impossible de créer le dossier logs : {e}")
            return

    safe_name = "".join([c if c.isalnum() else "_" for c in machine_name])
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"diag_{safe_name}_{timestamp}.json"
    filepath = os.path.join(LOGS_DIR, filename)

    full_report = {
        "machine": machine_name,
        "scan_date": datetime.now().isoformat(),
        "scan_result": data
    }

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(full_report, f, indent=4, ensure_ascii=False)
        print(f"\n[SUCCÈS] Rapport exporté ici : {filepath}")
    except Exception as e:
        print(f"\n[ERREUR] Échec de l'export JSON : {e}")

def get_local_health():
    """gather local system health using psutil"""
    print(f"[*] Analyse de la machine locale...")
    info = {}
    
    try:
        # 1. OS info
        info['OS'] = f"{platform.system()} {platform.release()}"
        
        # 2. uptime (calculated from boot time)
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_hours = int(uptime_seconds // 3600)
        uptime_days = uptime_hours // 24
        uptime_hours_remaining = uptime_hours % 24
        info['Uptime'] = f"{uptime_days} jours, {uptime_hours_remaining} heures"
        
        # 3. CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        info['CPU'] = f"{cpu_percent}%"
        
        # 4. RAM usage
        ram = psutil.virtual_memory()
        info['RAM'] = f"{ram.percent}% utilisée ({ram.used // (1024**3)} GB / {ram.total // (1024**3)} GB)"
        
        # 5. disk usage (main drive)
        disk = psutil.disk_usage('/')
        info['Disque'] = f"{disk.percent}% utilisé ({disk.used // (1024**3)} GB / {disk.total // (1024**3)} GB)"
        
        return info
        
    except Exception as e:
        return {"ERREUR": f"Impossible de récupérer les informations locales: {e}"}

def get_remote_linux_health(ip, user, password):
    """connecte SSH + commandes Linux pour récup l'état"""
    print(f"[*] Connexion SSH vers {ip}...")
    info = {}
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(ip, username=user, password=password, timeout=5)
        
        # 1. récup OS
        stdin, stdout, stderr = client.exec_command("cat /etc/os-release | grep PRETTY_NAME")
        os_name = stdout.read().decode().strip().replace('PRETTY_NAME=', '').replace('"', '')
        info['OS'] = os_name if os_name else "Linux inconnu"

        # 2. récup uptime
        stdin, stdout, stderr = client.exec_command("uptime -p")
        info['Uptime'] = stdout.read().decode().strip()

        # 3. récup CPU load
        stdin, stdout, stderr = client.exec_command("cat /proc/loadavg")
        load = stdout.read().decode().split()[0]
        info['CPU Load'] = f"{load} (Load Avg)"

        # 4. récup RAM (libre/total)
        cmd_ram = "free -m | awk 'NR==2{printf \"%.2f\", $3*100/$2 }'"
        stdin, stdout, stderr = client.exec_command(cmd_ram)
        info['RAM'] = f"{stdout.read().decode().strip()}% utilisée"

        # 5. récup disque
        cmd_disk = "df -h / | awk 'NR==2 {print $5}'"
        stdin, stdout, stderr = client.exec_command(cmd_disk)
        info['Disque'] = stdout.read().decode().strip()

        client.close()
        return info

    except Exception as e:
        return {"ERREUR": f"Connexion impossible ou échec commandes: {e}"}

def check_simple_ports(ip, ports):
    """pour machines Windows sans SSH, vérifier juste les ports"""
    print(f"[*] Démarrage du scan détaillé vers {ip}...")
    
    info = {
        "OS": "Windows", 
        "Type": "Scan de Ports"
    }
    
    print(f"    > Test du Ping...", end=' ', flush=True)
    try:
        if platform.system().lower() == 'windows':
            # Windows: -n count, -w timeout in milliseconds
            command = ['ping', '-n', '1', '-w', '1000', ip]
        else:
            # Linux/Unix: -c count, -W timeout in seconds
            command = ['ping', '-c', '1', '-W', '1', ip]
        
        # Capture output to parse response time
        result = psutil.subprocess.run(
            command,
            stdout=psutil.subprocess.PIPE,
            stderr=psutil.subprocess.PIPE,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            # Parse ping time from output
            output = result.stdout
            ping_time = None
            
            if platform.system().lower() == 'windows':
                # Windows format: "time=XXms" or "time<1ms"
                import re
                match = re.search(r'time[=<](\d+)ms', output, re.IGNORECASE)
                if match:
                    ping_time = match.group(1)
                elif 'time<1ms' in output.lower():
                    ping_time = '<1'
            else:
                # Linux format: "time=XX.X ms"
                import re
                match = re.search(r'time=([\d.]+)\s*ms', output)
                if match:
                    ping_time = match.group(1)
            
            if ping_time:
                print(f"OK ({ping_time}ms)")
                info["Ping"] = f"OK ({ping_time}ms)"
            else:
                print("OK")
                info["Ping"] = "OK"
        else:
            print("Timeout")
            info["Ping"] = "Timeout"
    except psutil.subprocess.TimeoutExpired:
        print("Timeout")
        info["Ping"] = "Timeout"
    except Exception as e:
        print(f"ERREUR ({e})")
        info["Ping"] = "Erreur Commande"

    # loop ports
    for port in ports:
        print(f"    > Test du port TCP/{port}...", end=' ', flush=True)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0) # 1 sec max / port
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            status = "Ouvert"
            print("Ouvert")
        else:
            status = "Fermé"
            print("Fermé") 
            
        info[f"Port {port}"] = status
        sock.close()
    
    return info

def display_report(machine_name, data):
    print("\n" + "="*50)
    print(f" RAPPORT FINAL : {machine_name}")
    print("="*50)
    
    ports_data = []
    general_data = {}
    
    for key, value in data.items():
        if "Port" in key:
            ports_data.append((key, value))
        else:
            general_data[key] = value

    for key, value in general_data.items():
        print(f" {key:<15} : {value}")

    print("-" * 50)
    
    if ports_data:
        print(f" {'SERVICE/PORT':<15} | {'ÉTAT'}")
        print(f" {'-'*15} | {'-'*10}")
        for key, value in ports_data:
            etat = value
            print(f" {key:<15} | {etat}")
    
    print("="*50 + "\n")

def scan_single_machine(key, target):
    """Scan a single machine and return results"""
    try:
        print(f"\n[*] Scanning {target['name']} ({target['ip']})...")
        
        # detect OS type
        detected_type = detect_os_type(target['ip'])
        current_type = target['type']
        
        if target['type'] != 'local' and detected_type != 'unknown':
            current_type = detected_type
        
        # perform scan based on type
        data = {}
        if current_type == "local":
            # local analysis using psutil
            data = get_local_health()
            
        elif current_type == "linux_ssh":
            # Remote Linux analysis via SSH
            data = get_remote_linux_health(target["ip"], target.get("user"), target.get("password"))
            
        elif current_type == "windows_remote":
            # Windows remote - port scan
            data = check_simple_ports(target["ip"], [135, 445, 3389])
        
        return target["name"], data, None
        
    except Exception as e:
        return target["name"], None, str(e)

def scan_all_machines():
    """Scan all machines simultaneously using concurrent execution"""
    import concurrent.futures
    
    inventory = load_inventory()
    
    if not inventory:
        print("[!] Aucune configuration chargée. Vérifiez configs/diagnostic.json")
        return
    
    print("\n" + "="*60)
    print("--- DIAGNOSTIC SIMULTANÉ DE TOUTES LES MACHINES ---")
    print("="*60)
    print(f"[*] Démarrage du scan de {len(inventory)} machine(s)...")
    print("[*] Cette opération peut prendre quelques secondes.\n")
    
    results = []
    
    # scan all machines concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(inventory)) as executor:
        # submit all scan tasks
        futures = {executor.submit(scan_single_machine, key, target): (key, target) for key, target in inventory.items()}
        
        # collect results as they complete
        for future in concurrent.futures.as_completed(futures):
            key, target = futures[future]
            try:
                machine_name, data, error = future.result()
                if error:
                    print(f"[!] Erreur lors du scan de {machine_name}: {error}")
                    results.append((machine_name, {"ERREUR": error}))
                else:
                    print(f"[✓] {machine_name} - Scan terminé")
                    results.append((machine_name, data))
            except Exception as e:
                print(f"[!] Exception pour {target['name']}: {e}")
                results.append((target['name'], {"ERREUR": str(e)}))
    
    # display all results
    print("\n" + "="*60)
    print("RÉSULTATS DU SCAN SIMULTANÉ")
    print("="*60)
    
    for machine_name, data in results:
        display_report(machine_name, data)
    
    # ask if user wants to export all reports
    print("\n" + "="*60)
    save_choice = input("Voulez-vous exporter TOUS les rapports en JSON? (y/N) : ")
    if save_choice.lower() == 'y':
        for machine_name, data in results:
            save_report_json(machine_name, data)
        print(f"\n[OK] {len(results)} rapport(s) exporté(s) dans {LOGS_DIR}")

def run_diagnostic():
    inventory = load_inventory()

    if not inventory:
        print("Aucune configuration chargée. Vérifiez configs/diagnostic.json")
        return

    while True:
        # clear_screen()

        print("\n--- MENU DIAGNOSTIC RÉSEAU ---")
        print("Sélectionnez la machine à scanner :")
        
        keys = sorted(inventory.keys())
        for key in keys:
            val = inventory[key]
            print(f"{key}. {val['name']} ({val['ip']})")
        
        print("a. Scanner toutes les machines simultanément")
        print("q. Quitter")
        
        choice = input("\nVotre choix : ")
        
        if choice == 'a':
            scan_all_machines()
            wait_for_user()
            clear_screen()
            continue
        
        if choice == 'q':
            break
            
        if choice in inventory:
            target = inventory[choice]
            data = {}
            
            print(f"[*] Détection de l'OS de {target['ip']}...")
            detected_type = detect_os_type(target['ip'])
            
            current_type = target['type']
            if target['type'] != 'local' and detected_type != 'unknown':
                current_type = detected_type
            
            # scan
            try:
                if current_type == "local":
                    # analyse locale (psutil)
                    data = get_local_health()
                    
                elif current_type == "linux_ssh":
                    # analyse distante Linux (SSH)
                    # user/pass necessaire
                    data = get_remote_linux_health(target["ip"], target.get("user"), target.get("password"))
                    
                elif current_type == "windows_remote":
                    # win detected -> scan ports
                    data = check_simple_ports(target["ip"], [135, 445, 3389])
                
                display_report(target["name"], data)

                save = input("Voulez-vous exporter ce rapport en JSON? (y/N) : ")
                if save.lower() == 'y':
                    save_report_json(target["name"], data)
                
                wait_for_user()
                clear_screen()
                    
            except Exception as e:
                print(f"\n/!\ Une erreur est survenue pendant le scan :")
                print(f"{e}")
                print("Vérifiez vos IPs, mots de passe et connexions.")
                wait_for_user()
        else:
            print("Choix invalide.")

if __name__ == "__main__":
    try:
        run_diagnostic()
    except KeyboardInterrupt:
        print("\nArrêt forcé.")