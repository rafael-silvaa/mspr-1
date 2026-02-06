import os
import subprocess
import mysql.connector
import csv
import paramiko
import json
import gzip
import shutil
from datetime import datetime
from cryptography.fernet import Fernet
from .utils import *

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(CURRENT_DIR, "configs", "backup.json")
KEY_FILE = os.path.join(CURRENT_DIR, "configs", "secret.key")

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

def load_key():
    if not os.path.exists(KEY_FILE):
        print(f"[INFO] Aucune clé trouvée. Génération d'une nouvelle clé 'secret.key'...")
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        print(f"[IMP] Clé sauvegardée dans {KEY_FILE}.")

    try:
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    except Exception as e:
        print(f"[ERREUR] Lecture fichier clé : {e}")
        return None

def create_temp_dir():
    """crée un dossier avant """
    temp_dir = "backups_wms"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    return temp_dir

def encrypt_file(input_path, output_path, key):
    try:
        fernet = Fernet(key)

        with open(input_path, 'rb') as f:
            original_data = f.read()

        encrypted_data = fernet.encrypt(original_data)

        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

        return True
    except Exception as e:
        print(f"[ERREUR] Chiffrement échoué : {e}")
        return False

def transfer_to_nas(local_path, filename, nas_config):
    """envoie fichier -> NAS + supprime copie locale si succès"""
    abs_local_path = os.path.abspath(local_path)
    
    print(f"[*] Transfert de {filename} vers le NAS ({nas_config['host']})...")
    
    try:
        # créer client SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # connect
        ssh.connect(
            nas_config["host"], 
            username=nas_config["user"], 
            password=nas_config["password"]
        )
        
        sftp = ssh.open_sftp()
        
        # check dossier distant existant sinon creer
        try:
            sftp.chdir(nas_config["remote_dir"])
        except IOError:
            print(f"[INFO] Le dossier distant n'existe pas, tentative de création...")
            sftp.mkdir(nas_config["remote_dir"])
            sftp.chdir(nas_config["remote_dir"])

        clean_remote_dir = nas_config['remote_dir'].rstrip('/')
        remote_path = f"{clean_remote_dir}/{filename}"
        
        sftp.put(local_path, remote_path)
        sftp.close()
        ssh.close()
        
        print(f"[SUCCÈS] Fichier transféré sur le NAS : {remote_path}")

        print(f"\n[?] Le fichier est actuellement stocké ici: {abs_local_path}")
        keep_local = input("Voulez-vous conserver cette copie locale ? (y/N) : ").strip().lower()

        if keep_local == 'y':
            print(f"[INFO] Copie locale conservée.")
        else:
            # supp fichier local
            if os.path.exists(local_path):
                os.remove(local_path)
                print("[INFO] Copie locale supprimée.")
        
        return True

    except Exception as e:
        print(f"[ERREUR TRANSFERT] Impossible d'envoyer au NAS : {e}")
        print(f"[INFO] Le fichier est conservé localement ici : {local_path}")
        return False

def perform_sql_dump(config):
    """dump complet de la base via mysqldump"""
    db = config['database']
    tools = config['tools']
    nas = config['nas']

    key = load_key()
    
    print("\n[*] Démarrage de la sauvegarde SQL sécurisée...")
    
    # crée fichier horodaté
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_dir = create_temp_dir()

    raw_sql = os.path.join(temp_dir, f"temp_{timestamp}.sql")
    compressed_sql = raw_sql + ".gz"
    final_filename = f"backup_{db['db_name']}_{timestamp}.zsql.enc"
    final_path = os.path.join(temp_dir, final_filename) 

    command = [
        tools['mysqldump_path'],
        f"-h{db['host']}",
        f"-u{db['user']}",
        f"-p{db['password']}",
        db['db_name']
    ]
    if not db['password']: command.pop(3)

    try:
        # dump
        with open(raw_sql, 'w') as outfile:
            subprocess.run(command, stdout=outfile, stderr=subprocess.PIPE, check=True, text=True)
        
        # comp gzip
        with open(raw_sql, 'rb') as f_in:
            with gzip.open(compressed_sql, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        # chiffrement
        encrypt_file(compressed_sql, final_path, key)

        # clean up
        if os.path.exists(raw_sql): os.remove(raw_sql)
        if os.path.exists(compressed_sql): os.remove(compressed_sql)

        print(f"[SUCCÈS] Sauvegarde SQL chiffrée générée: {final_path}")
        transfer_to_nas(final_path, final_filename, nas)
        return True
    
    except Exception as err:
        print(f"[ERREUR] Processus de sauvegarde : {err}")
        return False
    except subprocess.CalledProcessError as e:
        print(f"[ERREUR] Échec de mysqldump. Code: {e.returncode}")
        print(f"Assurez-vous que 'mysqldump' est installé sur cette machine.")
        return False
    except FileNotFoundError:
        print("[ERREUR] Commande 'mysqldump' introuvable. Est-elle dans le PATH ?")
        return False

def export_table_csv(config):
    """exporte table spécifique en csv"""
    db = config['database']
    nas = config['nas']

    key = load_key()

    table_name = input("Table à exporter en CSV : ")
    print(f"\n[*] Export de la table '{table_name}' en CSV...")
    
    try:
        conn = mysql.connector.connect(
            host=db['host'],
            user=db['user'],
            password=db["password"],
            database=db["db_name"]
        )
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name}")
        
        # récupération des données et des en-têtes
        rows = cursor.fetchall()
        headers = [i[0] for i in cursor.description]
        
        # écriture du CSV
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_dir = create_temp_dir()

        raw_csv_path = os.path.join(temp_dir, f"temp_{table_name}.csv")
        filename = f"export_{table_name}_{timestamp}.csv.enc"
        local_path = os.path.join(temp_dir, filename)
        
        with open(raw_csv_path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow(headers)
            writer.writerows(rows)

        encrypt_file(raw_csv_path, local_path, key)
            
        print(f"[SUCCÈS] Export CSV généré : {filename} ({len(rows)} lignes)")
        
        cursor.close()
        conn.close()

        transfer_to_nas(local_path, filename, nas)
        return True

    except mysql.connector.Error as err:
        print(f"[ERREUR MySQL] {err}")
        return False

def run_backup_menu():
    """Sous-menu pour le module de sauvegarde."""
    config = load_config()
    if not config:
        print("\n[ERREUR CRITIQUE] Impossible de charger la configuration backup.")
        print("Vérifiez le fichier modules/configs/backup.json")
        wait_for_user() 
        return

    while True:
        clear_screen()

        print("\n--- MODULE SAUVEGARDE WMS ---")
        print("1. Sauvegarde complète (SQL Dump)")
        print("2. Export d'une table (CSV)")
        print("q. Retour au menu principal")
        
        choice = input("Choix : ")
        
        if choice == '1':
            perform_sql_dump(config)
            wait_for_user()
        elif choice == '2':
            export_table_csv(config)
            wait_for_user()
        elif choice == 'q':
            break
        else:
            print("Choix invalide.")