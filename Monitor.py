#!/usr/bin/env python3
import psutil
import time
import csv
import os
import hashlib
import json
import subprocess
from datetime import datetime
import logging
import socket

# === Configurație ===
CONFIG = {
    "MONITORED_FILES": ["/etc/passwd", "/etc/hosts"],  # /etc/shadow eliminat din motive de securitate
    "LOG_DIR": os.path.expanduser("~/monitor_logs"),
    "HASH_FILE": os.path.expanduser("~/monitor_logs/hashes.json"),
    "CSV_LOG": os.path.expanduser("~/monitor_logs/system.csv"),
    "ALERT_LOG": os.path.expanduser("~/monitor_logs/alerts.log"),
    "LOG_INTERVAL": 60,
    "MONITOR_APP": "sshd",
    "ALERT_THRESHOLDS": {
        "cpu": 90,
        "memory": 85,
        "disk": 90
    }
}

# === Inițializare logging ===
os.makedirs(CONFIG["LOG_DIR"], exist_ok=True)
os.makedirs(os.path.dirname(CONFIG["HASH_FILE"]), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(CONFIG["LOG_DIR"], "monitor.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === Utilitare ===
def sha256sum(path):
    """Calculează hash SHA256 pentru un fișier"""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        logger.warning(f"Nu pot calcula hash pentru {path}: {str(e)}")
        return None

def load_hashes():
    """Încarcă hash-urile salvate anterior"""
    try:
        if os.path.exists(CONFIG["HASH_FILE"]):
            with open(CONFIG["HASH_FILE"], "r") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Eroare la încărcarea hash-urilor: {str(e)}")
    return {}

def save_hashes(hashes):
    """Salvează hash-urile curente"""
    try:
        with open(CONFIG["HASH_FILE"], "w") as f:
            json.dump(hashes, f, indent=2)
    except Exception as e:
        logger.error(f"Eroare la salvarea hash-urilor: {str(e)}")

def detect_file_changes():
    """Detectează modificări în fișierele monitorizate"""
    alerts = []
    old_hashes = load_hashes()
    new_hashes = {}
    
    for path in CONFIG["MONITORED_FILES"]:
        current_hash = sha256sum(path)
        if current_hash is None:
            continue
            
        new_hashes[path] = current_hash
        
        if path in old_hashes and old_hashes[path] != current_hash:
            alert_msg = f"Fișier modificat: {path}"
            alerts.append(alert_msg)
            logger.warning(alert_msg)
    
    save_hashes(new_hashes)
    return alerts

def log_alerts(alerts):
    """Înregistrează alerte în fișierul de log"""
    try:
        with open(CONFIG["ALERT_LOG"], "a") as f:
            for alert in alerts:
                f.write(f"{datetime.now().isoformat()} {alert}\n")
    except Exception as e:
        logger.error(f"Eroare la înregistrarea alertelor: {str(e)}")

# === Monitorizare resurse sistem ===
def collect_system_metrics():
    """Colectează metrici de sistem"""
    ts = datetime.now().isoformat()
    
    try:
        cpu = psutil.cpu_percent(interval=1)
        if cpu > CONFIG["ALERT_THRESHOLDS"]["cpu"]:
            logger.warning(f"Utilizare CPU ridicată: {cpu}%")
    except Exception as e:
        logger.error(f"Eroare la monitorizarea CPU: {str(e)}")
        cpu = 0

    try:
        mem = psutil.virtual_memory().percent
        if mem > CONFIG["ALERT_THRESHOLDS"]["memory"]:
            logger.warning(f"Utilizare memorie ridicată: {mem}%")
    except Exception as e:
        logger.error(f"Eroare la monitorizarea memoriei: {str(e)}")
        mem = 0

    disks = {}
    try:
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks[part.mountpoint] = usage.percent
                if usage.percent > CONFIG["ALERT_THRESHOLDS"]["disk"]:
                    logger.warning(f"Utilizare disk ridicată pe {part.mountpoint}: {usage.percent}%")
            except Exception as e:
                logger.warning(f"Eroare la monitorizarea discului {part.mountpoint}: {str(e)}")
    except Exception as e:
        logger.error(f"Eroare la obținerea partițiilor: {str(e)}")

    try:
        disk_io = psutil.disk_io_counters()
        read_bytes = disk_io.read_bytes
        write_bytes = disk_io.write_bytes
    except Exception as e:
        logger.error(f"Eroare la monitorizarea I/O disk: {str(e)}")
        read_bytes = 0
        write_bytes = 0

    try:
        net_io = psutil.net_io_counters()
        net_sent = net_io.bytes_sent
        net_recv = net_io.bytes_recv
    except Exception as e:
        logger.error(f"Eroare la monitorizarea rețelei: {str(e)}")
        net_sent = 0
        net_recv = 0

    return {
        "timestamp": ts,
        "cpu": cpu,
        "mem": mem,
        "disks": disks,
        "read_bytes": read_bytes,
        "write_bytes": write_bytes,
        "net_sent": net_sent,
        "net_recv": net_recv
    }

def get_top_processes():
    """Obține top procese pentru CPU, memorie și I/O"""
    top_cpu = []
    top_mem = []
    top_disk = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'io_counters']):
        try:
            info = proc.info
            io = info.get('io_counters')
            io_total = (io.read_bytes + io.write_bytes) if io else 0
            
            top_cpu.append((info['pid'], info['name'], info.get('cpu_percent', 0)))
            top_mem.append((info['pid'], info['name'], info.get('memory_percent', 0)))
            top_disk.append((info['pid'], info['name'], io_total))
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            continue

    return {
        "top_cpu": sorted(top_cpu, key=lambda x: x[2], reverse=True)[:3],
        "top_mem": sorted(top_mem, key=lambda x: x[2], reverse=True)[:3],
        "top_disk": sorted(top_disk, key=lambda x: x[2], reverse=True)[:3]
    }

# === Verificări de securitate ===
def check_open_ports():
    """Verifică porturile deschise"""
    try:
        result = subprocess.run(["ss", "-tulnp"], 
                              capture_output=True, 
                              text=True, 
                              check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Eroare la verificarea porturilor: {str(e)}")
        return ""

def check_installed_packages():
    """Verifică pachete nou instalate"""
    try:
        if os.path.exists("/var/log/dpkg.log"):
            result = subprocess.run(["grep", " install ", "/var/log/dpkg.log"], 
                                  capture_output=True, 
                                  text=True)
            return result.stdout.strip()
    except Exception as e:
        logger.error(f"Eroare la verificarea pachetelor: {str(e)}")
    return ""

def check_root_processes():
    """Identifică procese care rulează cu drepturi de root"""
    root_procs = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'exe']):
        try:
            if proc.info.get('username') == 'root':
                root_procs.append((proc.info['pid'], proc.info['name']))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    if root_procs:
        logger.info(f"Procese care rulează ca root: {len(root_procs)}")

    #Afișează doar primele 10
    for pid, name in root_procs[:10]: 
         logger.warning(f"  {name} (PID {pid})")
    

    return root_procs

def get_cronjobs():
    """Obține cronjob-uri pentru utilizatorul curent"""
    try:
        result = subprocess.run(["crontab", "-l"], 
                              capture_output=True, 
                              text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        return "Nu există cronjob-uri"
    except Exception as e:
        logger.error(f"Eroare la obținerea cronjob-urilor: {str(e)}")
        return ""

def monitor_app(name):
    """Monitorizează o aplicație specifică"""
    app_processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] == name:
                app_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    if not app_processes:
        logger.warning(f"Aplicația {name} nu rulează!")
    
    return app_processes

def monitor_sshd():
    try:
        result = subprocess.run(['systemctl', 'is-active', 'sshd'],
                              capture_output=True, text=True)
        if result.stdout.strip() != 'active':
            logger.critical("Serviciul SSH nu rulează!")
            return False
        return True
    except Exception as e:
        logger.error(f"Eroare verificare SSH: {str(e)}")
        return False

# === Salvare date ===
def save_to_csv(data):
    """Salvează metricile în fișier CSV"""
    try:
        write_header = not os.path.exists(CONFIG["CSV_LOG"])
        with open(CONFIG["CSV_LOG"], "a", newline="") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow([
                    "timestamp", "cpu", "mem", "disks", 
                    "read_bytes", "write_bytes", 
                    "net_sent", "net_recv"
                ])
            writer.writerow([
                data["timestamp"],
                data["cpu"],
                data["mem"],
                json.dumps(data["disks"]),
                data["read_bytes"],
                data["write_bytes"],
                data["net_sent"],
                data["net_recv"]
            ])
    except Exception as e:
        logger.error(f"Eroare la salvarea în CSV: {str(e)}")

# === Funcția principală ===
def main():
    logger.info("Pornire serviciu de monitorizare sistem")
    
    # Inițializare hash-uri fișiere
    detect_file_changes()
    
    while True:
        start_time = time.time()
        
        try:
            # Colectare date
            alerts = detect_file_changes()
            metrics = collect_system_metrics()
            top_processes = get_top_processes()
            
            # Salvarea datelor
            save_to_csv(metrics)
            log_alerts(alerts)
            
            # Afișare informații în consolă
            print(f"\n===== [{metrics['timestamp']}] Monitorizare Sistem =====")
            print(f"CPU: {metrics['cpu']}% | Memorie: {metrics['mem']}%")
            
            print("\nDiscuri montate:")
            for mount, percent in metrics["disks"].items():
                print(f"  {mount}: {percent}%")
            
            print(f"\nI/O Disk: Read={metrics['read_bytes']} bytes | Write={metrics['write_bytes']} bytes")
            print(f"Rețea: Sent={metrics['net_sent']} bytes | Recv={metrics['net_recv']} bytes")
            
            if alerts:
                print("\n Alerte fișiere modificate:")
                for alert in alerts:
                    print(f"  {alert}")
            
            print("\n=== Top Procese ===")
            print("CPU:")
            for pid, name, val in top_processes["top_cpu"]:
                print(f"  {name} (PID {pid}): {val}%")
            
            print("\nMemorie:")
            for pid, name, val in top_processes["top_mem"]:
                print(f"  {name} (PID {pid}): {val:.1f}%")
            
            print("\nDisk I/O:")
            for pid, name, val in top_processes["top_disk"]:
                print(f"  {name} (PID {pid}): {val} bytes")
            
            print("\n=== Porturi deschise ===")
            print(check_open_ports())
            
            print("\n=== Pachete instalate recent ===")
            print(check_installed_packages() or "Niciun pachet nou instalat")
            
            print("\n=== Procese care rulează ca root ===")
            root_procs = check_root_processes()
            if root_procs:
                for pid, name in root_procs:
                    print(f"  {name} (PID {pid})")
            else:
                print("  Nu există procese care rulează ca root")
            
            print("\n=== Cronjobs ===")
            print(get_cronjobs())
            
            print(f"\n=== Monitorizare aplicație ({CONFIG['MONITOR_APP']}) ===")
            apps = monitor_app(CONFIG["MONITOR_APP"])
            if apps:
                for app in apps:
                    print(f"  {app['name']} (PID {app['pid']})")
            else:
                print("  Aplicația nu rulează!")
            
        except Exception as e:
            logger.error(f"Eroare în bucla principală: {str(e)}")
        
        # Așteptare pentru următorul ciclu
        elapsed = time.time() - start_time
        sleep_time = max(0, CONFIG["LOG_INTERVAL"] - elapsed)
        time.sleep(sleep_time)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Monitor oprit manual")
    except Exception as e:
        logger.critical(f"Eroare critică: {str(e)}")
        raise
