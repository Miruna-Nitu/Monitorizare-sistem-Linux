import psutil
import time
import csv
import os
import hashlib
import json
import subprocess
from datetime import datetime

# === Config ===
MONITORED_FILES = ["/etc/passwd", "/etc/shadow", "/etc/hosts"]
HASH_FILE = "hashes.json"
CSV_LOG = "logs/system.csv"
ALERT_LOG = "logs/alerts.log"
LOG_INTERVAL = 60  # secunde

# === Utils ===
def sha256sum(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def load_hashes():
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=2)

def detect_file_changes():
    alerts = []
    old = load_hashes()
    new = {}
    for path in MONITORED_FILES:
        h = sha256sum(path)
        new[path] = h
        if path in old and old[path] != h:
            alerts.append(f"[ALERT] {path} a fost modificat.")
    save_hashes(new)
    return alerts

def log_alerts(alerts):
    os.makedirs("logs", exist_ok=True)
    with open(ALERT_LOG, "a") as f:
        for alert in alerts:
            f.write(f"{datetime.now().isoformat()} {alert}\n")

# === Monitorizare resurse ===
def collect_system_metrics():
    ts = datetime.now().isoformat()
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory().percent
    disks = {part.mountpoint: psutil.disk_usage(part.mountpoint).percent for part in psutil.disk_partitions(all=False)}
    disk_io = psutil.disk_io_counters()
    net_io = psutil.net_io_counters()

    top_cpu, top_mem, top_disk = [], [], []

    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'io_counters']):
        try:
            info = p.info
            info['read_bytes'] = info['io_counters'].read_bytes if info['io_counters'] else 0
            info['write_bytes'] = info['io_counters'].write_bytes if info['io_counters'] else 0
            info['io_total'] = info['read_bytes'] + info['write_bytes']
            top_cpu.append(info)
            top_mem.append(info)
            top_disk.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    top_cpu = sorted(top_cpu, key=lambda x: x['cpu_percent'], reverse=True)[:3]
    top_mem = sorted(top_mem, key=lambda x: x['memory_percent'], reverse=True)[:3]
    top_disk = sorted(top_disk, key=lambda x: x['io_total'], reverse=True)[:3]

    return {
        "timestamp": ts,
        "cpu": cpu,
        "mem": mem,
        "disks": disks,
        "read_bytes": disk_io.read_bytes,
        "write_bytes": disk_io.write_bytes,
        "net_sent": net_io.bytes_sent,
        "net_recv": net_io.bytes_recv,
        "top_cpu": top_cpu,
        "top_mem": top_mem,
        "top_disk": top_disk
    }

# === Alte verificări ===
def check_open_ports():
    result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
    return result.stdout.strip()

def check_installed_packages():
    try:
        result = subprocess.run(["grep", " install ", "/var/log/dpkg.log"], capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return ""

def check_root_processes():
    return [p.info for p in psutil.process_iter(['pid', 'name', 'username']) if p.info.get('username') == 'root']

def get_cronjobs():
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    return result.stdout.strip()

def monitor_app(name):
    return [p.info for p in psutil.process_iter(['pid', 'name']) if p.info['name'] == name]

# === CSV ===
def save_to_csv(data):
    os.makedirs("logs", exist_ok=True)
    write_header = not os.path.exists(CSV_LOG)
    with open(CSV_LOG, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow([
                "timestamp", "cpu", "mem", "disks", "read_bytes", "write_bytes", "net_sent", "net_recv"
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

# === Main ===
def main():
    while True:
        alerts = detect_file_changes()
        metrics = collect_system_metrics()
        save_to_csv(metrics)
        log_alerts(alerts)

        print(f"\n===== [{metrics['timestamp']}] Monitorizare Sistem =====")
        print(f"CPU: {metrics['cpu']}% | Memorie: {metrics['mem']}%")
        print("Discuri montate:")
        for mount, percent in metrics["disks"].items():
            print(f"  {mount}: {percent}%")

        print(f"I/O Read: {metrics['read_bytes']} bytes | Write: {metrics['write_bytes']} bytes")
        print(f"Rețea: {metrics['net_sent']} bytes transmise | {metrics['net_recv']} bytes primite")

        if alerts:
            print("🔴 Alerte fișiere modificate:")
            for alert in alerts:
                print("   ", alert)

        print("\n=== Top 3 CPU ===")
        for p in metrics["top_cpu"]:
            print(f"  {p['name']} (PID {p['pid']}): {p['cpu_percent']}%")

        print("=== Top 3 Memorie ===")
        for p in metrics["top_mem"]:
            print(f"  {p['name']} (PID {p['pid']}): {p['memory_percent']:.2f}%")

        print("=== Top 3 Disk I/O ===")
        for p in metrics["top_disk"]:
            print(f"  {p['name']} (PID {p['pid']}): {p['io_total']} bytes")

        print("\n=== Porturi deschise ===")
        print(check_open_ports())

        print("\n=== Pachete instalate recent ===")
        print(check_installed_packages())

        print("\n=== Procese cu root ===")
        for p in check_root_processes():
            print(f"  {p['name']} (PID {p['pid']})")

        print("\n=== Cronjobs curente ===")
        print(get_cronjobs())

        print("\n=== Monitorizare aplicație (ex: sshd) ===")
        apps = monitor_app("sshd")
        if apps:
            for app in apps:
                print(f"  {app['name']} (PID {app['pid']})")
        else:
            print("  ❌ sshd NU rulează!")

        time.sleep(LOG_INTERVAL)

if __name__ == "__main__":
    main()

