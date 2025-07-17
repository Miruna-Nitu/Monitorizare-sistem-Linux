# gui_monitor.py actualizat cu metoda corecta update_files si organizare curata

import sys
import os
import psutil
import hashlib
import subprocess
import pwd
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QProgressBar, QGroupBox,
    QGridLayout, QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QTabWidget
)
from PyQt6.QtCore import QTimer

MONITORED_FILES = ["/etc/passwd", "/etc/hosts", "/etc/shadow"]
MONITORED_APP = "sshd"

class ResourceMonitor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Monitorizare Resurse Sistem")
        self.setGeometry(50, 50, 1000, 800)
        self.previous_hashes = {}

        self.tabs = QTabWidget()
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        self.layout.addWidget(self.tabs)

        self.create_resource_tab()
        self.create_process_tab()
        self.create_security_tab()

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_data)
        self.timer.start(3000)
        self.update_data()

    def create_resource_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        grid = QGridLayout()

        self.cpu_label = QLabel("CPU:")
        self.cpu_bar = QProgressBar()
        self.mem_label = QLabel("Memorie:")
        self.mem_bar = QProgressBar()

        grid.addWidget(self.cpu_label, 0, 0)
        grid.addWidget(self.cpu_bar, 0, 1)
        grid.addWidget(self.mem_label, 1, 0)
        grid.addWidget(self.mem_bar, 1, 1)

        self.disk_bars = []
        self.disk_mounts = []
        row = 2
        for part in psutil.disk_partitions(all=False):
            mount = part.mountpoint
            if mount == '/':
                label = QLabel("Root (/)")
            elif mount == '/boot/efi':
                label = QLabel("EFI Boot (/boot/efi)")
            elif mount.startswith('/home'):
                label = QLabel("Home (/home)")
            else:
                label = QLabel(f"{mount}")
            bar = QProgressBar()
            self.disk_mounts.append(part.mountpoint)
            self.disk_bars.append(bar)
            grid.addWidget(label, row, 0)
            grid.addWidget(bar, row, 1)
            row += 1

        self.io_label = QLabel("Disk I/O:")
        self.net_label = QLabel("Rețea:")
        grid.addWidget(self.io_label, row, 0, 1, 2)
        grid.addWidget(self.net_label, row + 1, 0, 1, 2)

        layout.addLayout(grid)

        self.file_text = QTextEdit()
        self.file_text.setReadOnly(True)
        layout.addWidget(QLabel("Monitorizare Fișiere Critice"))
        layout.addWidget(self.file_text)

        self.app_status_text = QTextEdit()
        self.app_status_text.setReadOnly(True)
        layout.addWidget(QLabel(f"Monitorizare aplicație: {MONITORED_APP}"))
        layout.addWidget(self.app_status_text)

        tab.setLayout(layout)
        self.tabs.addTab(tab, "Resurse")

    def create_process_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.proc_table = QTableWidget()
        self.proc_table.setColumnCount(5)
        self.proc_table.setHorizontalHeaderLabels(["PID", "Nume", "CPU %", "Memorie %", "I/O (bytes)"])
        self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        self.net_proc_text = QTextEdit()
        self.net_proc_text.setReadOnly(True)

        self.root_proc_text = QTextEdit()
        self.root_proc_text.setReadOnly(True)

        layout.addWidget(QLabel("Top Procese"))
        layout.addWidget(self.proc_table)
        layout.addWidget(QLabel("Top Procese Rețea"))
        layout.addWidget(self.net_proc_text)
        layout.addWidget(QLabel("Procese Root"))
        layout.addWidget(self.root_proc_text)

        tab.setLayout(layout)
        self.tabs.addTab(tab, "Procese")

    def create_security_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.ports_text = QTextEdit()
        self.ports_text.setReadOnly(True)
        self.packages_text = QTextEdit()
        self.packages_text.setReadOnly(True)
        self.cron_text = QTextEdit()
        self.cron_text.setReadOnly(True)

        layout.addWidget(QLabel("Porturi Deschise"))
        layout.addWidget(self.ports_text)
        layout.addWidget(QLabel("Pachete Instalate"))
        layout.addWidget(self.packages_text)
        layout.addWidget(QLabel("Cronjob-uri"))
        layout.addWidget(self.cron_text)

        tab.setLayout(layout)
        self.tabs.addTab(tab, "Securitate")

    def sha256sum(self, path):
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            return f"Eroare acces: {path}"

    def update_data(self):
        self.update_resources()
        self.update_top_processes()
        self.update_net_processes()
        self.update_root_processes()
        self.update_ports()
        self.update_packages()
        self.update_cronjobs()
        self.update_files()
        self.update_app()

    def update_resources(self):
        cpu = psutil.cpu_percent(interval=0.5)
        self.cpu_bar.setValue(int(cpu))
        self.cpu_label.setText(f"CPU: {cpu:.1f}%")

        mem = psutil.virtual_memory().percent
        self.mem_bar.setValue(int(mem))
        self.mem_label.setText(f"Memorie: {mem:.1f}%")

        for idx, mount in enumerate(self.disk_mounts):
            try:
                usage = psutil.disk_usage(mount).percent
                self.disk_bars[idx].setValue(int(usage))
            except:
                self.disk_bars[idx].setValue(0)

        io = psutil.disk_io_counters()
        self.io_label.setText(f"Disk I/O: Read={io.read_bytes:,} B, Write={io.write_bytes:,} B")

        net = psutil.net_io_counters()
        self.net_label.setText(f"Rețea: Sent={net.bytes_sent:,} B, Recv={net.bytes_recv:,} B")

    def update_top_processes(self):
        procs = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'io_counters']):
            try:
                io = proc.info.get('io_counters')
                io_total = io.read_bytes + io.write_bytes if io else 0
                procs.append((proc.info['pid'], proc.info['name'], proc.info['cpu_percent'], proc.info['memory_percent'], io_total))
            except:
                continue
        procs = sorted(procs, key=lambda x: x[2], reverse=True)[:10]
        self.proc_table.setRowCount(len(procs))
        for row, proc in enumerate(procs):
            for col, val in enumerate(proc):
                self.proc_table.setItem(row, col, QTableWidgetItem(str(val)))

    def update_net_processes(self):
        try:
            result = subprocess.check_output(["ss", "-tunp"], text=True)
            lines = result.strip().split("\n")[1:]
            connections = {}
            for line in lines:
                if "pid=" in line:
                    pid_part = line.split("pid=")[1].split(",")[0]
                    try:
                        pid = int(pid_part)
                        connections[pid] = connections.get(pid, 0) + 1
                    except ValueError:
                        continue
            sorted_conn = sorted(connections.items(), key=lambda x: x[1], reverse=True)[:3]
            output = []
            for pid, count in sorted_conn:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                except:
                    name = "N/A"
                output.append(f"{name} (PID {pid}): {count} conexiuni")
            self.net_proc_text.setPlainText("\n".join(output))
        except Exception as e:
            self.net_proc_text.setPlainText(f"Eroare: {str(e)}")


    def update_root_processes(self):
        output = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                if proc.info.get('username') == 'root':
                    output.append(f"{proc.info['name']} (PID {proc.info['pid']})")
            except:
                continue
        self.root_proc_text.setPlainText("\n".join(output))

    def update_ports(self):
        try:
            result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, check=True)
            self.ports_text.setPlainText(result.stdout.strip())
        except Exception as e:
            self.ports_text.setPlainText(f"Eroare: {str(e)}")

    def update_packages(self):
        try:
            if os.path.exists("/var/log/dpkg.log"):
                result = subprocess.run(["grep", " install ", "/var/log/dpkg.log"], capture_output=True, text=True)
                output = result.stdout.strip() or "Nicio instalare recentă."
            else:
                output = "Fișierul /var/log/dpkg.log nu există."
        except Exception as e:
            output = f"Eroare: {str(e)}"
        self.packages_text.setPlainText(output)

    def update_cronjobs(self):
        output = []
        try:
            users = [u.pw_name for u in pwd.getpwall() if u.pw_uid >= 1000 and '/home' in u.pw_dir]
            for user in users:
                result = subprocess.run(["crontab", "-l", "-u", user], capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    output.append(f"=== {user} ===\n{result.stdout.strip()}")
        except Exception as e:
            output.append(str(e))
        self.cron_text.setPlainText("\n\n".join(output))

    def update_files(self):
        lines = []
        for f in MONITORED_FILES:
            h = self.sha256sum(f)
            if isinstance(h, str) and h.startswith("Eroare"):
                lines.append(f"[EROARE] {f}: {h}")
                continue
            if f in self.previous_hashes:
                if self.previous_hashes[f] != h:
                    lines.append(f"[MODIFICAT] {f}")
                else:
                    lines.append(f"[NEMODIFICAT] {f}")
            else:
                lines.append(f"[NEMODIFICAT] {f}")
            self.previous_hashes[f] = h
        self.file_text.setPlainText("\n".join(lines))

    def update_app(self):
        output = []
        try:
            result = subprocess.run(["systemctl", "is-active", MONITORED_APP], capture_output=True, text=True)
            status = result.stdout.strip()
            output.append(f"Status serviciu: {status}")
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == MONITORED_APP:
                    output.append(f"{proc.info['name']} (PID {proc.info['pid']})")
        except Exception as e:
            output.append(f"Eroare: {str(e)}")
        self.app_status_text.setPlainText("\n".join(output))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = ResourceMonitor()
    win.show()
    sys.exit(app.exec())