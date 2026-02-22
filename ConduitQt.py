import sys
import os
import re
import time
import gzip
import io
import copy
import platform
import statistics
import ipaddress
import numpy as np
import json
import requests
import socket
import subprocess
import zoneinfo
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QGridLayout,
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, QInputDialog,
                             QCheckBox, QListWidget, QListWidgetItem, QPlainTextEdit, 
                             QFileDialog, QMessageBox, QFrame, QAbstractItemView, 
                             QRadioButton, QButtonGroup, QDialog, QFormLayout,QProgressBar, 
                             QTableWidgetItem, QTableWidget, QHeaderView, QScrollArea)

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject, QRunnable, QThreadPool
from PyQt5.QtGui import QFont
from PyQt5.QtGui import QColor, QBrush
from fabric import Connection, Config
import pyqtgraph as pg
from pyqtgraph import DateAxisItem
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *


# --- PLATFORM SPECIFIC FIXES ---
if platform.system() == "Darwin":  # Darwin is the internal name for macOS
    # Fix for tiny fonts on Retina displays
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    print("[INFO] macOS High-DPI Scaling Enabled")

conduit_release = "byte_release"
#conduit_release = "psiphon"
#conduit_release = "ssmirr"

if conduit_release == "psiphon":
    CONDUIT_URL = "https://github.com/Psiphon-Inc/conduit/releases/download/release-cli-1.5.0/conduit-linux-amd64"

if conduit_release == "byte_release":
    CONDUIT_URL = "https://github.com/Starling226/conduit/releases/download/d399071/conduit"

if conduit_release == "ssmirr":
    CONDUIT_URL = "https://github.com/ssmirr/conduit/releases/download/d399071/conduit-linux-amd64"

PSIPHON_CONFIG_URL = "https://raw.githubusercontent.com/Starling226/conduit-cli/master/cli/psiphon_config.json.backup"

APP_VERSION = "2.5.0"

class AppState:
    use_lion_sun = False
    use_sec_inst = False
    conduit_id = ""

class LogFetcherSignals(QObject):
    """Signals for individual thread status."""
    finished = pyqtSignal(str) # Emits IP when done

class ReportFetcher(QRunnable):
    def __init__(self, server):
        super().__init__()
        self.server = server
        # Reuse the existing signal class
        self.signals = LogFetcherSignals()

    def run(self):
        ip = self.server['ip']
        try:
            current_year = datetime.now().year
            remote_path = f"/opt/conduit{AppState.conduit_id}/{current_year}-conduit.log"
            
            # Simple stream and compress
            cmd = f"cat {remote_path} | gzip -c"

            text_buffer = io.StringIO()
            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")

            p = int(self.server['port'])
            user = self.server['user'].strip()
            password = self.server['password'].strip()
            is_root = (user == "root")

            if is_root:
                # Key-based: Explicitly tell Fabric which files to use
                connect_kwargs = {
                    "timeout": 15,
                    "key_filename": [key_path],
                    "look_for_keys": False,
                    "allow_agent": False
                }
                cfg = Config()

            else:
                # Password-based
                connect_kwargs = {"password": password, "timeout": 10}
                cfg = Config(overrides={'sudo': {'password': password}})

            with Connection(host=ip, user=user, port=p, connect_kwargs=connect_kwargs, config=cfg) as conn:


                def run_cmd(cmd, **kwargs):

                    kwargs.setdefault('hide', False)
                    kwargs.setdefault('warn', False)
                    kwargs.setdefault('timeout', 30)

                    if is_root:
                        return conn.run(cmd, **kwargs)
                    else:    
                        return conn.sudo(cmd, **kwargs)
                        

                # IMPORTANT: we specify latin-1 here so it maps bytes 1:1 to string characters

                run_cmd(cmd, hide=True, out_stream=text_buffer, encoding='latin-1')
                
                encoded_string = text_buffer.getvalue()
                
                if not encoded_string:
                    print(f"FAILED: No data in {remote_path} for {ip}")
                    return

                # Convert that string back to actual bytes using the same encoding
                compressed_bytes = encoded_string.encode('latin-1')

                # Decompress the raw bytes
                raw_bytes = gzip.decompress(compressed_bytes)

                decoded_text = raw_bytes.decode('utf-8')

                # Saving as .raw so the Visualizer knows it needs processing

                with open(f"server_report_logs{AppState.conduit_id}/{ip}.raw", "w", encoding='utf-8') as f:
                    f.write(decoded_text)
                            
        except Exception as e:
            print(f"CRITICAL ERROR for {ip}: {e}")
        finally:
            # Emitting the finished signal regardless of success/failure
            self.signals.finished.emit(ip)

class LogFetcher(QRunnable):
    def __init__(self, server, days):
        super().__init__()
        self.server = server
        self.days = days
        self.signals = LogFetcherSignals()

    def run(self):
        ip = self.server['ip']
        try:
            # 1. Fetch only relevant lines from journal

            cmd = (
                f"journalctl -u conduit-monitor{AppState.conduit_id}.service "
                f"--since '{self.days} days ago' --no-pager -o short-iso | "
                f"awk -F' CONDUIT_JSON: ' '{{ "
                f"split($1, a, \" \"); "
                f"split($2, b, \",\"); "
                f"print a[1] \",\" b[1] \",\" b[2] \",\" b[3] "
                f"}}' | "
                f"gzip -c"
            )

            text_buffer = io.StringIO()

            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")

            p = int(self.server['port'])
            user = self.server['user'].strip()
            password = self.server['password'].strip()
            is_root = (user == "root")

            if is_root:
                # Key-based: Explicitly tell Fabric which files to use
                connect_kwargs = {
                    "timeout": 15,
                    "key_filename": [key_path],
                    "look_for_keys": False,
                    "allow_agent": False
                }
                cfg = Config()

            else:
                # Password-based
                connect_kwargs = {"password": password, "timeout": 10}
                cfg = Config(overrides={'sudo': {'password': password}})

            with Connection(host=ip, user=user, port=p, connect_kwargs=connect_kwargs, config=cfg) as conn:

                def run_cmd(cmd, **kwargs):

                    kwargs.setdefault('hide', False)
                    kwargs.setdefault('warn', False)
                    kwargs.setdefault('timeout', 30)

                    if is_root:
                        return conn.run(cmd, **kwargs)
                    else:    
                        return conn.sudo(cmd, **kwargs)
                        

                # IMPORTANT: we specify latin-1 here so it maps bytes 1:1 to string characters

                run_cmd(cmd, hide=True, out_stream=text_buffer, encoding='latin-1')

                # Retrieve the "stringified" bytes
                encoded_string = text_buffer.getvalue()
                if not encoded_string:
                    print(f"FAILED: server_logs{AppState.conduit_id}/{ip}.raw")
                    return

                # Convert that string back to actual bytes using the same encoding
                compressed_bytes = encoded_string.encode('latin-1')

                # Decompress the raw bytes
                raw_bytes = gzip.decompress(compressed_bytes)
                decoded_text = raw_bytes.decode('utf-8')

#                with open(f"server_logs/{ip}.raw", "w") as f:
                with open(f"server_logs{AppState.conduit_id}/{ip}.raw", "w", encoding='utf-8') as f:                    
                    f.write(decoded_text)
                
                            
        except Exception as e:
            print(f"CRITICAL ERROR for {ip}: {e}")
        finally:
            self.signals.finished.emit(ip)

    def parse_to_bytes(self, size_str):
        """Helper to convert '10.5 GB' to raw integer bytes."""
        units = {"B": 1, "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12}
        try:
            number, unit = size_str.split()
            return int(float(number) * units.get(unit.upper(), 1))
        except:
            return 0

class HistoryWorker(QThread):
    """Manages the pool of LogFetchers."""
    all_finished = pyqtSignal()
    progress = pyqtSignal(int) # Percentage of servers completed

    def __init__(self, servers, days):
        super().__init__()
        self.servers = servers
        self.days = days
#        self.completed_count = 0

    def run(self):
        if not os.path.exists(f"server_logs{AppState.conduit_id}"):
            os.makedirs(f"server_logs{AppState.conduit_id}")

        pool = QThreadPool.globalInstance()
        # Set max threads to number of servers or a reasonable limit (e.g., 20)
        pool.setMaxThreadCount(5)

        total = len(self.servers)
        for s in self.servers:
            fetcher = LogFetcher(s, self.days)
#            fetcher.signals.finished.connect(self.on_one_finished)
            pool.start(fetcher)

        # Wait for pool to finish
        pool.waitForDone()
        self.all_finished.emit()

    def on_one_finished(self, ip):
        self.completed_count += 1
        percent = int((self.completed_count / len(self.servers)) * 100)
        self.progress.emit(percent)

class ReportWorker(QThread):
    """Manages the pool of LogFetchers."""
    all_finished = pyqtSignal()
    progress = pyqtSignal(int) # Percentage of servers completed

    def __init__(self, servers):
        super().__init__()
        self.servers = servers

#        self.completed_count = 0

    def run(self):
        if not os.path.exists(f"server_report_logs{AppState.conduit_id}"):
            os.makedirs(f"server_report_logs{AppState.conduit_id}", exist_ok=True)

        pool = QThreadPool.globalInstance()
        # Set max threads to number of servers or a reasonable limit (e.g., 20)
        pool.setMaxThreadCount(5)

        total = len(self.servers)
        for s in self.servers:
            fetcher = ReportFetcher(s)
#            fetcher.signals.finished.connect(self.on_one_finished)
            pool.start(fetcher)

        # Wait for pool to finish
        pool.waitForDone()
        self.all_finished.emit()

    def on_one_finished(self, ip):
        self.completed_count += 1
        percent = int((self.completed_count / len(self.servers)) * 100)
        self.progress.emit(percent)

class NumericTableWidgetItem(QTableWidgetItem):
    def __init__(self, text, sort_value):
        super().__init__(text)
        self.sort_value = sort_value

    def __lt__(self, other):
        if isinstance(other, NumericTableWidgetItem):
            return self.sort_value < other.sort_value
        return super().__lt__(other)

# --- 1. Dialog for Add/Edit (Compact Design) ---
class ServerDialog(QDialog):
    def __init__(self, parent=None, data=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Server" if data else "Add New Server")
        self.layout = QFormLayout(self)
        self.layout.setContentsMargins(15, 15, 15, 15)
        self.layout.setSpacing(10)
        timezone = self.get_timezone()

        self.name_edit = QLineEdit(data['server'] if data else "")
        self.ip_edit = QLineEdit(data['ip'] if data else "")
        self.tz_edit = QLineEdit(data['timezone'] if data else timezone)
        self.port_edit = QLineEdit(str(data['port']) if data else "22")
        self.user_edit = QLineEdit(data['user'] if data else "root")
        self.pass_edit = QLineEdit(data['password'] if data else "")
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.tz_edit.setMinimumWidth(160)

        self.layout.addRow("Name:", self.name_edit)
        self.layout.addRow("IP/Hostname:", self.ip_edit)
        self.layout.addRow("Timezone:", self.tz_edit)
        self.layout.addRow("Port:", self.port_edit)
        self.layout.addRow("Username:", self.user_edit)
        self.layout.addRow("Password:", self.pass_edit)
        
        btns = QHBoxLayout()
        self.btn_apply = QPushButton("Apply")
        self.btn_cancel = QPushButton("Cancel")
        btns.addWidget(self.btn_apply); btns.addWidget(self.btn_cancel)
        self.layout.addRow(btns)
        
        self.btn_apply.clicked.connect(self.accept)
        self.btn_cancel.clicked.connect(self.reject)

    def get_data(self):
        return {
            "server": self.name_edit.text().strip(),
            "ip": self.ip_edit.text().strip(),
            "timezone": self.tz_edit.text().strip(),
            "port": self.port_edit.text().strip(),
            "user": self.user_edit.text().strip(),
            "password": self.pass_edit.text().strip()
        }

    def get_timezone(self):
        current_os = platform.system()
        try:
            if current_os == "Windows":
                # 1. Get the Timezone Name (e.g., 'Iran Standard Time')
                # 2. Get the Offset using PowerShell (returns format like '+0330')
                name_cmd = "tzutil /g"
                offset_cmd = "powershell (Get-Date -Format 'zzzz').Replace(':', '')"
            
                tz_name = subprocess.check_output(name_cmd, shell=True, text=True).strip()
                offset_str = subprocess.check_output(offset_cmd, shell=True, text=True).strip()
            
            elif current_os == "Darwin":  # macOS
                # Use readlink to avoid sudo requirements on Mac
                cmd = "readlink /etc/localtime | sed 's/.*zoneinfo\///' && date +%z"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                parts = result.stdout.strip().split()
                tz_name, offset_str = parts[0], parts[1]
            
            else:  # Linux (Rocky/Debian/Ubuntu)
                cmd = "printf '%s %s' $(timedatectl show --property=Timezone --value) $(date +%z)"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                tz_name, offset_str = result.stdout.strip().split()

            print(f"✅ Local System ({current_os}): {tz_name} ({offset_str})")
            return f"{tz_name} {offset_str}"

        except Exception as e:
            print(f"❌ Error getting time zone on {current_os}: {e}")
            return ""

class AutoStatsWorker(QThread):
    # This signal sends the raw list of dictionaries to update_stats_table
    stats_ready = pyqtSignal(list)

    def __init__(self, targets, display_mode, time_window):
        super().__init__()
        self.targets = targets
        self.display_mode = display_mode
        self.time_window = time_window # Format: "X minutes ago"

    def run(self):
        results = []
        # Using 15 workers just like your StatsWorker for fast parallel fetching
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(self.get_stats, s) for s in self.targets]
            for f in as_completed(futures):
                results.append(f.result())
        
        # Sort by IP or clients if preferred, then emit to GUI
        self.stats_ready.emit(results)

    def fix_reboot_data_points(self, data_points):
        """
        Fixes reboot resets for data stored in a list of dictionaries.
        Expected keys: 'c' (clients), 'u' (upload), 'd' (download)
        """
        if len(data_points) < 2:
            return data_points

        offset_up = 0
        offset_down = 0

        # Initialize previous raw trackers with the first entry
        prev_raw_u = data_points[0]['u']
        prev_raw_d = data_points[0]['d']

        # We start from the second element
        for i in range(1, len(data_points)):
            current_raw_u = data_points[i]['u']
            current_raw_d = data_points[i]['d']

            # Detect Reboot: If current download is less than previous, the counter reset.
            if current_raw_d < prev_raw_d:
                offset_up += prev_raw_u
                offset_down += prev_raw_d
                # Optional: print("Reboot detected in dictionary data.")

            # Apply offsets to the current dictionary values
            data_points[i]['u'] = current_raw_u + offset_up
            data_points[i]['d'] = current_raw_d + offset_down

            # Update the 'previous' trackers with CURRENT raw values for the next loop
            prev_raw_u = current_raw_u
            prev_raw_d = current_raw_d

        return data_points

    def get_stats(self, s):
        res = {"ip": s['ip'], "success": False, "clients": "0", "up_val": "0 B", "down_val": "0 B"}
        
        try:
            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")
#            connect_kwargs = {"key_filename": [valid_keys], "look_for_keys": False, "allow_agent": False, "timeout": 10}
            p = int(s['port'])
            user = s['user'].strip()
            password = s['password'].strip()
            is_root = (user == "root")

            if is_root:
                # Key-based: Explicitly tell Fabric which files to use
                connect_kwargs = {
                    "timeout": 10,
                    "key_filename": [key_path],
                    "look_for_keys": False,
                    "allow_agent": False
                }
                cfg = Config()

            else:
                # Password-based
                connect_kwargs = {"password": password, "timeout": 15}
                cfg = Config(overrides={'sudo': {'password': password}})

            with Connection(host=s['ip'], user=user, port=p, connect_kwargs=connect_kwargs, config=cfg) as conn:
                # 1. Check if the service is actually RUNNING right now

                def run_cmd(cmd, **kwargs):

                    kwargs.setdefault('hide', False)
                    kwargs.setdefault('warn', False)
                    kwargs.setdefault('timeout', 20)

                    if is_root:
                        return conn.run(cmd, **kwargs)
                    else:    
                        return conn.sudo(cmd, **kwargs)

                status_check = run_cmd(f"systemctl is-active conduit{AppState.conduit_id}.service",hide=True, warn=True)
                is_running = status_check.stdout.strip() == "active"

                if not is_running:
                    res["success"] = False
                    res["clients"] = "Stopped"
                    return res

                # 2. If running, get the logs for the requested window

                cmd = (
                    f"journalctl -u conduit-monitor{AppState.conduit_id}.service "
                    f"--since \"{self.time_window}\" --no-pager -o short-iso | "
                    f"awk -F' CONDUIT_JSON: ' '{{ "
                    f"split($2, b, \",\"); "
                    f"print b[1] \",\" b[2] \",\" b[3] "
                    f"}}'"
                )

                result = run_cmd(cmd, hide=True, timeout=30)
                output = result.stdout.strip()

                if output:
                    lines = output.splitlines()
                    
                    data_points = []
                    for line in lines:
                        m = re.search(r"clients=(\d+),up=(\d+),down=(\d+)", line)

                        if m:
                            data_points.append({
                                'c': int(m.group(1)),
                                'u': int(m.group(2)),
                                'd': int(m.group(3))
                            })
                    if data_points:
                        data_points = self.fix_reboot_data_points(data_points)

                    if data_points:
                        res["success"] = True
                        client_counts = [d['c'] for d in data_points if d['c'] > 0]
                        if client_counts:
                            avg_clients = sum(client_counts) / len(client_counts)

                        first, last = data_points[0], data_points[-1]

                        res["clients"] = str(int(round(avg_clients)))
                        res["up_val"] = self.format_bytes(max(0, last['u'] - first['u']))
                        res["down_val"] = self.format_bytes(max(0, last['d'] - first['d']))
                else:
                    res["success"] = False
                    res["clients"] = "No Data"
                    
        except Exception:
            res["clients"] = "Offline"
            
        return res

    def parse_to_bytes(self, s):
        if not s or "0B" in s: return 0.0
        match = re.search(r'([\d\.]+)', s)
        if not match: return 0.0
        num = float(match.group(1))
        u = s.upper()
        if 'TB' in u: return num * 1024**4
        if 'GB' in u: return num * 1024**3
        if 'MB' in u: return num * 1024**2
        if 'KB' in u: return num * 1024
        if 'B' in u: return num
        return num

    def format_bytes(self, b):
        if b == 0: return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024: return f"{b:.2f} {unit}"
            b /= 1024
        return f"{b:.2f} PB"

# --- 2. Background Worker (SSH) ---
class ServerWorker(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, action, targets, config):
        super().__init__()
        self.action = action
        self.targets = targets
        self.config = config

    def run(self):
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.ssh_task, s) for s in self.targets]
            for f in as_completed(futures):
                self.log_signal.emit(f.result())

    def ssh_task(self, s):
        try:

            p = int(s['port'])
            user = s['user'].strip()
            password = s['password'].strip()
            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")
            is_root = (user == "root")

            # Official psiphon release uses the simplified command
            cmd_parts = [
                f"/opt/conduit{AppState.conduit_id}/conduit start",
                f"--max-clients {self.config['clients']}",
                f"--bandwidth {self.config['bw']}",
                f"--data-dir /var/lib/conduit{AppState.conduit_id}"
            ]

            service_file = f"/etc/systemd/system/conduit{AppState.conduit_id}.service"

            if conduit_release != "psiphon":
                # uses the extra config, geo, and stats flags
                cmd_parts.append("--geo --stats-file stats.json")

                if conduit_release == "byte_release":
                    # allows conduit to log bytes instead of KMGT
                    cmd_parts.append(f"--psiphon-config /opt/conduit{AppState.conduit_id}/psiphon_config.json")                
                
                if AppState.use_lion_sun:
                    # allows only Shir o Khorshid android clients in "Conduit Mode" settings to be connected
                    cmd_parts.append("--compartment shirokhorshid")

            exec_cmd = " ".join(cmd_parts)

            # Cross-platform home directory
            
            
#            potential_keys = [
#                os.path.join(home, ".ssh", "id_conduit")
#            ]
            # Filter to only keys that actually exist on your Windows machine
#            key_path = [k for k in potential_keys if os.path.exists(k)]

            if is_root:
                # Key-based: Explicitly tell Fabric which files to use
                connect_params = {
                    "timeout": 15,
                    "key_filename": [key_path],
                    "look_for_keys": False,
                    "allow_agent": False
                }
                cfg = Config()

            else:
                # Password-based
                connect_params = {"password": password, "timeout": 15}
                cfg = Config(overrides={'sudo': {'password': password}})

            with Connection(host=s['ip'], user=user, port=p, 
                            connect_kwargs=connect_params, config=cfg) as conn:
                
                def run_cmd(cmd, **kwargs):

                    kwargs.setdefault('hide', False)
                    kwargs.setdefault('warn', False)
                    kwargs.setdefault('timeout', 10)

                    if is_root:
                        return conn.run(cmd, **kwargs)
                    else:    
                        return conn.sudo(cmd, **kwargs)

                def get_conduit_stats():
                    service_path = f"/etc/systemd/system/conduit{AppState.conduit_id}.service"
    
                    # This command searches the ExecStart line for the flags and returns just the values
                    cmd = f"grep 'ExecStart' {service_path} | grep -oP '(?<=--max-clients )[0-9]+|(?<=--bandwidth )[0-9.]+'"
    
                    result = run_cmd(cmd, hide=True, warn=True)
    
                    if result and result.ok:
                        # result.stdout will contain two lines: max-clients and bandwidth
                        output = result.stdout.strip().split('\n')
                        if len(output) >= 2:
                            max_clients = output[0]
                            bandwidth = output[1]
#                            print(f"Current Config: {max_clients} Clients @ {bandwidth} Mbps")
                            return f"max-clients: {max_clients} bandwidth: {bandwidth} Mbps"
    
                    print(f"Failed to parse conduit{AppState.conduit_id} service file.")
                    return f"max-clients: None bandwidth: None Mbps"

                if self.action == "reset":
                    # 1. Stop the service
                    run_cmd(f"systemctl stop conduit{AppState.conduit_id}", hide=True, warn=True)
                    time.sleep(2)
                    # 2. Wipe the data directory (CAUTION: Destructive)
                    # We use -rf to ensure it clears everything inside
                    run_cmd(f"rm -rf /var/lib/conduit{AppState.conduit_id}/*", hide=True, warn=True)
                    
                    # 3. Apply Config if requested 

                    if self.config['update']:
                        #if conduit_release == 'pre_release':
#                            exec_cmd = f"/opt/conduit/conduit start --max-clients {self.config['clients']} --bandwidth {self.config['bw']} --psiphon-config /opt/conduit/psiphon_config.json --geo --stats-file stats.json --data-dir /var/lib/conduit"
#                        else:
#                            exec_cmd = f"/opt/conduit/conduit start --max-clients {self.config['clients']} --bandwidth {self.config['bw']} --data-dir /var/lib/conduit"

#                        run_cmd(f"sed -i 's|^ExecStart=.*|ExecStart={exec_cmd}|' /etc/systemd/system/conduit.service", hide=True, warn=True)
                        sed_cmd = f"sed -i 's|^ExecStart=.*|ExecStart={exec_cmd}|' {service_file}"
                        run_cmd(sed_cmd, hide=True, warn=True)
                        run_cmd("systemctl daemon-reload", hide=True, warn=True)
                    
                    # 4. Start service
                    run_cmd(f"systemctl start conduit{AppState.conduit_id}", hide=True, warn=True)
                    return f"[!] {s['server']}: FULL RESET COMPLETE (Data wiped & restarted)."

                if self.action == "status":
                    # 1. Get the standard systemctl status (Active/Inactive)
                    status_res = run_cmd(f"systemctl is-active conduit{AppState.conduit_id}", hide=True, warn=True)
                    current_status = status_res.stdout.strip() if status_res.ok else "inactive"
                    current_status = f"[*] {s['server']} ({s['ip']}): { current_status.upper()}"

                    remote_date_cmd = "date '+%Y-%m-%d %H:%M:%S'"
                    result = run_cmd(remote_date_cmd, hide=True, warn=True)

                    if result.ok:
                        remote_time = result.stdout.strip()
                        print(f"Remote Server Time: {remote_time}")
                    else:
                        remote_time = "00-00-00 00-00-00"

                    # 2. Get the last 5 lines of the journal
                    log_res = run_cmd(f"journalctl -u conduit{AppState.conduit_id}.service -n 10 --no-pager", hide=True, warn=True)
                    journal_logs = log_res.stdout if log_res.ok else "No logs found."

                    # 3. Combine them for the UI
                    
                    output = f"--- STATUS: {current_status} ---\n{get_conduit_stats()}  current system time: {remote_time}\n{journal_logs}"
                    return output        
                
                if self.action == "stop":
                    run_cmd(f"systemctl stop conduit{AppState.conduit_id}", hide=True)
                    return f"[-] {s['server']} Stopped."

                if self.action in ["start", "restart"]:
                    if self.config['update']:
#                        if conduit_release == 'pre_release':
#                            exec_cmd = f"/opt/conduit/conduit start --max-clients {self.config['clients']} --bandwidth {self.config['bw']} --psiphon-config /opt/conduit/psiphon_config.json --geo --stats-file stats.json --data-dir /var/lib/conduit"
#                        else:
#                            exec_cmd = f"/opt/conduit/conduit start --max-clients {self.config['clients']} --bandwidth {self.config['bw']} --data-dir /var/lib/conduit"

                        sed_cmd = f"sed -i 's|^ExecStart=.*|ExecStart={exec_cmd}|' {service_file}"
                        run_cmd(sed_cmd, hide=True)
                        run_cmd("systemctl daemon-reload", hide=True)
                    
                    run_cmd(f"systemctl {self.action} conduit{AppState.conduit_id}", hide=True)
                    return f"[+] {s['server']} {self.action.capitalize()}ed."
                
        except Exception as e:
            return f"[!] {s['server']} Error: {str(e)}"            


class StatsWorker(QThread):
    finished_signal = pyqtSignal(str)

    def __init__(self, targets, display_mode):
        super().__init__()
        self.targets = targets
        self.display_mode = display_mode

    def run(self):
        results = []
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(self.get_stats, s) for s in self.targets]
            for f in as_completed(futures):
                results.append(f.result())
        
        results = sorted(results, key=lambda x: x.get('mbps_val', 0), reverse=True)
        self.finished_signal.emit(self.generate_table(results))

    def fix_reboot_data_points(self, data_points):
        """
        Fixes reboot resets for data stored in a list of dictionaries.
        Expected keys: 'c' (clients), 'u' (upload), 'd' (download)
        """
        if len(data_points) < 2:
            return data_points

        offset_up = 0
        offset_down = 0

        # Initialize previous raw trackers with the first entry
        prev_raw_u = data_points[0]['u']
        prev_raw_d = data_points[0]['d']

        # We start from the second element
        for i in range(1, len(data_points)):
            current_raw_u = data_points[i]['u']
            current_raw_d = data_points[i]['d']

            # Detect Reboot: If current download is less than previous, the counter reset.
            if current_raw_d < prev_raw_d:
                offset_up += prev_raw_u
                offset_down += prev_raw_d
                # Optional: print("Reboot detected in dictionary data.")

            # Apply offsets to the current dictionary values
            data_points[i]['u'] = current_raw_u + offset_up
            data_points[i]['d'] = current_raw_d + offset_down

            # Update the 'previous' trackers with CURRENT raw values for the next loop
            prev_raw_u = current_raw_u
            prev_raw_d = current_raw_d

        return data_points

    def get_stats(self, s):
        display_label = s['server'] if self.display_mode == 'server' else s['ip']
        # Initialize with numeric zeros
        res = {
            "label": display_label, "success": False, "clients": 0, 
            "up": 0, "down": 0, "uptime": 0, 
            "mbps": "0.00", "mbps_val": 0.0,
            "mbps_1h": "0.00", "up_1h": 0, "down_1h": 0
        }
        
        try:
            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")
            port_num = int(s['port'])
            user = s['user'].strip()
            password = s['password'].strip()
            is_root = (user == "root")

            if is_root:
                connect_kwargs = {"timeout": 10, "key_filename": [key_path], "look_for_keys": False, "allow_agent": False}
                cfg = Config()
            else:
                connect_kwargs = {"password": password, "timeout": 15}
                cfg = Config(overrides={'sudo': {'password': password}})

            with Connection(host=s['ip'], user=user, port=port_num, connect_kwargs=connect_kwargs, config=cfg) as conn:
                def run_cmd(cmd, **kwargs):
                    kwargs.setdefault('hide', True)
                    kwargs.setdefault('warn', True)
                    kwargs.setdefault('timeout', 15)
                    return conn.run(cmd, **kwargs) if is_root else conn.sudo(cmd, **kwargs)

                cmd = (
                    f"journalctl -u conduit-monitor{AppState.conduit_id}.service "
                    f"--since '1 hour ago' --no-pager -o short-iso | "
                    f"awk -F' CONDUIT_JSON: ' '{{ "
                    f"split($2, b, \",\"); "
                    f"print b[1] \",\" b[2] \",\" b[3] \",\" b[4] "
                    f"}}'"
                )
                
                result = run_cmd(cmd)
                output = result.stdout.strip()
                
                if output:
                    lines = output.splitlines()
                    data_points = []
                    for line in lines:
                        # Parsing into raw integers
                        m = re.search(r"clients=(\d+),up=(\d+),down=(\d+),uptime=(\d+)", line)
                        if m:
                            data_points.append({
                                'c': int(m.group(1)),
                                'u': int(m.group(2)),
                                'd': int(m.group(3)),
                                'ut': int(m.group(4))
                            })

                    if data_points:
                        data_points = self.fix_reboot_data_points(data_points)
                        res["success"] = True
                        first = data_points[0]
                        last = data_points[-1]

                        # Store as numeric types
                        avg_clients = sum(d['c'] for d in data_points) / len(data_points)
                        res["clients"] = int(round(avg_clients))
                        res["up"] = last['u']
                        res["down"] = last['d']
                        res["uptime"] = last['ut']
                        res["up_1h"] = max(0, last['u'] - first['u'])
                        res["down_1h"] = max(0, last['d'] - first['d'])

                        # Mbps logic
                        if last['ut'] > 0:
                            mbps = (last['d'] * 8) / last['ut'] / (1024*1024)
                            res["mbps_val"] = mbps
                            res["mbps"] = f"{mbps:.2f}"

                        ut_1h = last['ut'] - first['ut']
                        if ut_1h > 0:
                            mbps_1h = ((last['d'] - first['d']) * 8) / ut_1h / (1024*1024)
                            res["mbps_1h"] = f"{mbps_1h:.2f}"
                else:
                    res["uptime_str"] = "No Data (1h)"

        except Exception:
            res["uptime_str"] = "Conn Error"
            
#        print(res)            
        return res

    def seconds_to_uptime(self,seconds):
        """
        Converts seconds into a string format: 210h44m53s
        """
        try:
            seconds = int(seconds)
            # Calculate hours, then get the remaining seconds to find minutes
            hours, remainder = divmod(seconds, 3600)
            minutes, secs = divmod(remainder, 60)
        
            return f"{hours}h{minutes}m{secs}s"
        except (ValueError, TypeError):
            return "0h0m0s"

    def uptime_to_seconds(self, uptime_str):
        try:
            # Handle formats like 6h55m19s
            h = int(re.search(r'(\d+)h', uptime_str).group(1)) if 'h' in uptime_str else 0
            m = int(re.search(r'(\d+)m', uptime_str).group(1)) if 'm' in uptime_str else 0
            s = int(re.search(r'(\d+)s', uptime_str).group(1)) if 's' in uptime_str else 0
            return (h * 3600) + (m * 60) + s
        except:
            return 0

    def parse_to_bytes(self, s):
        if not s or "0B" in s: return 0.0
        match = re.search(r'([\d\.]+)', s)
        if not match: return 0.0
        num = float(match.group(1))
        u = s.upper()
        if 'TB' in u: return num * 1024**4
        if 'GB' in u: return num * 1024**3
        if 'MB' in u: return num * 1024**2
        if 'KB' in u: return num * 1024
        if 'B'  in u: return num
        return num

#    def strip_ansi(text):
#        return re.compile(r'\x1b\[[0-9;]*[a-zA-Z]').sub('', text)

    def format_bytes(self,b):
        if b == 0: return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024: return f"{b:.2f} {unit}"
            b /= 1024
        return f"{b:.2f} PB"

    def generate_table(self, results):
        width = 121
        head = f"│ {'Name/IP':<20} │ {'Clients':<8} │ {'Up (total | 1h)':<22} │ {'Down (total | 1h)':<22} │ {'Uptime':<14} │ {'Mbps (total | 1h)':<17}  │\n"
        sep = "├" + "─"*22 + "┼" + "─"*10 + "┼" + "─"*24 + "┼" + "─"*24 + "┼" + "─"*16 + "┼" + "─"*20 +  "┤\n"
        
        body = ""
        valid_results = [r for r in results if r["success"]]

        for r in results:
            status = "✓" if r["success"] else "✗"
            if r["success"]:
                uptime = self.seconds_to_uptime(r['uptime'])
                
                # 1. Format raw bytes to strings
                u_tot = self.format_bytes(r['up'])
                u_1h  = self.format_bytes(r['up_1h'])
                d_tot = self.format_bytes(r['down'])
                d_1h  = self.format_bytes(r['down_1h'])
                m_tot = r['mbps']
                m_1h  = r['mbps_1h']
                
                # 2. Build fixed-width display strings
                # We allocate 10 chars for Total (right-aligned) and 9 for 1h (left-aligned)
                up_display    = f"{u_tot:>10} | {u_1h:<9}"
                down_display  = f"{d_tot:>10} | {d_1h:<9}"
                mbps_display  = f"{m_tot:>6} | {m_1h:<6}"
                
                # 3. Add to body with a fixed column width of 22
                body += f"│ {status} {r['label'][:18]:<18} │ {r['clients']:<8} │ {up_display:<22} │ {down_display:<22} │ {uptime:<14} │ {mbps_display:<14}    │\n"
            else:
                uptime = r.get("uptime_str", "Conn Error")
                body += f"│ {status} {r['label'][:18]:<18} │ {'-':<8} │ {'-':^22} │ {'-':^22} │ {uptime:<14} │ {'0.00 | 0.00':<14}    │\n"

        main_table = f"┌" + "─"*width + "┐\n" + head + sep + body + "└" + "─"*width + "┘"

        # 2. Analytics Summary Logic
        if not valid_results:
            return main_table + "\n[!] No active data to calculate analytics."

        ts = (datetime.now(timezone.utc) + timedelta(hours=3, minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
        
        # Clients are already stored as average strings, so we convert back to int for analytics
        clients_list = [r["clients"] for r in valid_results if r["clients"]]
        total_clients = sum(clients_list)        

        ups = [r["up"] for r in valid_results]
        downs = [r["down"] for r in valid_results]

        mbps_list = [r["mbps_val"] for r in valid_results]

        server_count = len(valid_results)
        total_up_all = sum(ups)
        total_down_all = sum(downs)

        total_up_1h = sum([r["up_1h"] for r in valid_results])
        total_down_1h = sum([r["down_1h"] for r in valid_results])

        out = []
        out.append(f"\n--- Analytics Summary (Iran Time: {ts}) ---")
        out.append(f"Total Average Clients across all servers: {total_clients}\n")
        
        # Printing the specific totals you requested
        out.append(f"\nTotal UP across {server_count} servers: {self.format_bytes(total_up_all)} | Total UP in last one hour: {self.format_bytes(total_up_1h)}")
        out.append(f"Total Down across {server_count} servers: {self.format_bytes(total_down_all)} | Total DOWN in last one hour: {self.format_bytes(total_down_1h)}\n")

        out.append(f"{'Metric':<12} │ {'Mean':<12} │ {'Median':<12} │ {'Min':<12} │ {'Max':<12}")
        sep_line = f"{'─'*13}┼{'─'*14}┼{'─'*14}┼{'─'*14}┼{'─'*14}"
        out.append(sep_line)

        def get_stat_row(label, data_list, is_bytes=False):
            if not data_list: return ""
            import statistics
            avg_val = statistics.mean(data_list)
            med_val = statistics.median(data_list)
            min_val = min(data_list)
            max_val = max(data_list)
            
            if is_bytes:
                return f"{label:<12} │ {self.format_bytes(avg_val):<12} │ {self.format_bytes(med_val):<12} │ {self.format_bytes(min_val):<12} │ {self.format_bytes(max_val):<12}"
            if label == "Clients":
                return f"{label:<12} │ {int(round(avg_val)):<12} │ {int(round(med_val)):<12} │ {int(min_val):<12} │ {int(max_val):<12}"
            return f"{label:<12} │ {avg_val:<12.2f} │ {med_val:<12.2f} │ {min_val:<12.2f} │ {max_val:<12.2f} Mbps"

        out.append(get_stat_row("Clients", clients_list))
        out.append(get_stat_row("Upload", ups, True))
        out.append(get_stat_row("Download", downs, True))
        out.append(get_stat_row("Avg Mbps", mbps_list))

        return main_table + "\n" + "\n".join(out)

class DeployWorker(QThread):
    log_signal = pyqtSignal(str)
    update_time_zone = pyqtSignal(dict) # { 'ip': 'timezone_string' }    

    def __init__(self, action, targets, params, client_ip):
        super().__init__()
        self.targets = targets
        self.params = params # password, max_clients, bandwidth, user
        self.action = action

    def run(self):
        # Read the public key once
        home = os.path.expanduser("~")
        pub_key_path = os.path.join(home, ".ssh", "id_conduit.pub")
        
        if not os.path.exists(pub_key_path):
            self.log_signal.emit(f"[ERROR] Public key not found at: {pub_key_path}")
            return

        collected_timezones = {}

        with open(pub_key_path, "r") as f:
            pub_key_content = f.read().strip()

        if self.action == "deploy":
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.deploy_task, s, pub_key_content) for s in self.targets]
                for f in as_completed(futures):
                    success, message, tz_data, ip = f.result()
                    self.log_signal.emit(message)

                    # If successful and we got a timezone, add to our batch
                    if success and tz_data:
                        collected_timezones[ip] = tz_data


            # After ALL threads are done, emit the batch update

            if collected_timezones:
                self.update_time_zone.emit(collected_timezones)

        elif self.action == "upgrade":
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.upgrade_task, s) for s in self.targets]
                for f in as_completed(futures):
                    self.log_signal.emit(f.result())
        else:
            self.log_signal.emit(f"[WARNING] No action is taken: {s['ip']}")
            return

    def deploy_task(self, s, pub_key):
        try:

            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")
            port_num = int(s['port'])
            ssh_port = int(s['port'])
            target_ip = s['ip']

            if self.params['default_port']:
                ssh_port = 22

            user = s['user'].strip()
            password = s['password'].strip()
            is_root = (user == "root")
        
            if is_root:
                # Key-based: Explicitly tell Fabric which files to use
                connect_params = {
                    "timeout": 10,
                    "banner_timeout": 20,
                    "password": password,
                }
                cfg = Config()

            else:
                # Password-based
                connect_params = {"password": password, "timeout": 10, "banner_timeout": 20}
                cfg = Config(overrides={'sudo': {'password': password}})            

            # Official psiphon release uses the simplified command
            cmd_parts = [
                f"/opt/conduit{AppState.conduit_id}/conduit start",
                f"--max-clients {self.params['clients']}",
                f"--bandwidth {self.params['bw']}",
                f"--data-dir /var/lib/conduit{AppState.conduit_id}"
            ]

            if conduit_release != "psiphon":
                # uses the extra config, geo, and stats flags
                cmd_parts.append("--geo --stats-file stats.json")

                if conduit_release == "byte_release":
                    # allows conduit to log bytes instead of KMGT
                    cmd_parts.append(f"--psiphon-config /opt/conduit{AppState.conduit_id}/psiphon_config.json")                
                
                if AppState.use_lion_sun:
                    # allows only Shir o Khorshid android clients in "Conduit Mode" settings to be connected
                    cmd_parts.append("--compartment shirokhorshid")

            exec_cmd = " ".join(cmd_parts)
            messages = []

            with Connection(host=target_ip, 
                            user=user,
                            port=ssh_port, 
                            connect_kwargs=connect_params,
                            config=cfg,
                            inline_ssh_env=True
            ) as conn:
                
                def run_cmd(cmd, **kwargs):

                    kwargs.setdefault('hide', False)
                    kwargs.setdefault('warn', False)

                    if is_root:
                        return conn.run(cmd, **kwargs)
                    else:    
                        return conn.sudo(cmd, **kwargs)  

                # Check if we are actually root or have access
                # This "id -u" check returns 0 for root

                res = run_cmd("id -u",hide=True, warn=True)
                if not res.ok:
                    return f"[SKIP] {target_ip}: Could not connect or not root."
                
                # 1. Key Injection
                if not AppState.use_sec_inst:
                    run_cmd("mkdir -p ~/.ssh && chmod 700 ~/.ssh",hide=True)
                    run_cmd(f'echo "{pub_key}" >> ~/.ssh/authorized_keys',hide=True)
                    run_cmd("chmod 600 ~/.ssh/authorized_keys",hide=True)
                
                    os_check = run_cmd("grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '\"'", hide=True)
                    os_id = os_check.stdout.strip()

                    if "rhel" in os_id or "rocky" in os_id or "almalinux" in os_id or "centos" in os_id or "fedora" in os_id:
                        print("Detected RHEL-based system.")
                        messages.append("Detected RHEL-based system.")
                        rh_distro = True
                    elif "debian" in os_id or "ubuntu" in os_id:
                        print("Detected Debian-based system.")
                        messages.append("Detected Debian-based system.")
                        rh_distro = False

                # 2. Cleanup & Directory Prep                

                run_cmd(f"systemctl stop conduit{AppState.conduit_id}", warn=True, hide=True)
                time.sleep(2)
                run_cmd(f"rm -f /opt/conduit{AppState.conduit_id}/conduit", warn=True, hide=True)
                run_cmd(f"mkdir -p /opt/conduit{AppState.conduit_id}", hide=True)

                # Crucial: The service hardening requires this directory to exist beforehand

                run_cmd(f"rm -rf /var/lib/conduit{AppState.conduit_id}", warn=True, hide=True)
                run_cmd(f"mkdir -p /var/lib/conduit{AppState.conduit_id}", hide=True)
                
                if not AppState.use_sec_inst:
                    # install system and network monitoring packages

#                    if run_cmd("command -v dnf", warn=True, hide=True).ok:
                    if rh_distro:
                        run_cmd("dnf install epel-release -y", hide=True)
                        run_cmd("dnf install sed wget policycoreutils firewalld curl tcpdump bind-utils net-tools vim htop nload iftop nethogs glances python3-bottle jq -y", hide=True)
                    else:
#                        conn.run("apt-get update -y", hide=True)
                        run_cmd("apt-get update -y", hide=True)
                        run_cmd("apt-get install sed wget policycoreutils selinux-utils policycoreutils-python-utils firewalld curl tcpdump dnsutils net-tools vim htop nload iftop nethogs glances python3-bottle jq -y", hide=True)

                
                # 3. Download Binary

                run_cmd(f"curl -L -o /opt/conduit{AppState.conduit_id}/conduit {CONDUIT_URL}", hide=True)
                run_cmd(f"chmod +x /opt/conduit{AppState.conduit_id}/conduit")

                if conduit_release == 'byte_release':
                    run_cmd(f"curl -L -o /opt/conduit{AppState.conduit_id}/psiphon_config.json {PSIPHON_CONFIG_URL}", hide=True)

                # 4. Manually Create the Service File (Replacing 'service install')
                WorkingDirectory = f"/opt/conduit{AppState.conduit_id}/"
                ReadWritePaths=f"/var/lib/conduit{AppState.conduit_id}"

                service_content = f"""[Unit]
Description=Psiphon Conduit inproxy service - relays traffic for users in censored regions
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_cmd}
Restart=always
RestartSec=10
User=root
Group=root
WorkingDirectory={WorkingDirectory}

# Hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths={ReadWritePaths}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
                # Escape single quotes in the content if any (though there are none currently)
                # We use sudo tee to write to the protected system directory
                run_cmd(f"echo '{service_content}' | sudo tee /etc/systemd/system/conduit{AppState.conduit_id}.service > /dev/null")

                # 5. Reload, Enable, and Start
                run_cmd("systemctl daemon-reload", hide=True)
                run_cmd(f"systemctl enable conduit{AppState.conduit_id}", hide=True)
                run_cmd(f"systemctl start conduit{AppState.conduit_id}", hide=True)
                
                # 6. Download Stats Script from GitHub
                # We use the 'raw' GitHub URL to get the actual code, not the HTML page
                stats_script_url = "https://raw.githubusercontent.com/Starling226/conduit-manager/main/get_conduit_stat.py"
                run_cmd(f"curl -L -o /opt/conduit{AppState.conduit_id}/get_conduit_stat.py {stats_script_url}", hide=True)
                run_cmd(f"chmod +x /opt/conduit{AppState.conduit_id}/get_conduit_stat.py")

                # 7. Setup Cronjob (Idempotent: prevents duplicate entries)
                cron_cmd = f"5 * * * * /usr/bin/python3 /opt/conduit{AppState.conduit_id}/get_conduit_stat.py --work_dir /opt/conduit{AppState.conduit_id} --service conduit{AppState.conduit_id}.service >> /opt/conduit{AppState.conduit_id}/cron_sys.log 2>&1"
                # This command checks if the job exists; if not, it adds it to the crontab
                search_pattern = f"/opt/conduit{AppState.conduit_id}/get_conduit_stat.py --work_dir /opt/conduit{AppState.conduit_id} --service conduit{AppState.conduit_id}.service"

#                run_cmd(f'(crontab -l 2>/dev/null | grep -Fv "/opt/conduit{conduit_id}/get_conduit_stat.py" ; echo "{cron_cmd}") | crontab -', hide=True)
                run_cmd(f'(crontab -l 2>/dev/null | grep -v -w "{search_pattern}" ; echo "{cron_cmd}") | crontab -', hide=True)
                
                #8. setting up the Systemd service for conduit-monitor

                if AppState.conduit_id:
                    exec_cmd = f"/opt/conduit{AppState.conduit_id}/conduit-monitor.sh --stats-file /var/lib/conduit{AppState.conduit_id}/stats.json --id {AppState.conduit_id}"
                else:
                    exec_cmd = f"/opt/conduit{AppState.conduit_id}/conduit-monitor.sh --stats-file /var/lib/conduit{AppState.conduit_id}/stats.json"
            
                # setting up the Systemd service for conduit-monitor.sh            
                           
                conduit_monitor_service_config = f"""[Unit]
Description=Conduit Metric Logger (10s)
After=network.target
# Ensure this only runs if Conduit is actually running
Requires=conduit.service
After=conduit.service

[Service]
ExecStart={exec_cmd}
Restart=always
RestartSec=5
# Run as a specific user if needed, or root
User=root

[Install]
WantedBy=multi-user.target"""

                run_cmd(f"echo '{conduit_monitor_service_config}' | sudo tee /etc/systemd/system/conduit-monitor{AppState.conduit_id}.service > /dev/null")
                
                # 5. Download conduit-monitor.sh Script from GitHub
                # We use the 'raw' GitHub URL to get the actual code, not the HTML page
                # in case this is a re-deployment
                # This stops it, and if it takes more than 5 seconds, it kills it instantly.
                # Then it deletes the file.
                cmd = (
                    f"systemctl stop conduit-monitor{AppState.conduit_id} --timeout=5s; "
                    f"systemctl kill -s SIGKILL conduit-monitor{AppState.conduit_id} 2>/dev/null; "
                    f"rm -f /opt/conduit{AppState.conduit_id}/conduit-monitor.sh"
                )
                run_cmd(cmd, warn=True, hide=True)

                stats_script_url = "https://raw.githubusercontent.com/Starling226/conduit-manager/main/conduit-monitor.sh"
                run_cmd(f"curl -L -o /opt/conduit{AppState.conduit_id}/conduit-monitor.sh {stats_script_url}", hide=True)
                run_cmd(f"chmod +x /opt/conduit{AppState.conduit_id}/conduit-monitor.sh")

                # 5. Reload, Enable, and Start
                run_cmd("systemctl daemon-reload", hide=True)
                run_cmd(f"systemctl enable --now conduit-monitor{AppState.conduit_id}", hide=True)
                run_cmd(f"systemctl start conduit-monitor{AppState.conduit_id}", hide=True)
                time.sleep(2)
                
                status_res = run_cmd(f"systemctl is-active conduit-monitor{AppState.conduit_id}", hide=True, warn=True)
                current_status = status_res.stdout.strip() if status_res.ok else "inactive"

                if current_status == "inactive":
                    current_status = f"[*] {s['server']} ({s['ip']}): { current_status.upper()}"
                    print(f"conduit-monitor{AppState.conduit_id} service failed to start: {current_status}")
                    messages.append(f"conduit-monitor{AppState.conduit_id} service failed to start: {current_status}")
                else:
                    current_status = f"[*] {s['server']} ({s['ip']}): { current_status.upper()}"

                
                #9. setting up the Systemd service for glances            
                service_config = """[Unit]
Description=Glances Web Server
After=network.target

[Service]
ExecStart=/usr/bin/glances -w -B 0.0.0.0
Restart=always

[Install]
WantedBy=multi-user.target"""
            
                # 10. Write service file and start
                run_cmd(f"echo '{service_config}' | sudo tee /etc/systemd/system/glancesweb.service", hide=True)
                run_cmd("systemctl daemon-reload", hide=True)
                run_cmd("systemctl enable --now glancesweb.service", hide=True)
            
                run_cmd("firewall-cmd --add-port=61208/tcp --permanent", hide=True)
                cmd = f"""firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="{client_ip}" port protocol="tcp" port="61208" accept'"""
                run_cmd(cmd, hide=True)
                run_cmd("firewall-cmd --reload", hide=True)

                # 11. customizing thhe ssh port number
                if not AppState.use_sec_inst:
                    config_path = "/etc/ssh/sshd_config"
                    cmd = fr"grep -iP '^#?Port\s+\d+' {config_path} | head -1 | awk '{{print $2}}'"
                    current_port_cmd = run_cmd(cmd, hide=True)
                    current_port = current_port_cmd.stdout.strip() or "22" # Default to 22 if not found

                    if str(port_num) == str(current_port):
                        print(f"Port is already {port_num}. No changes needed.")
                        messages.append(f"Port is already {port_num}. No changes needed.")
                        messages.append(f"[OK] {s['ip']} successfully deployed (Manual Service Config).")
                        messages = " ".join(messages)
                        return messages

                    print(f"Changing SSH port from {current_port} to {port_num}...")
                    messages.append(f"Changing SSH port from {current_port} to {port_num}...")
                    
                    # 1. Start the service
                    run_cmd("systemctl start firewalld", hide=True)
                    run_cmd("systemctl enable firewalld", hide=True)

                    # 2. Loop until firewalld is actually running or we timeout
                    max_attempts = 10
                    attempts = 0
                    is_running = False

                    print("Waiting for firewalld to start...")


                    while attempts < max_attempts:
                        # Check status
                        check = run_cmd("firewall-cmd --state", warn=True, hide=True)
    
                        # firewall-cmd --state returns exit code 0 if running
                        if check.ok:
                            is_running = True
                            break
    
                        attempts += 1
                        time.sleep(1) # Short poll interval

                    if is_running:
                        print("Firewalld is active.")
                        # Check if SELinux is active before running semanage
                        if str(port_num) == "22":
                            run_cmd("firewall-cmd --add-service=ssh --permanent", hide=True)
                        else:                    
                            selinux_check = run_cmd("getenforce", warn=True, hide=True)

                            # getenforce returns "Enforcing", "Permissive", or "Disabled"
                            if selinux_check.ok and "Disabled" not in selinux_check.stdout:
                                print("SELinux is active. Updating policy...")
                                # 2. Update the SELinux Policy to allow the new port
                                run_cmd(f"semanage port -a -t ssh_port_t -p tcp {port_num}", warn=True)
                            else:
                                print("SELinux is disabled or not installed. Skipping policy update.")                    

                            # 3. Open the new port in the firewall
                            run_cmd(f"firewall-cmd --add-port={port_num}/tcp --permanent", hide=True)

                            if str(current_port) == "22":
                                # 4. Remove the old SSH service from the firewall
                                run_cmd("firewall-cmd --remove-service=ssh --permanent", hide=True)
                            else:
                                 # 4. Cleanup: Remove the OLD port/service from firewall                             
                                run_cmd(f"firewall-cmd --remove-port={current_port}/tcp --permanent", hide=True)                                                

                            # 5. Reload firewall to apply changes
                            run_cmd("firewall-cmd --reload", hide=True)

                    else:
                        print("Firewalld is NOT running. Skipping firewall rules.")
  
                    # 6. Update the SSH configuration File
                    # This regex replaces the existing active Port line regardless of what the number was
                    sed_cmd = f"sed -i 's/^Port {current_port}/Port {port_num}/' {config_path}"
                    # If the line was commented out (default), we use your previous regex
                    if current_port == "22":
                        sed_cmd = f"sed -i 's/^#\\?Port 22.*/Port {port_num}/' {config_path}"

                    run_cmd(sed_cmd, hide=True)

                     # 7. Restart SSH service to apply config changes
                    if rh_distro:
                        run_cmd("systemctl restart sshd", hide=True)
                    else:
                        run_cmd("systemctl restart ssh", hide=True)
                    
                # getting the server timezone
                tz_string=""

                cmd = "printf '%s %s' $(timedatectl show --property=Timezone --value) $(date +%z)"
                tz_info_raw = run_cmd(cmd, hide=True).stdout.strip()

                if tz_info_raw and " " in tz_info_raw:
                    tz_name, offset_str = tz_info_raw.split()
                    tz_string = f"{tz_name} {offset_str}"

                messages.append(f"[OK] {target_ip} successfully deployed (Manual Service Config).")
                messages = " ".join(messages)

                return (True, messages, tz_string, target_ip)

        except Exception as e:
            return (False, f"[ERROR] {target_ip} failed: {str(e)}", "", target_ip)

    def upgrade_task(self, s):
        try:

            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")
            p = int(s['port'])
            user = s['user'].strip()
            password = s['password'].strip()
            is_root = (user == "root")
            messages = []

            if is_root:
                # Key-based: Explicitly tell Fabric which files to use
                connect_params = {
                    "timeout": 10,
                    "banner_timeout": 20,
                    "key_filename": [key_path],
                    "look_for_keys": True,
                    "allow_agent": True
                }
                cfg = Config()

            else:
                # Password-based
                connect_params = {"password": password, "timeout": 10, "banner_timeout": 20}
                cfg = Config(overrides={'sudo': {'password': password}})

            try:
                # Automatically extract 'version' from the URL
                version_tag = CONDUIT_URL.split('/')[-2]
            except (NameError, IndexError):
                version_tag = "Unknown"
                                    
            with Connection(host=s['ip'], 
                            user=self.params['user'],
                            port=int(s['port']), 
                            connect_kwargs=connect_params,
                            config=cfg,
                            inline_ssh_env=True
            ) as conn:
                
                def run_cmd(cmd, **kwargs):

                    kwargs.setdefault('hide', False)
                    kwargs.setdefault('warn', False)

                    if is_root:
                        return conn.run(cmd, **kwargs)
                    else:    
                        return conn.sudo(cmd, **kwargs) 

                # Check if we are actually root or have access
                # This "id -u" check returns 0 for root
                res = run_cmd("id -u", hide=True, warn=True)
                if not res.ok:
                    return f"[SKIP] {s['ip']}: Could not connect or not root."
                                                         
                # --- NEW: VERSION CHECK LOGIC ---
                self.log_signal.emit(f"[{s['ip']}] Checking current version...")
                v_check = run_cmd(f"/opt/conduit{AppState.conduit_id}/conduit --version", hide=True, warn=True)
                
                if v_check.ok:
                    # Extract the hash from "conduit version e421eff"
                    current_version = v_check.stdout.strip().split()[-1]
                    
                    if current_version == version_tag:
                        return f"[SKIP] {s['ip']} is already running the latest version ({version_tag})."
                else:
                    return f"[ERROR] {s['ip']} failed to upgrad to conduit version {version_tag}."
                # --------------------------------

                # 2. Cleanup & Stop (Only runs if version is different or binary missing)
                self.log_signal.emit(f"[{s['ip']}] Upgrading {current_version} -> {version_tag}...")
                
                run_cmd(f"systemctl stop conduit{AppState.conduit_id}", warn=True, hide=True)
                time.sleep(2)
                run_cmd(f"rm -f /opt/conduit{AppState.conduit_id}/conduit", warn=True, hide=True)

                # 3. Download Binary
                run_cmd(f"curl -L -o /opt/conduit{AppState.conduit_id}/conduit {CONDUIT_URL}", hide=True)                
                run_cmd(f"chmod +x /opt/conduit{AppState.conduit_id}/conduit")

                # Official psiphon release uses the simplified command
                cmd_parts = [
                    f"/opt/conduit{AppState.conduit_id}/conduit start",
                    f"--max-clients {self.params['clients']}",
                    f"--bandwidth {self.params['bw']}",
                    f"--data-dir /var/lib/conduit{AppState.conduit_id}"
                ]

                if conduit_release != "psiphon":
                    # uses the extra config, geo, and stats flags
                    cmd_parts.append("--geo --stats-file stats.json")

                    if conduit_release == "byte_release":
                        # allows conduit to log bytes instead of KMGT
                        cmd_parts.append(f"--psiphon-config /opt/conduit{AppState.conduit_id}/psiphon_config.json")                
                
                    if AppState.use_lion_sun:
                        # allows only Shir o Khorshid android clients in "Conduit Mode" settings to be connected
                        cmd_parts.append("--compartment shirokhorshid")

                exec_cmd = " ".join(cmd_parts)

                if conduit_release == 'byte_release':
                    run_cmd(f"curl -L -o /opt/conduit{AppState.conduit_id}/psiphon_config.json {PSIPHON_CONFIG_URL}", hide=True)
#                cmd = f"/opt/conduit/conduit start --max-clients {self.params['clients']} --bandwidth {self.params['bw']} --psiphon-config /opt/conduit/psiphon_config.json --geo --stats-file stats.json --data-dir /var/lib/conduit"
                run_cmd(f"sed -i 's|^ExecStart=.*|ExecStart={exec_cmd}|' /etc/systemd/system/conduit{AppState.conduit_id}.service")
                run_cmd("systemctl daemon-reload")

                # 5. Start
                run_cmd(f"systemctl start conduit{AppState.conduit_id}", hide=True)                
                                              
                stats_script_url = "https://raw.githubusercontent.com/Starling226/conduit-manager/main/get_conduit_stat.py"
                run_cmd(f"curl -L -o /opt/conduit{AppState.conduit_id}/get_conduit_stat.py {stats_script_url}", hide=True)
                run_cmd(f"chmod +x /opt/conduit{AppState.conduit_id}/get_conduit_stat.py")
                    
                current_year = datetime.now().year
                filename = f"/opt/conduit{AppState.conduit_id}/{current_year}-conduit.log"
                backup_log = f"/opt/conduit{AppState.conduit_id}/{current_year}-conduit.log.bak"
                
                # Check if file exists (-f) then move (mv)
                result = run_cmd(f'test -f {filename}', warn=True, hide=True)
 
                if result.ok:
                    run_cmd(f'mv {filename} {backup_log}', hide=True)
                else:
                    print(f"Skipping backup: {filename} does not exist.")
                                                
                # Use a variable to avoid repeating the sed logic
                '''
                target_service = f"conduit{AppState.conduit_id}.service" if AppState.conduit_id else "conduit.service"
                new_service = f"conduit-monitor{AppState.conduit_id}.service" if AppState.conduit_id else "conduit-monitor.service"
                # Escape the dot for sed (e.g., conduit\.service)
                pattern_old = target_service.replace(".", r"\.")
                # The '|| true' ensures that if crontab is empty, we don't crash or wipe it
                full_cmd = f"(crontab -l 2>/dev/null || true) | sed 's/{pattern_old}/{new_service}/g' | crontab -"
                run_cmd(full_cmd)
                '''
                
                # Setup Cronjob (Idempotent: prevents duplicate entries)
                cron_cmd = f"5 * * * * /usr/bin/python3 /opt/conduit{AppState.conduit_id}/get_conduit_stat.py --work_dir /opt/conduit{AppState.conduit_id} --service conduit{AppState.conduit_id}.service >> /opt/conduit{AppState.conduit_id}/cron_sys.log 2>&1"
                # This command checks if the job exists; if not, it adds it to the crontab
                search_pattern = f"/opt/conduit{AppState.conduit_id}/get_conduit_stat.py --work_dir /opt/conduit{AppState.conduit_id} --service conduit{AppState.conduit_id}.service"
                run_cmd(f'(crontab -l 2>/dev/null | grep -v -w "{search_pattern}" ; echo "{cron_cmd}") | crontab -', hide=True)
                
                # Download conduit-monitor.sh Script from GitHub

                # This stops it, and if it takes more than 5 seconds, it kills it instantly.
                # Then it deletes the file.
                cmd = (
                    f"systemctl stop conduit-monitor{AppState.conduit_id} --timeout=5s; "
                    f"systemctl kill -s SIGKILL conduit-monitor{AppState.conduit_id} 2>/dev/null; "
                    f"rm -f /opt/conduit{AppState.conduit_id}/conduit-monitor.sh"
                )
                run_cmd(cmd, warn=True, hide=True)

                stats_script_url = "https://raw.githubusercontent.com/Starling226/conduit-manager/main/conduit-monitor.sh"
                run_cmd(f"curl -L -o /opt/conduit{AppState.conduit_id}/conduit-monitor.sh {stats_script_url}", hide=True)
                run_cmd(f"chmod +x /opt/conduit{AppState.conduit_id}/conduit-monitor.sh")

                # Reload and Start
                run_cmd(f"systemctl start conduit-monitor{AppState.conduit_id}", hide=True)
                time.sleep(2)
                
                status_res = run_cmd(f"systemctl is-active conduit-monitor{AppState.conduit_id}", hide=True, warn=True)
                current_status = status_res.stdout.strip() if status_res.ok else "inactive"

                if current_status == "inactive":
                    current_status = f"[*] {s['server']} ({s['ip']}): { current_status.upper()}"
                    print(f"conduit-monitor{AppState.conduit_id} service failed to start: {current_status}")
                    messages.append(f"conduit-monitor{AppState.conduit_id} service failed to start: {current_status}")
                else:
                    current_status = f"[*] {s['server']} ({s['ip']}): { current_status.upper()}"
                
                
                messages.append(f"[OK] {s['ip']} successfully upgraded to conduit version {version_tag}.")
                messages = " ".join(messages)
                return messages

        except Exception as e:
            return f"[ERROR] {s['ip']} failed: {str(e)}"

# --- 3. Main GUI Window ---
class ConduitGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Conduit Manager")
        self.setMinimumSize(1200, 800)
        self.server_data = [] 
        self.current_path = ""

        self.selected_timezone = {"region": "UTC", "offset": "+0000"}
        # Timer for Auto-Refresh
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.run_auto_stats)

        self.init_ui()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        json_server_path = os.path.join(script_dir, "servers.json")
        self.load_servers_from_json(json_server_path)

    def init_ui(self):
        
# Main Central Widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # --- 1. Menu Bar Setup ---
        menubar = self.menuBar()
        menubar.setNativeMenuBar(False) 
        
        file_menu = menubar.addMenu('&File')

        # Import Action
        import_action = QAction('Import servers file', self)
        import_action.triggered.connect(self.import_srv)
        file_menu.addAction(import_action)

        # Set Timezone Action
        tz_action = QAction('Set Timezone', self)
        tz_action.triggered.connect(self.select_timezone_dialog)
        file_menu.addAction(tz_action)

        file_menu.addSeparator()

        # Exit Action
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # --- 2. Moving Labels to Menu Bar ---
        # Create a container widget for the right side of the Menu Bar
        right_menu_widget = QWidget()
        right_menu_layout = QHBoxLayout(right_menu_widget)
        right_menu_layout.setContentsMargins(0, 0, 10, 0)
        right_menu_layout.setSpacing(20)

        # Shared Style for the Labels
        lbl_style = "color: gray; font-style: italic; font-size: 11px; border: none;"

        # Path Label (Left in menu area)
        self.lbl_path = QLabel("No file loaded")
        self.lbl_path.setStyleSheet(lbl_style)
        right_menu_layout.addWidget(self.lbl_path)

        # Timezone Label (Middle in menu area)
        self.lbl_timezone = QLabel("") 
        self.lbl_timezone.setStyleSheet(lbl_style)
        right_menu_layout.addWidget(self.lbl_timezone)

        # Version Info (Right in menu area)
        try:
            version_tag = CONDUIT_URL.split('/')[-2]
        except:
            version_tag = "Unknown"
        version_text = f"Manager: v{APP_VERSION} | Conduit: {version_tag}"
        
        self.lbl_version = QLabel(version_text)
        self.lbl_version.setStyleSheet(lbl_style)
        right_menu_layout.addWidget(self.lbl_version)

        # Set the container as the corner widget of the menubar
        menubar.setCornerWidget(right_menu_widget, Qt.TopRightCorner)
        self.setMenuBar(menubar)

        # --- 3. Initial Load of Config ---
        self.load_timezone_config()

        cfgs_frame = QFrame(); 
        cfgs_frame.setFrameShape(QFrame.StyledPanel)
#        cfgs_lay = QVBoxLayout(cfgs_frame)
        cfg_lay = QHBoxLayout(cfgs_frame)
#        cfg_lay = QHBoxLayout()
        cfg2_lay = QHBoxLayout()

    # Helper to apply consistent width for the 4 entries
        def set_fixed_entry(widget):
            widget.setFixedWidth(60)
            return widget

        cfg_lay.addWidget(QLabel("Max Clients:"));
#        self.edit_clients = QLineEdit("225")
        self.edit_clients = set_fixed_entry(QLineEdit("225"))
        cfg_lay.addWidget(self.edit_clients)

#        cfg_lay.addWidget(QLabel("Mbps:"));
        cfg_lay.addWidget(QLabel("Bandwidth (Mbps):"));
#        self.edit_bw = QLineEdit("40.0")
        self.edit_bw = set_fixed_entry(QLineEdit("40.0"))
        cfg_lay.addWidget(self.edit_bw)

        # Field 3: Log Window (The new free parameter - in minutes)
        cfg_lay.addWidget(QLabel("Log Win(min):")); 
        self.edit_window = set_fixed_entry(QLineEdit("60"))
        self.edit_window.setToolTip("Lookback window for logs (1-60 minutes). Used in Status Table")
        cfg_lay.addWidget(self.edit_window)


# --- REFRESH ENTRY & BUTTON ---
        cfg_lay.addSpacing(15)
        cfg_lay.addWidget(QLabel("Refresh (min):"))
        self.edit_refresh = set_fixed_entry(QLineEdit("5"))
        self.edit_refresh.setToolTip("Refresh interval. Used in Status Table")
#        self.edit_refresh = QLineEdit("5")
#        self.edit_refresh.setFixedWidth(35)
        self.btn_refresh_now = QPushButton("↻") 
        self.btn_refresh_now.setFixedWidth(30)
        self.btn_refresh_now.setToolTip("Refresh Live Monitor Now")
        cfg_lay.addWidget(self.edit_refresh)
        cfg_lay.addWidget(self.btn_refresh_now)
        self.edit_refresh.textChanged.connect(self.update_timer_interval)
        self.btn_refresh_now.clicked.connect(self.run_auto_stats)
        # ------------------------------

        cfg_lay.addSpacing(10)
        self.chk_upd = QCheckBox("Update Config")
        self.chk_upd.setToolTip("Checked and Click on Re-Start (if server is running) or Start to update the Max Clients and Bandwidth")
        cfg_lay.addWidget(self.chk_upd)
        self.chk_upd.setChecked(True)

        self.chk_lion_sun = QCheckBox("Sun && Lion")
        self.chk_lion_sun.setToolTip("When checked only the Shir O Khorshid Android Client app can connect to Conduit server")
        cfg_lay.addWidget(self.chk_lion_sun)
        self.chk_lion_sun.setChecked(False)

        self.chk_sec_inst = QCheckBox("Secondary")
        self.chk_sec_inst.setToolTip("When checked it manages the secondary running conduit instance")
        cfg_lay.addWidget(self.chk_sec_inst)
        self.chk_sec_inst.setChecked(False)

        self.rad_name = QRadioButton("Display Name")
        self.rad_ip = QRadioButton("Display IP")
        self.rad_name.setChecked(True)
        cfg_lay.addWidget(self.rad_name)
        cfg_lay.addWidget(self.rad_ip)
        cfg_lay.addStretch(1)

#        cfgs_lay.addLayout(cfg_lay)
#        cfgs_lay.addLayout(cfg2_lay)
        layout.addWidget(cfgs_frame)

        lists_lay = QHBoxLayout()
        self.pool = QListWidget(); self.sel = QListWidget()
        for l in [self.pool, self.sel]: l.setSelectionMode(QAbstractItemView.ExtendedSelection)
        
        # --- NEW LIVE MONITOR TABLE ---
        self.stats_table = QTableWidget(0, 4)
        self.stats_table.setHorizontalHeaderLabels(["IP Address", "Avg Clients (1h)", "Up (1h)", "Down (1h)"])
#        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        header = self.stats_table.horizontalHeader()
        header.setStretchLastSection(True)

        header.setSectionResizeMode(0, QHeaderView.Stretch) # IP takes remaining space
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        
        self.stats_table.setColumnWidth(1, 110)  # Reduced Avg Clients
        self.stats_table.setColumnWidth(2, 110) # Reduced Up
        self.stats_table.setColumnWidth(3, 110) # Reduced Down

        self.stats_table.setStyleSheet("background-color: #f8f9fa; gridline-color: #dee2e6;")
        self.stats_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.stats_table.setSelectionBehavior(QAbstractItemView.SelectRows)
#        self.stats_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # ------------------------------
        
        # --- LIVE MONITOR TABLE (Right Panel) ---
#        self.stats_table = QTableWidget(0, 4)
        # ... (rest of table setup, including sorting enabled) ...
        
# --- FOOTER FOR TOTALS & TIMESTAMP ---
        self.footer_frame = QFrame()
        self.footer_frame.setFixedHeight(35) # Slightly taller for better padding
        self.footer_frame.setStyleSheet("background-color: #f1f2f6; border-top: 1px solid #dcdcdc;")
        footer_lay = QHBoxLayout(self.footer_frame)
        footer_lay.setContentsMargins(15, 0, 15, 0)

        # New Timestamp Label (Left Side)
        self.lbl_last_updated = QLabel("Last Sync: Never")
        self.lbl_last_updated.setStyleSheet("color: #7f8c8d; font-style: italic; font-size: 11px;")
        footer_lay.addWidget(self.lbl_last_updated)

        footer_lay.addStretch(1) # Pushes the stats to the right

        # Metric Labels (Right Side)
        self.lbl_total_clients = QLabel("Clients: 0")
        self.lbl_total_up = QLabel("Up: 0 B")
        self.lbl_total_down = QLabel("Down: 0 B")
        
        for lbl in [self.lbl_total_clients, self.lbl_total_up, self.lbl_total_down]:
            lbl.setStyleSheet("font-weight: bold; color: #2c3e50;")
            lbl.setFixedWidth(130)
            footer_lay.addWidget(lbl)

        layout.addWidget(self.stats_table)
        layout.addWidget(self.footer_frame)

        mid_btns = QVBoxLayout()
        self.btn_add = QPushButton("Add Server (+)")
        self.btn_edit = QPushButton("Display/Edit")
        self.btn_to_sel = QPushButton("Add Selected >>")
        self.btn_to_pool = QPushButton("<< Remove Selected")
        self.btn_del = QPushButton("Delete Server")
        self.btn_del.setStyleSheet("color: red; font-weight: bold;")
                
        mid_btns.addWidget(self.btn_to_sel); mid_btns.addWidget(self.btn_to_pool); mid_btns.addSpacing(20)
        mid_btns.addWidget(self.btn_add); mid_btns.addWidget(self.btn_edit); mid_btns.addSpacing(20)        
        mid_btns.addWidget(self.btn_del)
        
        lists_lay.addWidget(self.pool,1); lists_lay.addLayout(mid_btns); lists_lay.addWidget(self.sel,1)
        lists_lay.addWidget(self.stats_table, 2) # Giving the table more space
        layout.addLayout(lists_lay)

        ctrl_lay = QHBoxLayout()
        self.btn_start = QPushButton("Start"); 
        self.btn_start.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")
        
        self.btn_re = QPushButton("Re-Start");        
        self.btn_re.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")
        self.btn_re.setToolTip("Use Restart if server is already running.")

        self.btn_reset = QPushButton("Reset")
        self.btn_reset.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")

        self.btn_stat = QPushButton("Status");
        self.btn_stat.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")

        self.btn_quit = QPushButton("Quit")
        self.btn_reset.setToolTip("Use if clients not added after hours or server waiting to connect.")        

        self.btn_stats = QPushButton("Statistics")
        self.btn_stats.setStyleSheet("background-color: #2980b9; color: white; font-weight: bold;")

        self.btn_report = QPushButton("Report")
        self.btn_report.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold;")
        self.btn_report.clicked.connect(self.open_report)
        cfg_lay.addWidget(self.btn_report)

        self.btn_health = QPushButton("Health")
        self.btn_health.setStyleSheet("background-color: #a3cb38; color: white; font-weight: bold;")
        self.btn_health.clicked.connect(self.open_system_health_dashboard)
        cfg_lay.addWidget(self.btn_health)

        self.btn_visualize = QPushButton("Traffic")
        self.btn_visualize.setStyleSheet("background-color: #8e44ad; color: white; font-weight: bold;")
        self.btn_visualize.clicked.connect(self.open_visualizer)
        cfg_lay.addWidget(self.btn_visualize)

        self.btn_deploy = QPushButton("Deploy")
        self.btn_deploy.setStyleSheet("background-color: #e67e22; color: white; font-weight: bold;")            

        self.btn_upgrade = QPushButton("Upgrade")
#        self.btn_upgrade.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold;")
#        self.btn_upgrade.setStyleSheet("background-color: #8e44ad; color: white; font-weight: bold;")

#        self.btn_upgrade.setStyleSheet("background-color: #2980b9; color: white; font-weight: bold;")
        self.btn_upgrade.setStyleSheet("background-color: #f1c40f; color: white; font-weight: bold;")
        self.btn_upgrade.setToolTip("Upgrade the conduit to the version displayed in GUI.")      

#        for b in [self.btn_start, self.btn_stop, self.btn_re, self.btn_reset, self.btn_stat, self.btn_upgrade, self.btn_stats, self.btn_deploy, self.btn_quit]:
        for b in [self.btn_start, self.btn_stop, self.btn_re, self.btn_reset, self.btn_stat, self.btn_upgrade, self.btn_stats, self.btn_deploy, self.btn_health, self.btn_visualize, self.btn_report]:            
            ctrl_lay.addWidget(b)
        layout.addLayout(ctrl_lay)


        self.console = QPlainTextEdit(); self.console.setReadOnly(True)
#        self.console.setStyleSheet("background: #1e1e1e; color: #00ff00; font-family: Consolas;")

        # 1. Set the Colors (Dark background, Green text)
        self.console.setStyleSheet("background-color: #1e1e1e; color: #00ff00;")
        
        # 2. Set the Font dynamically based on OS
        font = QFont()
        sys_name = platform.system()
        
        if sys_name == "Darwin":    # macOS
            font.setFamily("Menlo") # Standard Mac high-res mono font
            font.setPointSize(12)
        elif sys_name == "Windows": # Windows
            font.setFamily("Consolas")
            font.setPointSize(10)
        else:                       # Linux
            font.setFamily("Monospace")
            font.setPointSize(10)
            
        # This is the "Magic" line that forces perfect table alignment
        font.setStyleHint(QFont.Monospace)
        font.setFixedPitch(True)
        
        self.console.setFont(font)

        layout.addWidget(self.console)

        # Connection Slots
#        self.btn_import.clicked.connect(self.import_srv)
        self.btn_add.clicked.connect(self.add_srv)
        self.btn_edit.clicked.connect(self.edit_srv)
        self.btn_to_sel.clicked.connect(self.move_to_sel)
        self.btn_to_pool.clicked.connect(self.move_to_pool)
        self.btn_del.clicked.connect(self.delete_srv)
        self.btn_quit.clicked.connect(self.close)
        self.chk_lion_sun.clicked.connect(self.lion_sun_status)
        self.chk_sec_inst.clicked.connect(self.secondary_conduit_instance_status)
        
        
#        self.rad_name.toggled.connect(self.sync_ui)
#        self.rad_ip.toggled.connect(self.sync_ui)

        # Change this in init_ui
        self.rad_name.toggled.connect(lambda checked: self.sync_ui() if checked else None)
        self.rad_ip.toggled.connect(lambda checked: self.sync_ui() if checked else None)

#        self.btn_re.clicked.connect(lambda: QMessageBox.information(self, "Info", "Use Restart if server is already running."))

        self.btn_start.clicked.connect(lambda: self.confirm_action("start"))
        self.btn_stop.clicked.connect(lambda: self.confirm_action("stop"))
        self.btn_re.clicked.connect(lambda: self.confirm_action("restart"))
        self.btn_stat.clicked.connect(lambda: self.run_worker("status"))
        self.btn_reset.clicked.connect(self.confirm_reset)
        self.btn_stats.clicked.connect(self.run_stats)
        self.btn_deploy.clicked.connect(self.run_deploy)
        self.btn_upgrade.clicked.connect(self.run_upgrade)
        
        self.last_clicked_item = None
#        self.pool.setObjectName("PoolList")
#        self.sel.setObjectName("SelectionList")
        # Connect the selection change to our debug method
#        self.pool.itemClicked.connect(self.debug_selection)
#        self.sel.itemClicked.connect(self.debug_selection)

        self.pool.itemClicked.connect(self.handle_item_click)
        self.sel.itemClicked.connect(self.handle_item_click)

        self.pool.itemDoubleClicked.connect(self.edit_srv)
        self.sel.itemDoubleClicked.connect(self.edit_srv)

        self.update_timer_interval() # Initialize timer

    def get_timezone(self):
        current_os = platform.system()
        try:
            if current_os == "Windows":
                # 1. Get the Timezone Name (e.g., 'Iran Standard Time')
                # 2. Get the Offset using PowerShell (returns format like '+0330')
                name_cmd = "tzutil /g"
                offset_cmd = "powershell (Get-Date -Format 'zzzz').Replace(':', '')"
            
                tz_name = subprocess.check_output(name_cmd, shell=True, text=True).strip()
                offset_str = subprocess.check_output(offset_cmd, shell=True, text=True).strip()
            
            elif current_os == "Darwin":  # macOS
                # Use readlink to avoid sudo requirements on Mac
                cmd = "readlink /etc/localtime | sed 's/.*zoneinfo\///' && date +%z"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                parts = result.stdout.strip().split()
                tz_name, offset_str = parts[0], parts[1]
            
            else:  # Linux (Rocky/Debian/Ubuntu)
                cmd = "printf '%s %s' $(timedatectl show --property=Timezone --value) $(date +%z)"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
                tz_name, offset_str = result.stdout.strip().split()

            print(f"✅ Local System ({current_os}): {tz_name} ({offset_str})")
            return f"{tz_name} {offset_str}"

        except Exception as e:
            print(f"❌ Error getting time zone on {current_os}: {e}")
            return ""

    def load_timezone_config(self):
        """Reads timezone.conf and updates the UI Label & Dict"""
        if os.path.exists("timezone.conf"):
            try:
                with open("timezone.conf", "r") as f:
                    content = f.read().strip()
                    if " " in content:
                        region, offset = content.split(" ", 1)
                        self.selected_timezone = {"region": region, "offset": offset}
                        self.lbl_timezone.setText(f"🌍 {content}")
            except Exception as e:
                region, offset = self.get_timezone().split(" ",1)
                self.selected_timezone = {"region": region, "offset": offset}
                QMessageBox.warning(self, "Warning", f"Error reading timezone.conf: {e}")

    def select_timezone_dialog(self):
        """Generates list of IANA zones and shows a selection dialog"""
        # Generate list using the cross-platform zoneinfo method
        all_zones = []
        now = datetime.now(timezone.utc)
        
        for zone in sorted(zoneinfo.available_timezones()):
            if '/' in zone:
                offset = now.astimezone(zoneinfo.ZoneInfo(zone)).strftime('%z')
                all_zones.append(f"{zone} {offset}")

        # Show Selection Dialog
        choice, ok = QInputDialog.getItem(self, "Select Timezone", 
                                        "Available Regions:", all_zones, 0, False)
        
        if ok and choice:
            # Update File
            with open("timezone.conf", "w") as f:
                f.write(choice)
            
            # Update GUI and Class Dict
            region, offset = choice.split(" ", 1)
            self.selected_timezone = {"region": region, "offset": offset}
            self.lbl_timezone.setText(f"🌍 {choice}")
            print(f"Timezone preference saved: {choice}")

    def lion_sun_status(self):

        if self.chk_lion_sun.checkState() != 2:
            AppState.use_lion_sun = False
        else:
            AppState.use_lion_sun = True

    def secondary_conduit_instance_status(self):

        if self.chk_sec_inst.checkState() != 2:
            AppState.use_sec_inst = False
            AppState.conduit_id=""
        else:
            AppState.use_sec_inst = True
            AppState.conduit_id="2"

    def handle_item_click(self, item):
        """Updates tracker and ensures only one list has an active selection."""
        self.last_clicked_item = item
        
        # Determine which list was NOT clicked and clear it
        if item.listWidget() == self.pool:
            self.sel.clearSelection()
        else:
            self.pool.clearSelection()
            
#        print(f"DEBUG: Now tracking: {item.text()}")

    def handle_item_click2(self, item):
        """Updates the global tracker whenever any list item is clicked."""
        self.last_clicked_item = item
        # Optional: Print to verify it's tracking the right one
#        print(f"DEBUG: Last clicked is now: {item.text()}")

    '''
    def debug_selection(self):
        """Prints the details of the selected item to the console."""
        # Check both lists
        sender = self.sender() # Identifies which list was clicked
        it = sender.currentItem()
        
        if it:
            name_or_ip_text = it.text()
            hidden_ip = it.data(Qt.UserRole)
            
            # Find the actual dictionary in memory
            data = self.find_data_by_item(it)
            memory_name = data.get('server') if data else "NOT FOUND"
            
            print("--- SELECTION DEBUG ---")
            print(f"Widget: {sender.objectName()}")
            print(f"UI Text: {name_or_ip_text}")
            print(f"Hidden IP (UserRole): {hidden_ip}")
            print(f"Linked Memory Name: {memory_name}")
            print("-----------------------")

    '''

    def open_report(self):
        if not hasattr(self, 'rep_window'):
            self.report_window = VisualizerReportWindow(self.server_data, self.console, self.selected_timezone)
        self.report_window.show()
        self.report_window.raise_() # Bring to front

        # Trigger initial fetch for current day
#        self.viz_window.start_data_fetch()

    def open_system_health_dashboard(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        json_file = os.path.join(base_dir, 'servers.json')
        display_mode = 'server' if self.rad_name.isChecked() else 'ip'
        
        if not hasattr(self, 'health_window'):
            self.health_window = ConduitDashboard(self.console, display_mode, json_file)
        else:
            # Tell the existing window to switch modes
            self.health_window.set_display_mode(display_mode)
            
        self.health_window.show()
        self.health_window.raise_() # Bring to front

    '''
    def open_system_health_dashboard(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        json_file = os.path.join(base_dir, 'servers.json')

        display_mode = 'server' if self.rad_name.isChecked() else 'ip'
        
        if not hasattr(self, 'health_window'):
            self.health_window = ConduitDashboard(self.console, display_mode, json_file)
        self.health_window.show()
    '''

    def open_visualizer(self):
        if not hasattr(self, 'viz_window'):
            self.viz_window = VisualizerWindow(self.server_data, self.console, self.selected_timezone)
        self.viz_window.show()
        self.viz_window.raise_() # Bring to front
        # Trigger initial fetch for current day
#        self.viz_window.start_data_fetch()

    def parse_to_bytes(self, s):
        if not s or "0 B" in s or "-" in s: return 0.0
        match = re.search(r'([\d\.]+)', s)
        if not match: return 0.0
        num = float(match.group(1))
        u = s.upper()
        if 'TB' in u: return num * 1024**4
        if 'GB' in u: return num * 1024**3
        if 'MB' in u: return num * 1024**2
        if 'KB' in u: return num * 1024
        return num

    def format_bytes(self, b):
        if b == 0: return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if b < 1024: return f"{b:.2f} {unit}"
            b /= 1024
        return f"{b:.2f} PB"

    def update_stats_table(self, results):
        """Updates the table with dynamic Name/IP toggle support."""
        self.stats_table.setSortingEnabled(False)

        # 1. Update Header based on Radio Button
        display_header = "Server Name" if self.rad_name.isChecked() else "IP Address"
        win = self.edit_window.text()
        self.stats_table.setHorizontalHeaderLabels([
            display_header, "Avg Clients", f"Up ({win}m)", f"Down ({win}m)"
        ])
        
        self.stats_table.setRowCount(0)
        
        # Initial sort: Online first
        results.sort(key=lambda x: int(x['clients']) if x.get('success') and x['clients'].isdigit() else -1, reverse=True)
        
        COLOR_ONLINE = QColor("#27ae60")
        COLOR_OFFLINE = QColor("#c0392b")
        BG_OFFLINE = QColor("#fff5f5")
        COLOR_NO_DATA = QColor("#d68910")
        BG_NO_DATA = QColor("#fef9e7")
        
        total_clients = 0
        total_up_bytes = 0
        total_down_bytes = 0
        
        for r in results:
            row = self.stats_table.rowCount()
            self.stats_table.insertRow(row)
            
            is_ok = r.get("success", False)
            
            # Numeric values for math/sorting
            c_val = int(r["clients"]) if r["clients"].isdigit() else 0
            u_bytes = self.parse_to_bytes(r["up_val"])
            d_bytes = self.parse_to_bytes(r["down_val"])

            if is_ok:
                total_clients += c_val
                total_up_bytes += u_bytes
                total_down_bytes += d_bytes

            # Normalize IP and lookup server
            raw_ip = str(r["ip"]).strip()
            server_name = raw_ip
            for s in self.server_data:
                if str(s['ip']).strip() == raw_ip:
                    server_name = str(s['server']).strip()
                    break
            
            display_text = server_name if self.rad_name.isChecked() else raw_ip

            # 1. Column 0: IP/Name Item
            ip_item = QTableWidgetItem(display_text)
            ip_item.setData(Qt.UserRole, raw_ip) 

            # 2. Column 1: Client Item
            client_text = str(c_val) if is_ok else r["clients"]
            client_item = NumericTableWidgetItem(client_text, c_val)

            # 3. Column 2: Up Item
            up_item = NumericTableWidgetItem(r["up_val"], u_bytes)

            # 4. Column 3: Down Item
            down_item = NumericTableWidgetItem(r["down_val"], d_bytes)

            items = [ip_item, client_item, up_item, down_item]
            
            for col, item in enumerate(items):
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                
                # Apply Colors & Fonts
                if is_ok:
                    if col == 0:
                        item.setForeground(QBrush(COLOR_ONLINE))
                        f = item.font(); f.setBold(True); item.setFont(f)
                else:
                    if r["clients"] == "Stopped":
                        item.setForeground(QBrush(COLOR_OFFLINE))
                        item.setBackground(QBrush(BG_OFFLINE))
                    else:
                        item.setForeground(QBrush(COLOR_NO_DATA))
                        item.setBackground(QBrush(BG_NO_DATA))

                    if col > 0 and r["clients"] != "Stopped":
                        item.setText("-")
                        if hasattr(item, 'sort_value'):
                            item.sort_value = -1 
                
                if col != 0:
                    item.setTextAlignment(Qt.AlignCenter)
                
                # We only call setItem ONCE per column here
                self.stats_table.setItem(row, col, item)

        # Update Footer Labels
        self.lbl_total_clients.setText(f"Clients: {total_clients}")
        self.lbl_total_up.setText(f"Up: {self.format_bytes(total_up_bytes)}")
        self.lbl_total_down.setText(f"Down: {self.format_bytes(total_down_bytes)}")

        now = datetime.now().strftime("%H:%M:%S")
        self.lbl_last_updated.setText(f"Last Sync: {now}")

        self.stats_table.setSortingEnabled(True)
        
        # Final Step: Sync the rest of the UI (ListWidgets) to match
        self.sync_ui()

    def update_timer_interval(self):
        """Restarts the timer with the interval specified in the Refresh box."""
        try:
            val = self.edit_refresh.text().strip()
            if val:
                mins = float(val)
                if mins > 0:
                    # Restarts the countdown from 0
                    self.refresh_timer.start(int(mins * 60 * 1000))
        except ValueError:
            pass

    def run_auto_stats(self):
        """Forces an immediate refresh and resets the timer."""
        # Check if worker is already running to prevent overlapping
        if hasattr(self, 'auto_worker') and self.auto_worker.isRunning():
            return

        if not self.server_data:
            print("Debug: No server data found to refresh.")
            return

        # 1. Visual Feedback - This MUST happen first
        self.btn_refresh_now.setEnabled(False)
        self.btn_refresh_now.setText("...")
        
        # 2. Reset the timer interval
        self.update_timer_interval()

        # 3. Get parameters
        try:
            win_val = int(self.edit_window.text().strip())
            clamped = max(1, min(60, win_val))
            time_window_str = f"{clamped} minutes ago"
        except:
            time_window_str = "60 minutes ago"

        mode = 'server' if self.rad_name.isChecked() else 'ip'

        # 4. Initialize Worker
        # IMPORTANT: Assign to self.auto_worker so it isn't deleted by Python
        self.auto_worker = AutoStatsWorker(self.server_data, mode, time_window_str)
        
        # Connect signals
        self.auto_worker.stats_ready.connect(self.update_stats_table)
        self.auto_worker.finished.connect(self.on_worker_finished)
        
        # 5. Start
        print(f"Starting manual refresh for {len(self.server_data)} servers...")
        self.auto_worker.start()

    def on_worker_finished(self):
        """Restores the button state."""
        self.btn_refresh_now.setText("↻")
        self.btn_refresh_now.setEnabled(True)
        print("Debug: Refresh complete.")

    def get_validated_inputs(self):
        """Helper to validate and return clients and bandwidth."""
        raw_clients = self.edit_clients.text().strip()
        raw_bw = self.edit_bw.text().strip()

        # 1. Validate Clients (Integer 1-500)
        try:
            # Convert to float first in case user typed "200.5", then to int
            clients = int(float(raw_clients))
            if not (1 <= clients <= 500):
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", 
                                "Max Clients must be a whole number between 1 and 500.")
            return None

        # 2. Validate Bandwidth (Float 1-200)
        try:
            bw = float(raw_bw)
            if not (1.0 <= bw <= 200.0):
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", 
                                "Bandwidth must be a number between 1.0 and 200.0.")
            return None

        return {"clients": clients, "bw": bw}


    def run_deploy(self):
        # 1. Get targets

        selected_targets = self.get_target_servers(True)
        if not selected_targets:
            QMessageBox.warning(self, "Deployment", "No servers selected.")
            return

        validated = self.get_validated_inputs()
        if not validated: return 

        client_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
        valid_targets = []

        # THE WARNING GATE ---
        target_names = ", ".join([s.get('server', s['ip']) for s in selected_targets])

        port_22_detected = False
        for s in selected_targets:
            if int(s['port']) == 22:
                port_22_detected = True
                break

        port_message = f"Your current port is {int(s['port'])}"
        if port_22_detected:
            port_message = f"Your current port is 22. It is recommnded to choose a port\n in range 2000 to 3000 to avoid active ssh probing your server"

        warning_msg = (
            "⚠️ CRITICAL: FRESH DEPLOYMENT\n\n"
            f"You are about to deploy to: {target_names}\n\n"
            "This action will:\n"
            "• Connect as ROOT\n"
            "• OVERWRITE any existing conduit installation if this is a re-deployment\n"
            "• RESET all service configurations\n"
            f"• {port_message}\n\n"
            "Are you absolutely sure you want to proceed?"
        )

        # Show the dialog with 'No' as the default safe choice
        reply = QMessageBox.warning(
            self, 
            "Confirm System Reinstall", 
            warning_msg,
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            self.console.appendPlainText("[CANCELLED] Deployment aborted by user.")
            return

        # --- CASE: Single Selection ---

        if len(selected_targets) == 1:
            target = selected_targets[0]
            stored_user = target.get('user', '').strip().lower()
            stored_pwd = target.get('password', '').strip()
            target_ip = target.get('ip', '').strip()
#            stored_user,stored_pwd = self.get_root_pwd_from_file(target_ip)
                        
            # Check if we have a password AND it belongs to root
            has_root_creds = (stored_user == 'root' and stored_pwd)

            if not has_root_creds:
                # Explain why we are asking (either no pwd, or pwd is for a sub-user)
                reason = "No root password found" if not stored_pwd else f"Stored password is for user '{stored_user}', not 'root'"
                
                msg = QMessageBox(self)
                msg.setWindowTitle("Root Authentication Required")
                msg.setText(f"{reason} for {target['ip']}.\n\nHow do you want to proceed?")
                btn_pwd = msg.addButton("Enter Root Password", QMessageBox.ActionRole)
                btn_key = msg.addButton("Use Root SSH Key", QMessageBox.ActionRole)
                msg.addButton(QMessageBox.Cancel)
                
                msg.exec()
                
                if msg.clickedButton() == btn_pwd:
                    pwd_input, ok = QInputDialog.getText(self, "Root Password", "Enter Root Password:", QLineEdit.Password)
                    if ok and pwd_input:
                        target['password'] = pwd_input
                        # We force the worker to use 'root' regardless of what's in the file
                        valid_targets = [target]
                    else: return
                elif msg.clickedButton() == btn_key:
                    target['password'] = None 
                    valid_targets = [target]
                else:
                    return
            else:
                for s in selected_targets:
                    valid_targets.append(s)                
        else:
            for s in selected_targets:
                # If password exists, or if we want to try key-only servers
                # For bulk, we'll assume if no password exists, we attempt Key-only
                valid_targets.append(s)

        # 4. Final Verification

        if not valid_targets: return

        warning_msg = (
            "Is this the first time you deploy this system(s)?"
        )

        # Show the dialog with 'No' as the default safe choice
        reply = QMessageBox.warning(
            self, 
            "Port Verification", 
            warning_msg,
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            default_port = True
            AppState.use_sec_inst = False
            self.chk_sec_inst.setChecked(False)
        else:
            default_port = False

        params = {
            "user": "root",
            "default_port": default_port,
            "clients": validated['clients'], 
            "bw": validated['bw'],
            "update": self.chk_upd.isChecked()
        }

        # UI Feedback and Start Thread
        self.btn_deploy.setEnabled(False)
        self.btn_deploy.setText("Deploying...")
        
        self.deploy_thread = DeployWorker("deploy",valid_targets, params, client_ip)
        self.deploy_thread.log_signal.connect(lambda m: self.console.appendPlainText(m))
        self.deploy_thread.update_time_zone.connect(self.update_time_zone_json)
        self.deploy_thread.finished.connect(lambda: self.btn_deploy.setEnabled(True))
        self.deploy_thread.finished.connect(lambda: self.btn_deploy.setText("Deploy"))
        
        self.deploy_thread.start()

    def get_target_servers(self, warnin_flag):
        """
        Returns a list of server IPs based on input or table selection.
        """

        selected_targets = [self.find_data_by_item(self.sel.item(i)) for i in range(self.sel.count())]
    
        if selected_targets:
            # Split by comma or space and clean up
            return selected_targets

        # 2. If panel is empty, get highlighted rows from the table
        selected_ips = []
    
        # We use selectedIndexes to identify unique rows
        indexes = self.stats_table.selectionModel().selectedRows()
    
        selected_targets = []
        for index in indexes:
            row = index.row()            
            ip_item = self.stats_table.item(row, 0) 
            if ip_item:
                target_ip = ip_item.data(Qt.UserRole)
                for s in self.server_data:
                    if s['ip'] == target_ip:
                        selected_targets.append(s)

        if selected_targets and warnin_flag:
            QMessageBox.warning(self, "Information", "You have selected servers from Status Tables")

        return selected_targets

    def run_upgrade(self):
        # 1. Get targets

        selected_targets = self.get_target_servers(True)

        validated = self.get_validated_inputs()
        if not validated: return 

        valid_targets = []

        client_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()

        # THE WARNING GATE ---
        target_names = ", ".join([s.get('server', s['ip']) for s in selected_targets])
        
        warning_msg = (
            "⚠️ CRITICAL: UPGARDE CONDUIT\n\n"
            f"You are about to upgrade: {target_names}\n\n"
            "This action will:\n"
            "• Connect as ROOT\n"
            "• UPGARDE the existing conduit applicatinon\n"
            "Are you sure you want to proceed?"
        )

        # Show the dialog with 'No' as the default safe choice
        reply = QMessageBox.warning(
            self, 
            "Confirm System Upgrade", 
            warning_msg,
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )

        if reply != QMessageBox.Yes:
            self.console.appendPlainText("[CANCELLED] Upgrade aborted by user.")
            return

        # 4. Final Verification
        if not selected_targets: return

        params = {
            "user": "root",
            "clients": validated['clients'], 
            "bw": validated['bw'],
            "update": self.chk_upd.isChecked()        
        }

        # UI Feedback and Start Thread
        self.btn_upgrade.setEnabled(False)
        self.btn_upgrade.setText("Upgrading...")
        
        self.deploy_thread = DeployWorker("upgrade",selected_targets, params, client_ip)
        self.deploy_thread.log_signal.connect(lambda m: self.console.appendPlainText(m))
        self.deploy_thread.finished.connect(lambda: self.btn_upgrade.setEnabled(True))
        self.deploy_thread.finished.connect(lambda: self.btn_upgrade.setText("Upgrade"))
        
        self.deploy_thread.start()

    def run_stats(self):
        targets = self.get_target_servers(False)
        '''
        targets = [self.find_data_by_item(self.sel.item(i)) for i in range(self.sel.count())]
        if not targets: 
            QMessageBox.warning(self, "Stats", "Add servers to the right-side list first.")
            return
        '''    
        # Check which radio button is active
        mode = 'server' if self.rad_name.isChecked() else 'ip'
        
        self.console.appendPlainText(f"\n[>>>] Fetching Statistics (Display: {mode.upper()})...")
        self.stats_thread = StatsWorker(targets, mode)
        self.stats_thread.finished_signal.connect(lambda m: self.console.appendPlainText(m))
        self.stats_thread.start()

    def confirm_action(self, action):
        """Standard guard for Start, Stop, and Restart"""
#        count = self.sel.count()

        targets = self.get_target_servers(True)
        count = len(targets)
        if count == 0:
            QMessageBox.warning(self, "No Selection", "Please add servers to the 'Selected' list first.")
            return

        # Personalize the message based on the action
        action_title = action.capitalize()
        if action == "restart":
            msg = f"Are you sure you want to RESTART the Conduit service on {count} server(s)?"
            icon = QMessageBox.Question
        elif action == "stop":
            msg = f"WARNING: This will STOP the service on {count} server(s).\nContinue?"
            icon = QMessageBox.Warning
        else:
            msg = f"Start the Conduit service on {count} server(s)?"
            icon = QMessageBox.Information

        reply = QMessageBox.question(self, f"Confirm {action_title}", msg, 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.run_worker(action)

    def confirm_reset(self):
        """Safety check before performing a destructive reset"""
#        targets = [self.find_data_by_item(self.sel.item(i)) for i in range(self.sel.count())]
        
        targets = self.get_target_servers(True)
        if not targets:
            QMessageBox.warning(self, "Reset", "No servers selected in the right-side list.")
            return
        
        msg = f"WARNING: This will stop the service and DELETE ALL DATA in /var/lib/conduit{AppState.conduit_id}/ on {len(targets)} server(s).\n\nAre you absolutely sure?"
        reply = QMessageBox.critical(self, "Confirm Full Reset", msg, 
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.run_worker("reset")

    def create_item(self, server_dict):
        # Determine text based on current radio button mode
        text = server_dict['server'] if self.rad_name.isChecked() else server_dict['ip']
        item = QListWidgetItem(text)
        
        # This is what find_data_by_item looks for!
        item.setData(Qt.UserRole, server_dict['ip']) 
        return item

    def sync_ui(self):
        """Updates display text for all items using the hidden IP key."""
        is_name_mode = self.rad_name.isChecked()
        
        # Block sorting during update to prevent row-jumping
        self.stats_table.setSortingEnabled(False)
        
        # 1. Update the Header
        if self.stats_table.horizontalHeaderItem(0):
            self.stats_table.horizontalHeaderItem(0).setText("Server Name" if is_name_mode else "IP Address")

        # 2. Update Table Rows
        for row in range(self.stats_table.rowCount()):
            item = self.stats_table.item(row, 0)
            if not item:
                continue # Skip if item doesn't exist

            hidden_ip = item.data(Qt.UserRole)
            if not hidden_ip:
                continue

            # Determine correct text
            target_text = str(hidden_ip).strip()
            if is_name_mode:
                for s in self.server_data:
                    if str(s['ip']).strip() == target_text:
                        target_text = str(s['server']).strip()
                        break
            
            item.setText(target_text)

        self.stats_table.setSortingEnabled(True)

        # 3. Update ListWidgets
        attr = 'server' if is_name_mode else 'ip'
        for lw in [self.pool, self.sel]:
            for i in range(lw.count()):
                it = lw.item(i)
                ip_key = it.data(Qt.UserRole)
                for s in self.server_data:
                    if str(s['ip']).strip() == str(ip_key).strip():
                        it.setText(str(s[attr]).strip())
                        break
            lw.sortItems()

    def find_data_by_item(self, item):
        """Finds the dictionary in server_data matching the item's hidden IP."""
        if not item: 
            return None
            
        search_ip = str(item.data(Qt.UserRole)).strip()
        
        # DEBUG: Let's see what the UI thinks the IP is
        # print(f"Searching for IP: {search_ip}")

        for s in self.server_data:
            # We must ensure we are comparing strings to strings
            if str(s.get('ip', '')).strip() == search_ip:
                return s
        
        self.console.appendPlainText(f"[ERROR] No memory record found for IP: {search_ip}")
        return None

    def edit_srv(self):
        """Edits the server that was most recently clicked."""

        # 1. Count total selected items across both lists
        total_selected = len(self.pool.selectedItems()) + len(self.sel.selectedItems())

        if total_selected > 1:
            QMessageBox.warning(self, "Selection Error", 
                                f"You have {total_selected} servers selected.\n"
                                "Please select only one server to edit.")
            return

        # 2. Use the tracker we updated during handle_item_click
        it = self.last_clicked_item
        
        # 3. If nothing was clicked (e.g. app just started), then fallback
        if not it:
            it = self.pool.currentItem() or self.sel.currentItem()

        # 4. Get the actual data
        data = self.find_data_by_item(it)
        if not data:
            QMessageBox.information(self, "Edit", "Please select a server first.")
            return

#        print(f"EDITING: {data.get('server')} | IP: {data.get('ip')}")

        dlg = ServerDialog(self, data)
        if dlg.exec_() == QDialog.Accepted:
            new_info = dlg.get_data()
            
            # Update the UI item and memory list
            it.setData(Qt.UserRole, new_info['ip'])
            data.update(new_info)
            
            self.save()
            self.sync_ui() 
            self.console.appendPlainText(f"[*] Updated: {new_info['server']}")

    def remove_server_from_ui(self, ip_key):
        """Removes a server from all UI components by its IP key."""
        # 1. Remove from ListWidgets (pool and sel)
        for lw in [self.pool, self.sel]:
            for i in range(lw.count()):
                it = lw.item(i)
                if it and it.data(Qt.UserRole) == ip_key:
                    lw.takeItem(i)
                    break # Assuming one instance per ListWidget

        # 2. Remove from stats_table
        for row in range(self.stats_table.rowCount()):
            item = self.stats_table.item(row, 0)
            if item and item.data(Qt.UserRole) == ip_key:
                self.stats_table.removeRow(row)
                break

    def delete_srv(self):
        """Deletes selected servers using hidden IP key to ensure accuracy."""
        its = self.pool.selectedItems() + self.sel.selectedItems()
        if not its: return

        if QMessageBox.warning(self, "Delete", f"Delete {len(its)} server(s)?", 
                               QMessageBox.Yes|QMessageBox.No) == QMessageBox.Yes:

            # Create a list of IPs to delete first (to avoid index shifting issues)
            ips_to_delete = [it.data(Qt.UserRole) for it in its]

            for ip_key in ips_to_delete:
                # Remove from Memory
                self.server_data = [s for s in self.server_data if s['ip'] != ip_key]
                # Remove from all UI elements
                self.remove_server_from_ui(ip_key)
            
            self.save()
            self.sync_ui() # Refresh all labels
            self.console.appendPlainText(f"[-] Deleted {len(its)} server(s).")

    # --- Standard File/List Handlers ---

    def import_srv(self):
        # 1. Open dialog for both file types
        path, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "Supported Files (*.json *.txt);;JSON (*.json);;Text (*.txt)"
        )
    
        if not path:
            return

        # Determine paths
        base_dir = os.path.dirname(os.path.abspath(__file__))
        local_json = os.path.join(base_dir, 'servers.json')
    
        # 2. Preparation
        self.current_path = path
        self.server_data = []
        self.pool.clear()
        self.sel.clear()

        # 3. Branching Logic
        if path.lower().endswith('.json'):
            # If it's a JSON, just load it directly
            self.console.appendPlainText(f"[INFO] Loading JSON configuration: {os.path.basename(path)}")
            self.load_servers_from_json(path)
        
        else:
            # If it's a TXT, we check for overwrite because load_from_file likely saves to servers.json
            if os.path.exists(local_json):
                reply = QMessageBox.question(
                    self, 
                    'File Exists',
                    f"A local 'servers.json' already exists. Importing this text file will overwrite your existing server list. Proceed?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                    QMessageBox.StandardButton.No
                )

                if reply == QMessageBox.StandardButton.No:
                    self.console.appendPlainText("[CANCEL] Import aborted to protect existing servers.json.")
                    return

            self.console.appendPlainText(f"[INFO] Converting and importing Text: {os.path.basename(path)}")
            self.load_from_file(path)

    def move_to_sel(self):
        for it in self.pool.selectedItems():
            self.sel.addItem(self.create_item(self.find_data_by_item(it)))
            self.pool.takeItem(self.pool.row(it))
        self.sel.sortItems()

    def move_to_pool(self):
        for it in self.sel.selectedItems():
            self.pool.addItem(self.create_item(self.find_data_by_item(it)))
            self.sel.takeItem(self.sel.row(it))
        self.pool.sortItems()

    def is_valid_ip(self, ip_str):
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False

    def format_placeholder_cell(self, row, col):
        """Standardizes the look of empty/N/A cells."""
        placeholder = QTableWidgetItem("N/A")
        placeholder.setForeground(QColor("gray"))
        placeholder.setTextAlignment(Qt.AlignCenter)
        self.stats_table.setItem(row, col, placeholder)

    def add_srv(self):
        dlg = ServerDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            d = dlg.get_data()
            
            # Extract and trim values
            server = d.get('server', '').strip()
            ip = d.get('ip', '').strip()
            port = d.get('port', '').strip()
            timezone = d.get('timezone', '').strip()
            
            # 1. Validate Name
            if not server:
                QMessageBox.critical(self, "Invalid Name", "Server Name cannot be empty.")
                return
            
            # Check for commas as they would break your CSV servers.txt format
            if ',' in server:
                QMessageBox.critical(self, "Invalid Name", "Server Name cannot contain commas.")
                return

            # 2. Validate IP
            if not self.is_valid_ip(ip):
                QMessageBox.critical(self, "Invalid IP", f"'{ip}' is not a valid IP address.")
                return

            # 3. Validate Port
            try:
                port_num = int(port)
                if not (1 <= port_num <= 65535):
                    raise ValueError
            except ValueError:
                QMessageBox.critical(self, "Invalid Port", "Port must be a number between 1 and 65535.")
                return

            # If all checks pass:

            # 1. Update Memory
            self.server_data.append(d)

            # 2. Update ListWidgets
            new_list_item = self.create_item(d)
            # FORCE the UserRole here just in case create_item missed it
            new_list_item.setData(Qt.UserRole, d['ip']) 
            self.pool.addItem(new_list_item)                        
            
            # 3. Update Table
            row_position = self.stats_table.rowCount()
            self.stats_table.insertRow(row_position)

            # Create the item for the first column and set the IP as UserRole
            item = QTableWidgetItem(d['server'] if self.rad_name.isChecked() else d['ip'])
            item.setData(Qt.UserRole, d['ip'])
            self.stats_table.setItem(row_position, 0, item)

            for col in range(1, self.stats_table.columnCount()):
                self.format_placeholder_cell(row_position, col)

            # Sort the UI
            self.pool.sortItems()

            # Select the item we just added so "Edit" knows which one it is
            self.pool.setCurrentItem(new_list_item)

            self.sync_ui() # Refresh all labels

            self.save()
            self.console.appendPlainText(f"[OK] Added server: {server}")

    def save(self):
        # 1. Determine the path (default to servers.json)
        if not self.current_path or self.current_path.endswith('.txt'): 
            self.current_path = "servers.json"
        
        self.lbl_path.setText(f"File: {os.path.basename(self.current_path)}")

        # 2. Check for Duplicate IPs
        seen_ips = set()
        for s in self.server_data:
            ip = s.get('ip', '').strip()
            if ip in seen_ips:
                QMessageBox.warning(None, "Duplicate IP", f"The IP address {ip} is already in the list.")
                return
            seen_ips.add(ip)

        # 3. Save to JSON
        try:
            # We want to save the entire list of dictionaries
            # mapping 'pass' from your data to 'password' for the JSON format
            output_data = []
            for s in self.server_data:
                entry = {
                    "server": s.get('server', ''),
                    "ip": s.get('ip', ''),
                    "timezone": s.get('timezone', ''),
                    "port": int(s.get("port", 22)) if s.get("port") else 22,
                    "user": s.get('user', ''),
                    "password": s.get('password', '')  # Standardizing to 'password'
                }
                output_data.append(entry)

            with open(self.current_path, 'w') as f:
                json.dump(output_data, f, indent=4)
                
            self.console.appendPlainText(f"[OK] Changes saved to {self.current_path}")
        except Exception as e:
            self.console.appendPlainText(f"[ERROR] Save failed: {e}")

    def run_worker(self, action):
        """
        Pulling targets based on the hidden UserRole IP key.
        """
        '''
        targets = []
        for i in range(self.sel.count()):
            item = self.sel.item(i)
            server_dict = self.find_data_by_item(item)
            if server_dict:
                targets.append(server_dict)
        
        '''
        targets = self.get_target_servers(False)

        if not targets: 
            QMessageBox.warning(self, "Action", "No servers in the Selected list.")
            return

        # Console Debug: Verify we have the right IPs before launching
        self.console.appendPlainText(f"\nTarget IPs: {', '.join([t['ip'] for t in targets])}")
        
        conf = {
            "clients": self.edit_clients.text(), 
            "bw": self.edit_bw.text(), 
            "update": self.chk_upd.isChecked()
        }
        
        self.console.appendPlainText(f"[>>>] {action.upper()} on {len(targets)} servers...")
        self.worker = ServerWorker(action, targets, conf)
        self.worker.log_signal.connect(lambda m: self.console.appendPlainText(m))
        self.worker.start()

    def update_time_zone_json(self, tz_map):
        """
        tz_map: {'1.2.3.4': 'Asia/Tehran +0330', ...}
        Only saves to disk if at least one value is different from what's currently stored.
        """
        filename = "servers.json"
        if not os.path.exists(filename):
            return

        try:
            with open(filename, 'r', encoding='utf-8') as f:
                servers = json.load(f)

            file_needs_update = False
            updated_list = []

            for s in servers:
                ip = s.get("ip")
            
                # Check if this IP is in our new results
                if ip in tz_map:
                    new_tz = tz_map[ip]
                    current_tz = s.get("timezone", "")

                    # Only mark for update if the value is actually different
                    if new_tz != current_tz:
                        file_needs_update = True
                    
                        # Rebuild entry to ensure 'timezone' is placed after 'ip'
                        new_entry = {}

                        for k, v in s.items():
                            if k == "timezone":
                                continue

                            new_entry[k] = v

                            if k == "ip":
                                new_entry["timezone"] = new_tz
                        updated_list.append(new_entry)
                    else:
                        # No change for this specific server
                        updated_list.append(s)
                else:
                    # Server not in the deployment batch
                    updated_list.append(s)

            # Final check: Only write to disk if something changed
            if file_needs_update:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(updated_list, f, indent=4)
                
                self.console.appendPlainText(f"💾 servers.json updated (changes detected).")
            else:
                self.console.appendPlainText("ℹ️ No timezone changes detected; servers.json remains unchanged.")

        except Exception as e:
            self.console.appendPlainText(f"❌ Failed to process timezone update: {e}")

    def update_time_zone_json2(self, tz_map):
        """
        tz_map: {'1.2.3.4': 'Asia/Tehran +0330', ...}
        This is called via the signal after ALL threads finish.
        """
        filename = "servers.json"
        if not os.path.exists(filename):
            return

        try:
            with open(filename, 'r', encoding='utf-8') as f:
                servers = json.load(f)

            updated_list = []
            for s in servers:
                ip = s.get("ip")
                if ip in tz_map:
                    # Rebuild entry to put timezone after ip
                    new_entry = {}
                    for k, v in s.items():
                        new_entry[k] = v
                        if k == "ip":
                            new_entry["timezone"] = tz_map[ip]
                    updated_list.append(new_entry)
                else:
                    updated_list.append(s)

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(updated_list, f, indent=4)
        
            self.log_signal.emit(f"✅ Batch updated timezones for {len(tz_map)} servers in servers.json")

        except Exception as e:
            self.log_signal.emit(f"❌ Failed to batch update servers.json: {e}")

    def remove_password_from_file(self,target_ip):
        filename = "servers.txt"
        if not os.path.exists(filename):
            return

        updated_lines = []

        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue # Handle comments/empty lines
                    
                parts = [p.strip() for p in line.split(',')]

                # Basic requirement: server, ip, port, user
                if len(parts) >= 6:
                    # 1. IP Validation
                    if not self.is_valid_ip(parts[1].strip()):
                        continue

                    # 2. Port Validation
                    try:
                        port_num = int(parts[3].strip())
                        if not (1 <= port_num <= 65535):
                            raise ValueError
                    except ValueError:
                        continue

                if parts[1] == target_ip:
                    if parts[4] == "root":
                        # Reconstruct line without the password
                        # Format: server, ip, port, user, 
                        new_line = f"{parts[0].strip()}, {parts[1].strip()}, {parts[2].strip()}, {parts[3].strip()}, {parts[4].strip()}, "
                        updated_lines.append(new_line)
                    else:
                        updated_lines.append(line)

                else:
                    updated_lines.append(line)

        with open(filename, "w") as f:
            f.write("\n".join(updated_lines) + "\n")

    def get_root_pwd_from_file(self,target_ip):
        filename = "servers.txt"
        if not os.path.exists(filename):
            return "", ""

        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue # Handle comments/empty lines
                    
                parts = [p.strip() for p in line.split(',')]

                # Basic requirement: server, ip, port, user
                if len(parts) < 6: continue

                # 1. IP Validation
                if not self.is_valid_ip(parts[1].strip()):
                    continue

                # 2. Port Validation
                try:
                    port_num = int(parts[3].strip())
                    if not (1 <= port_num <= 65535):
                        raise ValueError
                except ValueError:
                    continue

                if parts[1] == target_ip:
                    if parts[4] == "root":
                        return parts[4].strip(),parts[5].strip()
                    else:
                        return "", ""

        return "", ""

    def load_from_file(self, path):

        try:
            self.server_data.clear()
            self.pool.clear()

            # Track IP → (line_number, server_name) for duplicate detection
            ip_seen = {}          # ip → first line number where it appeared
            ip_server_map = {}    # ip → first server server (for nicer warning)

            with open(path, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f, start=1):  # line numbers start at 1
                    line = line.strip()
                    if not line or line.startswith('#'):  # skip empty lines & comments
                        continue

                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) < 6:
                        self.console.appendPlainText(
                            f"[NOTICE] Line {i}: too few fields ({len(parts)}), skipped."
                        )
                        continue

                    server_name = parts[0].strip()
                    ip = parts[1].strip()
                    timezone = parts[2].strip()

                    # 1. IP Validation
                    if not self.is_valid_ip(ip):
                        self.console.appendPlainText(
                            f"[NOTICE] Line {i}: '{ip}' is not a valid IP address. Server '{server_name}' skipped."
                        )
                        continue

                    # 2. Port Validation
                    try:
                        port_num = int(parts[3].strip())
                        if not (1 <= port_num <= 65535):
                            raise ValueError
                    except ValueError:
                        self.console.appendPlainText(
                            f"[NOTICE] Line {i}: Invalid port '{parts[3]}' for '{server_name}'. Skipped."
                        )
                        continue

                    # 3. Duplicate IP check
                    if ip in ip_seen:
                        first_line = ip_seen[ip]
                        first_server = ip_server_map[ip]
                        self.console.appendPlainText(
                            f"[WARNING] Line {i}: Duplicate IP address '{ip}' "
                            f"(already used by '{first_server}' on line {first_line}). "
                            f"Server '{server_name}' skipped."
                        )
                        continue
                    else:
                        # Record first occurrence
                        ip_seen[ip] = i
                        ip_server_map[ip] = server_name

                    # 4. Create entry
                    d = {
                        'server': server_name,
                        'ip': ip,
                        'timezone': timezone,
                        'port': str(port_num),  # string – good for fabric/invoke
                        'user': parts[4].strip(),
                        'password': parts[5].strip() if len(parts) > 5 else ''                        
                    }

                    self.server_data.append(d)
                    self.pool.addItem(self.create_item(d))

            self.pool.sortItems()

            count = len(self.server_data)
            self.console.appendPlainText(f"[*] Successfully imported {len(self.server_data)} servers.")
#            self.console.appendPlainText(
#                f"[SUCCESS] {count} server{'s' if count != 1 else ''} imported."
#            )

            # Optional: still convert to JSON (now only contains valid + non-duplicate entries)
            self.convert_to_json(input_file=path)
            self.lbl_path.setText(os.path.basename('servers.json'))

        except FileNotFoundError:
            self.console.appendPlainText(f"[ERROR] File not found: {path}")
            QMessageBox.critical(self, "Import Error", f"[ERROR] File not found: {path}")
        except Exception as e:
            self.console.appendPlainText(f"[ERROR] Could not read file: {e}")
            QMessageBox.critical(self, "Import Error", f"[ERROR] Could not read file: {str(e)}")

    def load_servers_from_json(self, json_file='servers.json'):
        """Loads data and strictly prevents duplicate IPs from entering memory."""
        # 1. Reset everything
        self.server_data = []
        self.pool.clear()
        self.sel.clear()
        self.stats_table.setRowCount(0)
        
        # Track IPs we've already processed in this load session
        seen_ips = set()

        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for item in data:
                # 2. Extract and Normalize
                s_ip = item.get("ip", "").strip()
                if not s_ip:
                    continue

                # --- THE DUPLICATE FILTER ---
                if s_ip in seen_ips:
                    self.console.appendPlainText(f"[SKIP] Duplicate IP found in file: {s_ip}")
                    continue
                # ----------------------------

                s_name = item.get("server", item.get("server", "")).strip()
                s_pass = item.get("password", item.get("password", ""))
                s_port = str(item.get("port", "22"))
                s_user = item.get("user", "root")
                timezone = item.get("timezone", item.get("timezone", "")).strip()

                entry = {
                    "server": s_name,
                    "ip": s_ip,
                    "timezone": timezone,
                    "port": s_port,
                    "user": s_user,
                    "password": s_pass
                }

                # 3. Add to Memory and Seen Set
                self.server_data.append(entry)
                seen_ips.add(s_ip)

                # 4. Update UI Items
                # Pool List
                list_item = QListWidgetItem(s_name if self.rad_name.isChecked() else s_ip)
                list_item.setData(Qt.UserRole, s_ip)
                self.pool.addItem(list_item)

                # Table
                row = self.stats_table.rowCount()
                self.stats_table.insertRow(row)
                t_item = QTableWidgetItem(s_name if self.rad_name.isChecked() else s_ip)
                t_item.setData(Qt.UserRole, s_ip)
                self.stats_table.setItem(row, 0, t_item)
                
                for col in range(1, self.stats_table.columnCount()):
                    self.format_placeholder_cell(row, col)

            self.pool.sortItems()
            self.console.appendPlainText(f"[OK] {len(self.server_data)} unique servers loaded.")
            self.lbl_path.setText(os.path.basename('servers.json'))
            
        except Exception as e:
            self.console.appendPlainText(f"[ERROR] Load failed: {e}")

    def convert_to_json(self, input_file='servers.txt', output_file='servers.json'):
        """Converts comma-separated server data to a formatted JSON file."""

        servers_list = []

        try:
            with open(input_file, 'r') as f:
                for line in f:
                    data = line.strip().split(',')
                    if len(data) == 6:
                        server_entry = {
                            "server": data[0].strip(),
                            "ip": data[1].strip(),
                            "timezone": data[2].strip(),
                            "port": int(data[3].strip()),
                            "user": data[4].strip(),
                            "password": data[5].strip()
                        }
                        servers_list.append(server_entry)

            with open(output_file, 'w') as json_f:
                json.dump(servers_list, json_f, indent=4)
            
            self.console.appendPlainText(f"Successfully exported {len(servers_list)} servers.")
            return True
        except Exception as e:
            print(f"An error occurred: {e}")
            return False


class VisualizerWindow(QMainWindow):
    def __init__(self, server_list, console, selected_timezone):
        super().__init__()
        self.setWindowTitle("Conduit Network Traffic Analytics")
        self.resize(1400, 850)
        self.selected_timezone = selected_timezone
        self.server_list = copy.deepcopy(server_list)

        d = {
            "server": "---TOTAL---",
            "ip":   "---.---.---.---",
            "port": 22,
            "user": "",
            "password": ""
        }
        self.server_list.append(d)

        self.server_list = sorted(self.server_list, key=lambda x: x['ip'])
        self.console = console
        
        self.allow_network = False # Flag to block any automatic network activity
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        # Splitter allows user to resize the sidebar vs graph area
        splitter = QSplitter(Qt.Horizontal)
        self._is_initializing = True
        # --- LEFT PANEL: IP List ---
        self.ip_list = QListWidget()
        self.ip_list.setFixedWidth(180)
        # Populate IPs

        for s in self.server_list:
            item = QListWidgetItem(s['ip'])
            # Store the permanent IP in UserRole so we can always find it
            item.setData(Qt.UserRole, s['ip']) 
            self.ip_list.addItem(item)

        self.ip_list.setStyleSheet("""
            QListWidget {
                font-family: 'Consolas';
                font-size: 14px;
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #555;
            }
            QListWidget::item {
                height: 30px; /* Increases the row height */
                padding-left: 10px;
            }
            QListWidget::item:selected {
                background-color: #4a90e2;
            }
        """)

        # CHANGE: Use currentItemChanged for Click/Arrow Key navigation
#        self.ip_list.currentItemChanged.connect(self.handle_selection_change)

        splitter.addWidget(self.ip_list)
        
        # --- RIGHT PANEL: Canvas with 3 Plots ---
        self.canvas = pg.GraphicsLayoutWidget()
        self.canvas.setBackground('k') # Black background often looks sharper for data
        
        # Setup 3 Vertical Plots with Date Axes
        self.p_clients = self.canvas.addPlot(row=0, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        self.p_up = self.canvas.addPlot(row=1, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        self.p_down = self.canvas.addPlot(row=2, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        
        # Configure axes and titles
        plot_configs = [
            (self.p_clients, "Total Clients", "#00d2ff"),
            (self.p_up, "Upload Traffic (Bytes)", "#3aeb34"),
            (self.p_down, "Download Traffic (Bytes)", "#ff9f43")
        ]
        
        for plot, title, color in plot_configs:
            plot.setTitle(title, color=color, size="12pt")
            plot.showGrid(x=True, y=True, alpha=0.3)
            plot.getAxis('bottom').setLabel("Time (MM:DD HH:MM)")
            
        splitter.addWidget(self.canvas)
        main_layout.addWidget(splitter)
        
        # --- BOTTOM PANEL: Controls ---
        bottom_frame = QFrame()
        bottom_frame.setFixedHeight(50)
        bottom_lay = QHBoxLayout(bottom_frame)
        
        bottom_lay.addWidget(QLabel("Log Window (days):"))
        self.edit_days = QLineEdit("1")
        self.edit_days.setFixedWidth(60)
        bottom_lay.addWidget(self.edit_days)
        
       
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(300)
        self.progress_bar.setVisible(False)  # Hidden until "Reload" is clicked
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        bottom_lay.addWidget(self.progress_bar)
        

        self.btn_reload = QPushButton("Reload to retrieve the data")
        self.btn_reload.setFixedWidth(200)
        self.btn_reload.clicked.connect(self.start_data_fetch)
        bottom_lay.addWidget(self.btn_reload)
        
# --- PLOT MODE SELECTION (Radio Buttons) ---
#        mode_group_box = QGroupBox("Plot Mode")
#        mode_layout = QHBoxLayout()        

        Traffic_lb = QLabel("Traffic Mode ")
        Traffic_lb.setStyleSheet("font-weight: bold; color: #2c3e50;")
        bottom_lay.addWidget(Traffic_lb)

        self.radio_total = QRadioButton("Total")
        self.radio_instant = QRadioButton("Interval")
        self.radio_instant.setChecked(True) # Default to your current delta view
        
        # Group them to ensure mutual exclusivity
        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.radio_total)
        self.mode_group.addButton(self.radio_instant)
        
        bottom_lay.addWidget(self.radio_total)
        bottom_lay.addWidget(self.radio_instant)

        self.radio_total.setChecked(True)

#        mode_group_box.setLayout(mode_layout)
        
        # Add to your existing bottom_lay
#        bottom_lay.addWidget(mode_group_box)

        self.radio_total.clicked.connect(self.refresh_current_plot)

        self.radio_instant.clicked.connect(self.refresh_current_plot)

        Display_lb = QLabel("Display Mode ")
        Display_lb.setStyleSheet("font-weight: bold; color: #2c3e50;")
        bottom_lay.addWidget(Display_lb)

        self.rad_name = QRadioButton("Display Name")
        self.rad_ip = QRadioButton("Display IP")
        self.rad_ip.setChecked(True)
        bottom_lay.addWidget(self.rad_name)
        bottom_lay.addWidget(self.rad_ip)

        self.rad_name.toggled.connect(self.sync_disp_ui)
        self.rad_ip.toggled.connect(self.sync_disp_ui)

        self.status_label = QLabel("Last Sync: Never")
        # Use Consolas for that "Conduit Version" terminal look
        self.status_label.setFont(QFont("Consolas", 10, QFont.Bold))
        self.set_status_color("red")


        bottom_lay.addStretch()
        bottom_lay.addWidget(self.status_label)

        main_layout.addWidget(bottom_frame)
        self.p_up.setXLink(self.p_clients)
        self.p_down.setXLink(self.p_clients)

        self.data_cache = {} # The central memory store

        self.load_all_logs_into_memory()
        self.console.appendPlainText(f"Importing data finished.")        
        self.ip_list.currentItemChanged.connect(self.refresh_current_plot)
        self.check_local_data_on_startup()        
        self._is_initializing = False     

    def sync_disp_ui(self):
        """Updates display text for all items using the hidden IP key."""
        is_name_mode = self.rad_name.isChecked()
    
        # Choose which key to show: 'server' or 'ip'
        attr = 'server' if is_name_mode else 'ip'
    
        # We must block signals so the text change doesn't trigger 
        # 'refresh_current_plot' 40 times in a row.
        self.ip_list.blockSignals(True)
    
        # Correct way to iterate through a QListWidget
        for i in range(self.ip_list.count()):
            item = self.ip_list.item(i)
        
            # Get the hidden IP we stored in UserRole
            ip_key = item.data(Qt.UserRole)    

            # Look up the server in your server_list
            found = False
            for s in self.server_list:
                if str(s['ip']) == str(ip_key):
                    item.setText(str(s[attr]))
                    found = True
                    break
        
            if not found:
                print(f"Warning: Could not find server data for IP {ip_key}")

        self.ip_list.sortItems()
        self.ip_list.blockSignals(False)
    
        # Force the UI to repaint
        self.ip_list.update()

    def set_status_color(self, color_name):
        """Sets the status label color (red for old, dark gray/white for fresh)."""
        color_map = {
            "red": "#ff4d4d",
            "dark": "#888888" # Professional dark gray for updated state
        }
        hex_color = color_map.get(color_name, "#ffffff")
        self.status_label.setStyleSheet(f"color: {hex_color};")

    def get_last_log_time(self, ip):
        """Reads the very last line of a local log file to get the timestamp."""
        file_path = f"server_logs{AppState.conduit_id}/{ip}.log"
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, 'rb') as f:
                f.seek(-2, os.SEEK_END)
                while f.read(1) != b'\n':
                    f.seek(-2, os.SEEK_CUR)
                last_line = f.readline().decode()
                return last_line.split('\t')[0] # Returns "YYYY-MM-DD HH:MM:SS"
        except Exception:
            return None

    def check_local_data_on_startup(self):
        """Ensures the first server is actually rendered on window open."""
        if self.ip_list.count() > 0:
            # 1. Highlight the first item
            self.ip_list.setCurrentRow(0)
            
            # 2. Force the window to 'calculate' its layout and sizes
            # This prevents the "blank graph" issue
            QApplication.processEvents() 

            # 3. Get the first IP and its cached data
            ip = self.ip_list.item(0).text()
            if ip in self.data_cache:
                data = self.data_cache[ip]
                
                # 4. Explicitly call the plot based on radio state
                if self.radio_total.isChecked():
                    self.plot_cumulative(data, ip)
                else:
                    self.plot_instantaneous(data)
                
                # 6. Force the axes to find the data points
                self.p_clients.enableAutoRange()
                self.p_up.enableAutoRange()
                self.p_down.enableAutoRange()

                # 5. Update the Sync Label for the first time
                if data['epochs']:
                    last_ts = datetime.fromtimestamp(data['epochs'][-1]).strftime("%Y-%m-%d %H:%M:%S")
                    self.status_label.setText(f"Last Sync: {last_ts}")
                    self.set_status_color("red")            

    def start_data_fetch(self):
        """User manually clicked 'Reload'. NOW we start the SSH download."""
        self.allow_network = True  # Enable network mode
        self.set_status_color("dark") # Change color to dark as requested
        
        os.makedirs(f"server_logs{AppState.conduit_id}", exist_ok=True)
        days = self.edit_days.text()
        self.btn_reload.setEnabled(False)
#        self.progress_bar.setVisible(True)
#        self.progress_bar.setValue(0)
#        self.progress_bar.setFormat(f"Downloading")
        self.status_label.setText("Retrieving data started...")
        # This is where the actual 'Downloading' happens
        server_list = [s for s in self.server_list if s.get("ip") != "---.---.---.---"]
        self.worker = HistoryWorker(server_list, days)
        self.worker.progress.connect(self.update_progress_ui)
        self.worker.all_finished.connect(self.on_fetch_complete)
        self.worker.start()

    def update_progress_ui(self, value):
        """Updates the bar and the text format."""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(f"Downloading Logs: %p%")


    def parse_to_bytes(self, size_str):
        """Helper to convert '10.5 GB' to raw integer bytes."""
        units = {"B": 1, "KB": 1024, "MB": 1024*1024, "GB": 1024*1024*1024, "TB": 1024*1024*1024*1024}
        try:
            number, unit = size_str.split()
            return int(float(number) * units.get(unit.upper(), 1))
        except:
            return 0

    def parse_record(self, line):
        parts = line.strip().split(',')
        if len(parts) < 4:
            return None

        dt_raw = parts[0]
        numbers = []

        # Loop through the data parts (clients, up, down)
        for p in parts[1:]:
            # Only process if it looks like "key=value"
            if '=' in p:
                val_str = p.split('=')[1]
                if val_str.isdigit():
                    numbers.append(int(val_str))

        # Only return if we successfully found exactly 3 numbers
        if len(numbers) == 3:
            clients = numbers[0]
            up = numbers[1]
            down = numbers[2]
            return [dt_raw, clients, up, down]

        return None

    def process_to_utc(self, dt_str, offset_str):
        """
        dt_str: '2026-02-21 15:22:14' (from your journalctl log)
        offset_str: '+0330' (from your remote check)
        """

        try:
            # 1. Parse the offset (+/- HHMM)
            sign = 1 if offset_str[0] == '+' else -1
            hours = int(offset_str[1:3])
            minutes = int(offset_str[3:5])
        
            # 2. Create the Remote Timezone object
            remote_tz = timezone(timedelta(hours=sign * hours, minutes=sign * minutes))
        
            # 3. Parse the log date and attach the remote timezone
            local_dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=remote_tz)
        
            # 4. Convert to UTC
            utc_dt = local_dt.astimezone(timezone.utc)
        
            return utc_dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            print(f"⚠️ Error converting time: {e}")
            return dt_str # Return original if conversion fails   

    def process_raw_file(self, ip):
        """
        Takes the raw journalctl output and converts it to a clean tab-separated log.
        This runs on the local machine after all downloads are finished.
        """
        raw_path = f"server_logs{AppState.conduit_id}/{ip}.raw"
        log_path = f"server_logs{AppState.conduit_id}/{ip}.log"
    
        if not os.path.exists(raw_path):
            return

        offset_str = ""
        for s in self.server_list:
            if s.get("ip") == ip:
                region, offset_str = s.get("timezone").split()
                break

        valid_lines = 0
        try:
            with open(raw_path, "r") as r, open(log_path, "w") as f:
                for line in r:
                    # 1. Regex to extract: Date, Clients, UP, DOWN
                    if (res := self.parse_record(line)) is not None:
                        dt_raw, clients, up_bytes, down_bytes = res
                    
                        # 2. Format data
#                        dt = dt_raw.replace('T', ' ')
                        dt_obj = datetime.fromisoformat(dt_raw)
                        dt = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
                        if offset_str:
                            dt = self.process_to_utc(dt, offset_str)
                        # 3. Write standardized columns
                        f.write(f"{dt}\t{clients}\t{up_bytes}\t{down_bytes}\n")
                        valid_lines += 1
        
            # Optional: Remove the raw file to save space after processing
            os.remove(raw_path)
            print(f"✅ {ip}: Processed {valid_lines} lines.")
        
        except Exception as e:
            print(f"❌ Error processing raw data for {ip}: {e}")

    def on_fetch_complete(self):
        """Called when HistoryWorker (the network threads) finishes."""
        self.status_label.setText("Processing Raw Logs...")

        # 1. Convert all RAW files to clean LOG files
        for server in self.server_list:
            self.process_raw_file(server['ip'])

        # 2. Load the newly cleaned data into the Memory Cache
        self.status_label.setText("Importing data...")
        self.load_all_logs_into_memory()
        self.console.appendPlainText(f"Importing data finished.")
        # 3. Refresh the GUI
        self.progress_bar.setVisible(False)
        self.btn_reload.setEnabled(True)
        if self.ip_list.currentItem():
            self.handle_selection_change(self.ip_list.currentItem(), None)
    
        self.status_label.setText("Sync Complete")

    def handle_selection_change(self, current, previous):
        """Switching is now instantaneous because it uses self.data_cache."""
        if not current: return
        ip = current.text()
        
        # Check if the IP exists in our memory cache
        if ip in self.data_cache:
            data_obj = self.data_cache[ip] # This is the dictionary
            
            # 1. Update Timestamp Label
            if data_obj['epochs']:
                last_ts = datetime.fromtimestamp(data_obj['epochs'][-1]).strftime("%Y-%m-%d %H:%M:%S")
                self.status_label.setText(f"Last Sync: {last_ts}")
                
                # Logic for color: Red if idle, Dark if reloading
                if not self.progress_bar.isVisible():
                    self.set_status_color("red")
                else:
                    self.set_status_color("dark")

            # 2. PASS THE DICTIONARY, NOT THE IP STRING
            if self.radio_total.isChecked():
                self.plot_cumulative(data_obj, ip)   # Pass the object {}
            else:
                self.plot_instantaneous(data_obj) # Pass the object {}
        else:
            self.status_label.setText("Last Sync: No Data in Cache")

    def refresh_current_plot(self):
        """One function to rule them all. Call this whenever any UI setting changes."""
        current_item = self.ip_list.currentItem()
        if not current_item:
            return
            
#        ip = current_item.text()
        ip = current_item.data(Qt.UserRole)

        if ip in self.data_cache:
            data_obj = self.data_cache[ip]
            
            if self.radio_total.isChecked():
                self.plot_cumulative(data_obj, ip)
            else:
                self.plot_instantaneous(data_obj)

    def get_dynamic_scale(self, max_value):
        KB = 1024
        MB = 1024 ** 2
        GB = 1024 ** 3
        TB = 1024 ** 4

        if max_value < KB:
            return 1, "Bytes"
        elif max_value < MB:
            return KB, "KB"
        elif max_value < GB:
            return MB, "MB"
        elif max_value < TB:
            return GB, "GB"
        else:
            return TB, "TB"

    def plot_instantaneous(self, data):
        """Plots speed (deltas) using cached memory data."""

        # 1. Always clear first to ensure we don't overlay data
        self.p_clients.clear()
        self.p_up.clear()
        self.p_down.clear()

        epochs = data.get('epochs', [])
        
        # 2. Check for insufficient data
        if len(epochs) < 2:
            self.p_up.setTitle("Up (No Data)")
            self.p_down.setTitle("Down (No Data)")
            # Re-enable auto-range so it's ready for the next valid click
            for p in [self.p_clients, self.p_up, self.p_down]:
                p.enableAutoRange()
            return

        MB = 1024 * 1024
        unit = "MBps"
        diff_epochs = epochs[1:]
        diff_ups_mb = []
        diff_downs_mb = []

        for i in range(1, len(epochs)):
            time_delta = epochs[i] - epochs[i-1]
            up_delta = max(0, data['ups'][i] - data['ups'][i-1])
            down_delta = max(0, data['downs'][i] - data['downs'][i-1])
            
            # Speed = delta / time
            divisor = time_delta if time_delta > 0 else 1
            diff_ups_mb.append((up_delta / MB) / divisor)
            diff_downs_mb.append((down_delta / MB) / divisor)

        self.p_clients.plot(epochs, data['clients'], pen=pg.mkPen('#00d2ff', width=2), clear=True)
        self.p_up.plot(diff_epochs, diff_ups_mb, pen=pg.mkPen('#3aeb34', width=2), clear=True)
        self.p_down.plot(diff_epochs, diff_downs_mb, pen=pg.mkPen('#ff9f43', width=2), clear=True)
        
        self.p_up.setTitle(f"Up ({unit})")
        self.p_down.setTitle(f"Down ({unit})")

        # Rescale Y-axis for the new data
        for p in [self.p_clients, self.p_up, self.p_down]: p.enableAutoRange(axis='y')

    def plot_cumulative(self, data, ip):
        """Plots total usage using cached memory data with dynamic units."""
        # 1. Always clear first to ensure we don't overlay data
        self.p_clients.clear()
        self.p_up.clear()
        self.p_down.clear()

        epochs = data.get('epochs', [])
        
        # 2. Check for insufficient data
        if len(epochs) < 2:
            self.p_up.setTitle("Up (No Data)")
            self.p_down.setTitle("Down (No Data)")
            # Re-enable auto-range so it's ready for the next valid click
            for p in [self.p_clients, self.p_up, self.p_down]:
                p.enableAutoRange()
            return
        
        # 1. Determine the scale based on the highest value in either Up or Down
        max_up = data['ups'][-1] if data['ups'] else 0
        max_down = data['downs'][-1] if data['downs'] else 0
        max_val = max(max_up, max_down)

        # 2. Apply your specific rules
        KB = 1024
        MB = 1024 * 1024
        GB = 1024 * 1024 * 1024
        TB = 1024 * 1024 * 1024 * 1024

        if max_val >= KB and max_val < MB:
            divisor, unit = KB, "KBytes"
        elif max_val >= MB and max_val < GB:
            divisor, unit = MB, "MBytes"
        elif max_val >= GB and max_val < TB:
            divisor, unit = GB, "GBytes"
        elif max_val >= TB:
            divisor, unit = TB, "TBytes"
        else:
            divisor, unit = 1, "Bytes"

        # 3. Scale the data arrays
        scaled_ups = [x / divisor for x in data['ups']]
        scaled_downs = [x / divisor for x in data['downs']]

        # 4. Plot scaled data
        self.p_clients.plot(data['epochs'], data['clients'], pen=pg.mkPen('#00d2ff', width=2), clear=True)
        self.p_up.plot(data['epochs'], scaled_ups, pen=pg.mkPen('#3aeb34', width=2), clear=True)
        self.p_down.plot(data['epochs'], scaled_downs, pen=pg.mkPen('#ff9f43', width=2), clear=True)

        # 5. Update Titles/Labels to show the unit
        if ip != "---.---.---.---":
            self.p_clients.setTitle(f"Total Clients")
            self.p_up.setTitle(f"Total Up ({unit})")            
            self.p_down.setTitle(f"Total Down ({unit})")
        else:
            self.p_up.setTitle(f"Total Up - all servers ({unit})")
            self.p_down.setTitle(f"Total Down - all servers ({unit})")
            self.p_clients.setTitle(f"Total Clients - all servers")

        for p in [self.p_clients, self.p_up, self.p_down]: 
            p.enableAutoRange(axis='y')      

    def load_all_logs_into_memory(self):
        """Reads logs and creates a Global Total with reboot-resilient summing."""
        self.data_cache.clear()
        
        # Sort excluding the virtual IP for the file-reading phase
        actual_servers = [s for s in self.server_list if s['ip'] != "---.---.---.---"]
        
        all_epochs = []
        for server in actual_servers:
            ip = server['ip']
            file_path = f"server_logs{AppState.conduit_id}/{ip}.log"
            if os.path.exists(file_path):
                data = self.parse_log_file(file_path)
                self.data_cache[ip] = data
                print(ip,len(data['epochs']))
                if data['epochs']:
                    all_epochs.extend([data['epochs'][0], data['epochs'][-1]])

        if not all_epochs:
            return

        # --- GLOBAL SUMMING CALCULATION ---
        start_t = int(min(all_epochs))
        end_t = int(max(all_epochs))
        
        server_ips = list(self.data_cache.keys())
        cursors = {ip: 0 for ip in server_ips}
        up_offsets = {ip: 0 for ip in server_ips}
        down_offsets = {ip: 0 for ip in server_ips}
        
        total_epochs, total_clients, total_ups, total_downs = [], [], [], []

        for current_t in range(start_t, end_t + 1):
            s_clients, s_ups, s_downs = 0, 0, 0

            for ip in server_ips:
                data = self.data_cache[ip]
                idx = cursors[ip]
                
                # Counter Reset Check (Server Reboot Detection)
                if idx + 1 < len(data['epochs']) and data['epochs'][idx + 1] <= current_t:
                    if data['ups'][idx + 1] < data['ups'][idx]:
                        up_offsets[ip] += data['ups'][idx]
                    if data['downs'][idx + 1] < data['downs'][idx]:
                        down_offsets[ip] += data['downs'][idx]

                    while idx + 1 < len(data['epochs']) and data['epochs'][idx + 1] <= current_t:
                        idx += 1
                    cursors[ip] = idx
                
                s_clients += data['clients'][idx]
                s_ups     += (data['ups'][idx] + up_offsets[ip])
                s_downs   += (data['downs'][idx] + down_offsets[ip])

            total_epochs.append(float(current_t))
            total_clients.append(s_clients)
            total_ups.append(s_ups)
            total_downs.append(s_downs)

        # 2. Create 1-minute (60s) grid
        start_time = start_t
        end_time = end_t
        new_times = np.arange(start_time, end_time, 60)

        # Interpolate values across the new grid
        # np.interp is highly optimized for this

        resampled_clients = np.interp(new_times, total_epochs, total_clients).round().astype(int).tolist()
        resampled_ups = np.interp(new_times, total_epochs, total_ups).astype(int).tolist()
        resampled_downs = np.interp(new_times, total_epochs, total_downs).astype(int).tolist()
        new_times_list = new_times.tolist()

        # Assign calculated totals to the cache key used by the GUI
        # Slicing [1:] skips index 0 (the first element)
        self.data_cache["---.---.---.---"] = {
            'epochs': new_times_list[1:], 
            'clients': resampled_clients[1:],
            'ups': resampled_ups[1:], 
            'downs': resampled_downs[1:]
        }        

    def fix_reboot_counters(self, raw_rows):
        """
        Detects server reboots by checking if cumulative counters drop.
        Applies a running offset to make Ups and Downs strictly increasing.
        """
        if len(raw_rows) < 2:
            return raw_rows

        offset_up = 0
        offset_down = 0
        
        # We must track the RAW values from the previous line to detect the reset
        # row: [timestamp, clients, ups, downs]
        prev_raw_up = int(raw_rows[0][2])
        prev_raw_down = int(raw_rows[0][3])

        # Note: The first row remains as-is (no offset applied yet)
        for i in range(1, len(raw_rows)):
            current_raw_up = int(raw_rows[i][2])
            current_raw_down = int(raw_rows[i][3])

            # Detect Reboot: If current is less than previous, the counter reset.
            # We use 'down' as the primary indicator for reboot.
            if current_raw_down < prev_raw_down:
                offset_up += prev_raw_up
                offset_down += prev_raw_down
                # Optional: log the reboot event
                # print(f"Reboot detected at {raw_rows[i][0]}")

            # Apply the cumulative offsets to the current values
            corrected_up = current_raw_up + offset_up
            corrected_down = current_raw_down + offset_down

            # Update the prev_raw trackers BEFORE we overwrite the row data
            prev_raw_up = current_raw_up
            prev_raw_down = current_raw_down

            # Update the raw_rows list in-place
            raw_rows[i][2] = corrected_up
            raw_rows[i][3] = corrected_down

        return raw_rows

    def decimate_by_download(self, raw_rows):
        """
        Groups data by constant Download values. 
        Averages clients and upload during the stagnant period.
        """
        if not raw_rows:
            return []

        raw_rows = self.fix_reboot_counters(raw_rows)

        decimated = []
        
        # State trackers for the current "bucket"
        current_batch_clients = []
        current_batch_ups = []
        
        # Initialize with the first row
        # row: [timestamp_str, clients, ups, downs]
        first_ts = datetime.strptime(raw_rows[0][0], "%Y-%m-%d %H:%M:%S")
        anchor_down = int(raw_rows[0][3])
        
        current_batch_clients.append(int(raw_rows[0][1]))
        current_batch_ups.append(int(raw_rows[0][2]))
        
        last_ts = first_ts

        for i in range(1, len(raw_rows)):
            ts = datetime.strptime(raw_rows[i][0], "%Y-%m-%d %H:%M:%S")
            clients = int(raw_rows[i][1])
            ups = int(raw_rows[i][2])
            downs = int(raw_rows[i][3])

            if downs == anchor_down:
                # Still the same download value, keep accumulating for the average
                current_batch_clients.append(clients)
                current_batch_ups.append(ups)
                last_ts = ts
            else:
                # Download changed! Commit the averaged results for the previous window
                avg_clients = round(sum(current_batch_clients) / len(current_batch_clients))
                avg_ups = int(sum(current_batch_ups) / len(current_batch_ups))
                
                # We use the 'last_ts' to show the state just before the download incremented
                decimated.append((last_ts, avg_clients, avg_ups, anchor_down))
                
                # Reset for the new anchor
                anchor_down = downs
                current_batch_clients = [clients]
                current_batch_ups = [ups]
                last_ts = ts

        # Don't forget to add the final bucket
        if current_batch_clients:
            avg_clients = round(sum(current_batch_clients) / len(current_batch_clients))
            avg_ups = int(sum(current_batch_ups) / len(current_batch_ups))
            decimated.append((last_ts, avg_clients, avg_ups, anchor_down))

        # 1. Convert timestamps to unix floats
        # Assuming d[0] is a datetime object from your previous parsing step
        times = np.array([d[0].timestamp() for d in decimated])
        clients_arr = np.array([d[1] for d in decimated])
        ups_arr = np.array([d[2] for d in decimated])
        downs_arr = np.array([d[3] for d in decimated])

        # 2. Create 1-minute (60s) grid
        start_time = times[0]
        end_time = times[-1]
        new_times = np.arange(start_time, end_time, 60)

        # 3. Interpolate values across the new grid
        # np.interp is highly optimized for this
        resampled_clients = np.interp(new_times, times, clients_arr).round().astype(int)
        resampled_ups = np.interp(new_times, times, ups_arr).astype(int)
        resampled_downs = np.interp(new_times, times, downs_arr).astype(int)

        # 4. Reconstruct the list of tuples
        # FIXED: Returning datetime objects instead of strings to avoid .timestamp() error
        final_result = [
            (datetime.fromtimestamp(t), c, u, d)
            for t, c, u, d in zip(new_times, resampled_clients, resampled_ups, resampled_downs)
        ]

        print(f'Decimated: {len(decimated)} | Resampled: {len(final_result)}')
        return final_result

    def convert_utc_to_selected(self, dt_input, target_offset_str):
        """
        dt_input: Can be a '2026-02-21...' string OR a datetime object (from decimation)
        target_offset_str: '+0330'
        """
        try:
            # 1. Get a datetime object regardless of input type
            if isinstance(dt_input, str):
                utc_dt = datetime.strptime(dt_input, "%Y-%m-%d %H:%M:%S")
            else:
                utc_dt = dt_input  # It's already a datetime object
            
            # 2. Ensure it is marked as UTC
            utc_dt = utc_dt.replace(tzinfo=timezone.utc)

            # 3. Parse your selected offset (+/- HHMM)
            sign = 1 if target_offset_str[0] == '+' else -1
            hours = int(target_offset_str[1:3])
            minutes = int(target_offset_str[3:5])
        
            # 4. Create the target timezone object
            user_tz = timezone(timedelta(hours=sign * hours, minutes=sign * minutes))

            # 5. Convert UTC to the User's Timezone
            return utc_dt.astimezone(user_tz)
        
        except Exception as e:
            print(f"⚠️ Conversion error: {e}")
            return dt_input

    def convert_utc_to_selected2(self, utc_dt_str, target_offset_str):
        """
        utc_dt_str: '2026-02-21 08:24:36' (Stored UTC)
        target_offset_str: '+0330' (Your GUI preference)
        """
        try:
            # 1. Parse the stored string as a UTC-aware object
            utc_dt = datetime.strptime(utc_dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

            # 2. Parse your selected offset (+/- HHMM)
            sign = 1 if target_offset_str[0] == '+' else -1
            hours = int(target_offset_str[1:3])
            minutes = int(target_offset_str[3:5])
        
            # 3. Create the target timezone object
            user_tz = timezone(timedelta(hours=sign * hours, minutes=sign * minutes))

            # 4. Convert UTC to the User's Timezone
            return utc_dt.astimezone(user_tz)
        except Exception as e:
            print(f"⚠️ Conversion error: {e}")
            return datetime.strptime(utc_dt_str, "%Y-%m-%d %H:%M:%S")

    def parse_log_file(self, file_path):
        """Converts raw disk text into high-speed memory arrays with decimation."""
        raw_rows = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) == 4:
                        # parts: [timestamp_str, clients, ups, downs]
                        raw_rows.append(parts)
            
            # Apply decimation before converting to final dictionary
            clean_rows = self.decimate_by_download(raw_rows)
            
            # Convert decimated rows into the final cache format
            data = {'epochs': [], 'clients': [], 'ups': [], 'downs': []}        
            target_offset = self.selected_timezone.get("offset", "+0000")

            for row in clean_rows:
                # row is (datetime_obj, avg_clients, avg_ups, anchor_down)
                local_dt = self.convert_utc_to_selected(row[0],target_offset)
                data['epochs'].append(local_dt.timestamp())
                data['clients'].append(row[1])
                data['ups'].append(row[2])
                data['downs'].append(row[3])
                
            return data

        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return {'epochs': [], 'clients': [], 'ups': [], 'downs': []}

class VisualizerReportWindow(QMainWindow):
    def __init__(self, server_list, console, selected_timezone):
        super().__init__()
        self.setWindowTitle("Conduit Hourly Report Analytics")
        self.resize(1400, 850)
        self.server_list = copy.deepcopy(server_list)
        self.server_list = sorted(self.server_list, key=lambda x: x['ip'])
        self.console = console
        self.selected_timezone = selected_timezone
        
        d = {
            "server": "---TOTAL---",
            "ip":   "---.---.---.---",
            "port": 22,
            "user": "",
            "password": ""
        }
        self.server_list.append(d)

        self.allow_network = False # Flag to block any automatic network activity
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        # Splitter allows user to resize the sidebar vs graph area
        splitter = QSplitter(Qt.Horizontal)
        self._is_initializing = True
        # --- LEFT PANEL: IP List ---
        self.ip_list = QListWidget()
        self.ip_list.setFixedWidth(180)
        # Populate IPs
#        for s in self.server_list:
#            self.ip_list.addItem(s['ip'])
        
        for s in self.server_list:
            item = QListWidgetItem(s['ip'])
            # Store the permanent IP in UserRole so we can always find it
            item.setData(Qt.UserRole, s['ip']) 
            self.ip_list.addItem(item)

        self.ip_list.setStyleSheet("""
            QListWidget {
                font-family: 'Consolas';
                font-size: 14px;
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #555;
            }
            QListWidget::item {
                height: 30px; /* Increases the row height */
                padding-left: 10px;
            }
            QListWidget::item:selected {
                background-color: #4a90e2;
            }
        """)

        # CHANGE: Use currentItemChanged for Click/Arrow Key navigation
#        self.ip_list.currentItemChanged.connect(self.handle_selection_change)

        splitter.addWidget(self.ip_list)
        
        # --- RIGHT PANEL: Canvas with 3 Plots ---
        self.canvas = pg.GraphicsLayoutWidget()
        self.canvas.setBackground('k') # Black background often looks sharper for data
        
        # Setup 3 Vertical Plots with Date Axes
        self.p_clients = self.canvas.addPlot(row=0, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        self.p_up = self.canvas.addPlot(row=1, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        self.p_down = self.canvas.addPlot(row=2, col=0, axisItems={'bottom': DateAxisItem(orientation='bottom')})
        
        # Configure axes and titles
        plot_configs = [
            (self.p_clients, "Total Clients", "#00d2ff"),
            (self.p_up, "Upload Traffic (Bytes)", "#3aeb34"),
            (self.p_down, "Download Traffic (Bytes)", "#ff9f43")
        ]
        
        for plot, title, color in plot_configs:
            plot.setTitle(title, color=color, size="12pt")
            plot.showGrid(x=True, y=True, alpha=0.3)
            plot.getAxis('bottom').setLabel("Time (MM:DD HH:MM)")
            
        splitter.addWidget(self.canvas)
        main_layout.addWidget(splitter)
        
        # --- BOTTOM PANEL: Controls ---
        bottom_frame = QFrame()
        bottom_frame.setFixedHeight(50)
        bottom_lay = QHBoxLayout(bottom_frame)
                       
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(300)
        self.progress_bar.setVisible(False)  # Hidden until "Reload" is clicked
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        bottom_lay.addWidget(self.progress_bar)
        

        self.btn_reload = QPushButton("Reload to retrieve the data")
        self.btn_reload.setFixedWidth(200)
        self.btn_reload.clicked.connect(self.start_data_fetch)
        bottom_lay.addWidget(self.btn_reload)
        

#        self.radio_total.clicked.connect(self.refresh_current_plot)

#        self.radio_instant.clicked.connect(self.refresh_current_plot)

        self.lbl_total_clients = QLabel("Clients: 0")
        self.lbl_total_up = QLabel("Up: 0 B")
        self.lbl_total_down = QLabel("Down: 0 B")

        for lbl in [self.lbl_total_clients, self.lbl_total_up, self.lbl_total_down]:
            lbl.setStyleSheet("font-weight: bold; color: #2c3e50;")
            lbl.setFixedWidth(180)
            bottom_lay.addWidget(lbl)

        Traffic_lb = QLabel("Traffic Mode ")
        Traffic_lb.setStyleSheet("font-weight: bold; color: #2c3e50;")
        bottom_lay.addWidget(Traffic_lb)
        
        self.radio_total = QRadioButton("Total")
        self.radio_instant = QRadioButton("Interval")
        self.radio_instant.setChecked(True) # Default to your current delta view
        
        # Group them to ensure mutual exclusivity
        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.radio_total)
        self.mode_group.addButton(self.radio_instant)
        
        bottom_lay.addWidget(self.radio_total)
        bottom_lay.addWidget(self.radio_instant)

        self.radio_instant.setChecked(True)

        self.radio_total.clicked.connect(self.refresh_current_plot)

        self.radio_instant.clicked.connect(self.refresh_current_plot)  

        Display_lb = QLabel("Display Mode ")
        Display_lb.setStyleSheet("font-weight: bold; color: #2c3e50;")
        bottom_lay.addWidget(Display_lb)

        self.rad_name = QRadioButton("Display Name")
        self.rad_ip = QRadioButton("Display IP")
        self.rad_ip.setChecked(True)
        bottom_lay.addWidget(self.rad_name)
        bottom_lay.addWidget(self.rad_ip)

        self.rad_name.toggled.connect(self.sync_disp_ui)
        self.rad_ip.toggled.connect(self.sync_disp_ui)

        self.status_label = QLabel("Last Sync: Never")
        # Use Consolas for that "Conduit Version" terminal look
        self.status_label.setFont(QFont("Consolas", 10, QFont.Bold))
        self.set_status_color("red")


        bottom_lay.addStretch()
        bottom_lay.addWidget(self.status_label)

        main_layout.addWidget(bottom_frame)
        self.p_up.setXLink(self.p_clients)
        self.p_down.setXLink(self.p_clients)

        self.data_cache = {} # The central memory store

        self.load_all_logs_into_memory()
        self.console.appendPlainText(f"Importing data finished.")        
        self.ip_list.currentItemChanged.connect(self.refresh_current_plot)
        self.check_local_data_on_startup()        
        self._is_initializing = False     

    def set_status_color(self, color_name):
        """Sets the status label color (red for old, dark gray/white for fresh)."""
        color_map = {
            "red": "#ff4d4d",
            "dark": "#888888" # Professional dark gray for updated state
        }
        hex_color = color_map.get(color_name, "#ffffff")
        self.status_label.setStyleSheet(f"color: {hex_color};")

    def get_last_log_time(self, ip):
        """Reads the very last line of a local log file to get the timestamp."""
        file_path = f"server_report_logs{AppState.conduit_id}/{ip}.log"
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, 'rb') as f:
                f.seek(-2, os.SEEK_END)
                while f.read(1) != b'\n':
                    f.seek(-2, os.SEEK_CUR)
                last_line = f.readline().decode()
                return last_line.split('\t')[0] # Returns "YYYY-MM-DD HH:MM:SS"
        except Exception:
            return None

    def sync_disp_ui(self):
        """Updates display text for all items using the hidden IP key."""
        is_name_mode = self.rad_name.isChecked()
    
        # Choose which key to show: 'server' or 'ip'
        attr = 'server' if is_name_mode else 'ip'
    
        # We must block signals so the text change doesn't trigger 
        # 'refresh_current_plot' 40 times in a row.
        self.ip_list.blockSignals(True)
    
        # Correct way to iterate through a QListWidget
        for i in range(self.ip_list.count()):
            item = self.ip_list.item(i)
        
            # Get the hidden IP we stored in UserRole
            ip_key = item.data(Qt.UserRole)    

            # Look up the server in your server_list
            found = False
            for s in self.server_list:
                if str(s['ip']) == str(ip_key):
                    item.setText(str(s[attr]))
                    found = True
                    break
        
            if not found:
                print(f"Warning: Could not find server data for IP {ip_key}")

        self.ip_list.sortItems()
        self.ip_list.blockSignals(False)
    
        # Force the UI to repaint
        self.ip_list.update()

    def check_local_data_on_startup(self):
        """Ensures the first server is actually rendered on window open."""
        if self.ip_list.count() > 0:
            # 1. Highlight the first item
            self.ip_list.setCurrentRow(0)
            
            # 2. Force the window to 'calculate' its layout and sizes
            # This prevents the "blank graph" issue
            QApplication.processEvents() 

            # 3. Get the first IP and its cached data
            ip = self.ip_list.item(0).text()
            if ip in self.data_cache:
                data = self.data_cache[ip]
                
                # 4. Explicitly call the plot based on radio state

                self.plot_report_interval(data, ip)
                
                # 6. Force the axes to find the data points
                self.p_clients.enableAutoRange()
                self.p_up.enableAutoRange()
                self.p_down.enableAutoRange()

                # 5. Update the Sync Label for the first time
                if data['epochs']:
                    last_ts = datetime.fromtimestamp(data['epochs'][-1]).strftime("%Y-%m-%d %H:%M:%S")
                    self.status_label.setText(f"Last Sync: {last_ts}")
                    self.set_status_color("red")            

    def start_data_fetch(self):
        """User manually clicked 'Reload'. NOW we start the SSH download."""
        self.allow_network = True  # Enable network mode
        self.set_status_color("dark") # Change color to dark as requested
        
        self.btn_reload.setEnabled(False)
#        self.progress_bar.setVisible(True)
#        self.progress_bar.setValue(0)
#        self.progress_bar.setFormat(f"Downloading")
        self.status_label.setText("Retrieving data started...")
        # This is where the actual 'Downloading' happens

        server_list = [s for s in self.server_list if s.get("ip") != "---.---.---.---"]

        self.worker = ReportWorker(server_list)
        self.worker.progress.connect(self.update_progress_ui)
        self.worker.all_finished.connect(self.on_fetch_complete)
        self.worker.start()

    def update_progress_ui(self, value):
        """Updates the bar and the text format."""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(f"Downloading Logs: %p%")


    def parse_to_bytes(self, size_str):
        """Helper to convert '10.5 GB' to raw integer bytes."""
        units = {"B": 1, "KB": 1024, "MB": 1024*1024, "GB": 1024*1024*1024, "TB": 1024*1024*1024*1024}
        try:
            number, unit = size_str.split()
            return int(float(number) * units.get(unit.upper(), 1))
        except:
            return 0

    def process_to_utc(self, dt_str, offset_str):
        """
        dt_str: '2026-02-21 15:22:14' (from your journalctl log)
        offset_str: '+0330' (from your remote check)
        """

        try:
            # 1. Parse the offset (+/- HHMM)
            sign = 1 if offset_str[0] == '+' else -1
            hours = int(offset_str[1:3])
            minutes = int(offset_str[3:5])
        
            # 2. Create the Remote Timezone object
            remote_tz = timezone(timedelta(hours=sign * hours, minutes=sign * minutes))
        
            # 3. Parse the log date and attach the remote timezone
            local_dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=remote_tz)
        
            # 4. Convert to UTC
            utc_dt = local_dt.astimezone(timezone.utc)
        
            return utc_dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            print(f"⚠️ Error converting time: {e}")
            return dt_str # Return original if conversion fails  

    def process_raw_file(self, ip):
        """
        Takes the raw journalctl output and converts it to a clean tab-separated log.
        This runs on the local machine after all downloads are finished.
        """
        raw_path = f"server_report_logs{AppState.conduit_id}/{ip}.raw"
        log_path = f"server_report_logs{AppState.conduit_id}/{ip}.log"
    
        if not os.path.exists(raw_path):
            return

        offset_str = ""
        for s in self.server_list:
            if s.get("ip") == ip:
                region, offset_str = s.get("timezone").split()
                break

        # 1. Regex to extract: Date, Clients, UP, DOWN

        pattern = r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}),\s*(\d+),\s*(\d+),\s*(\d+)"
    
        valid_lines = 0
        try:
            with open(raw_path, "r") as r, open(log_path, "w") as f:
                for line in r:
                    match = re.search(pattern, line)
                    if match:
                        dt_raw, clients, up_str, down_str = match.groups()
                    
                        # 2. Format data
                        dt = dt_raw.replace('T', ' ')
                        if offset_str:
                            dt = self.process_to_utc(dt, offset_str)

#                        up_bytes = self.parse_to_bytes(up_str)
#                        down_bytes = self.parse_to_bytes(down_str)
                        up_bytes = int(up_str)
                        down_bytes = int(down_str)
                    
                        # 3. Write standardized columns
                        f.write(f"{dt}\t{clients}\t{up_bytes}\t{down_bytes}\n")
                        valid_lines += 1
        
            # Optional: Remove the raw file to save space after processing
            os.remove(raw_path)
            print(f"✅ {ip}: Processed {valid_lines} lines.")
        
        except Exception as e:
            print(f"❌ Error processing raw data for {ip}: {e}")

    def on_fetch_complete(self):
        """Called when ReportWorker (the network threads) finishes."""
        self.status_label.setText("Processing Raw Logs...")

        # 1. Convert all RAW files to clean LOG files
        for server in self.server_list:
            self.process_raw_file(server['ip'])

        # 2. Load the newly cleaned data into the Memory Cache
        self.status_label.setText("Importing data...")
        self.load_all_logs_into_memory()
        self.status_label.setText("Importing data finished")
        self.console.appendPlainText(f"Importing data finished.")
        # 3. Refresh the GUI
        self.progress_bar.setVisible(False)
        self.btn_reload.setEnabled(True)
        if self.ip_list.currentItem():
            self.handle_selection_change(self.ip_list.currentItem(), None)
    
        self.status_label.setText("Sync Complete")

    def handle_selection_change(self, current, previous):
        
        if not current: return
        ip = current.text()
        # Check if the IP exists in our memory cache
        if ip in self.data_cache:
            data_obj = self.data_cache[ip] # This is the dictionary
            
            # 1. Update Timestamp Label
            if data_obj['epochs']:
                last_ts = datetime.fromtimestamp(data_obj['epochs'][-1]).strftime("%Y-%m-%d %H:%M:%S")
                self.status_label.setText(f"Last Sync: {last_ts}")
                
                # Logic for color: Red if idle, Dark if reloading
                if not self.progress_bar.isVisible():
                    self.set_status_color("red")
                else:
                    self.set_status_color("dark")

            # 2. PASS THE DICTIONARY, NOT THE IP STRING

            if self.radio_total.isChecked():                        
                self.plot_report_cumulative(data_obj, ip)
            else:
                self.plot_report_interval(data_obj, ip)

        else:
            self.status_label.setText("Last Sync: No Data in Cache")

    def refresh_current_plot(self):
        """One function to rule them all. Call this whenever any UI setting changes."""
        current_item = self.ip_list.currentItem()
        if not current_item:
            return
            
#        ip = current_item.text()
        ip = current_item.data(Qt.UserRole)

        if ip in self.data_cache:
            data_obj = self.data_cache[ip]
            
            if self.radio_total.isChecked():                        
                self.plot_report_cumulative(data_obj, ip)
            else:
                self.plot_report_interval(data_obj, ip)

    def get_dynamic_scale(self, max_value):
        KB = 1024
        MB = 1024 ** 2
        GB = 1024 ** 3
        TB = 1024 ** 4

        if max_value < KB:
            return 1, "Bytes"
        elif max_value < MB:
            return KB, "KB"
        elif max_value < GB:
            return MB, "MB"
        elif max_value < TB:
            return GB, "GB"
        else:
            return TB, "TB"

    def get_scale_unit(self, max_val):
        KB = 1024
        MB = 1024 ** 2
        GB = 1024 ** 3
        TB = 1024 ** 4

        if max_val >= KB and max_val < MB:
            divisor, unit = KB, "KBytes"
        elif max_val >= MB and max_val < GB:
            divisor, unit = MB, "MBytes"
        elif max_val >= GB and max_val < TB:
            divisor, unit = GB, "GBytes"
        elif max_val >= TB:
            divisor, unit = TB, "TBytes"
        else:
            divisor, unit = 1, "Bytes"
        return divisor, unit

    def plot_report_interval(self, data, ip):
        """Plots total usage using cached memory data with dynamic units."""
        # 1. Always clear first to ensure we don't overlay data
        self.p_clients.clear()
        self.p_up.clear()
        self.p_down.clear()

        epochs = data.get('epochs', [])
        
        # 2. Check for insufficient data
        if len(epochs) < 2:
            self.p_up.setTitle("Up (No Data)")
            self.p_down.setTitle("Down (No Data)")
            # Re-enable auto-range so it's ready for the next valid click
            for p in [self.p_clients, self.p_up, self.p_down]:
                p.enableAutoRange()
            return
        
        # 1. Determine the scale based on the highest value in either Up or Down
        max_up = max(data['ups']) if data['ups'] else 0
        max_down = max(data['downs']) if data['downs'] else 0
        max_val = max(max_up, max_down)
        
        # 2. Apply your specific rules
        KB = 1024
        MB = 1024 * 1024
        GB = 1024 * 1024 * 1024
        TB = 1024 * 1024 * 1024 * 1024

        divisor, unit = self.get_scale_unit(max_val)

        max_clients = max(data['clients'])
        total_up_bytes = sum(data['ups'])
        total_down_bytes = sum(data['downs'])

        # 3. Scale the data arrays
        scaled_ups = [x / divisor for x in data['ups']]
        scaled_downs = [x / divisor for x in data['downs']]

        # 4. Plot scaled data
        self.p_clients.plot(data['epochs'], data['clients'], pen=pg.mkPen('#00d2ff', width=2), clear=True)
        self.p_up.plot(data['epochs'], scaled_ups, pen=pg.mkPen('#3aeb34', width=2), clear=True)
        self.p_down.plot(data['epochs'], scaled_downs, pen=pg.mkPen('#ff9f43', width=2), clear=True)

        # 5. Update Titles/Labels to show the unit
        if ip != "---.---.---.---":
            self.p_clients.setTitle(f"Total Clients")
            self.p_up.setTitle(f"Total Up ({unit})")            
            self.p_down.setTitle(f"Total Down ({unit})")
        else:
            self.p_up.setTitle(f"Total Up - all servers ({unit})")
            self.p_down.setTitle(f"Total Down - all servers ({unit})")
            self.p_clients.setTitle(f"Total Clients - all servers")

        for p in [self.p_clients, self.p_up, self.p_down]: 
            p.enableAutoRange(axis='y')      

        divisor_up, unit_up = self.get_scale_unit(total_up_bytes,)
        divisor_down, unit_down = self.get_scale_unit(total_down_bytes)

        self.lbl_total_clients.setText(f"Max Clients: {max_clients}")
        self.lbl_total_up.setText(f"Total Up: {total_up_bytes/divisor_up:.1f} {unit_up}")
        self.lbl_total_down.setText(f"Total Down: {total_down_bytes/divisor_down:.1f} {unit_down}") 

    def plot_report_cumulative(self, data, ip):
        """Plots total usage using cached memory data with dynamic units."""
        # 1. Always clear first to ensure we don't overlay data
        self.p_clients.clear()
        self.p_up.clear()
        self.p_down.clear()

        epochs = data.get('epochs', [])
        ups_array = np.array(data['ups'])
        down_array = np.array(data['downs'])
        ups_cumulative = np.cumsum(ups_array)
        down_cumulative = np.cumsum(down_array)

        # 2. Check for insufficient data
        if len(epochs) < 2:
            self.p_up.setTitle("Up (No Data)")
            self.p_down.setTitle("Down (No Data)")
            # Re-enable auto-range so it's ready for the next valid click
            for p in [self.p_clients, self.p_up, self.p_down]:
                p.enableAutoRange()
            return
        
        # 1. Determine the scale based on the highest value in either Up or Down
        max_up = max(0,ups_cumulative[-1])
        max_down = max(0,down_cumulative[-1])
        max_val = max(max_up, max_down)
        
        # 2. Apply your specific rules
        KB = 1024
        MB = 1024 * 1024
        GB = 1024 * 1024 * 1024
        TB = 1024 * 1024 * 1024 * 1024

        divisor, unit = self.get_scale_unit(max_val)

        max_clients = max(data['clients'])
        total_up_bytes = ups_cumulative[-1]
        total_down_bytes = down_cumulative[-1]

        # 3. Scale the data arrays

        scaled_ups = ups_cumulative / divisor
        scaled_downs = down_cumulative / divisor

        # 4. Plot scaled data
        self.p_clients.plot(data['epochs'], data['clients'], pen=pg.mkPen('#00d2ff', width=2), clear=True)
        self.p_up.plot(data['epochs'], scaled_ups, pen=pg.mkPen('#3aeb34', width=2), clear=True)
        self.p_down.plot(data['epochs'], scaled_downs, pen=pg.mkPen('#ff9f43', width=2), clear=True)

        # 5. Update Titles/Labels to show the unit
        if ip != "---.---.---.---":
            self.p_clients.setTitle(f"Total Clients")
            self.p_up.setTitle(f"Total Up ({unit})")            
            self.p_down.setTitle(f"Total Down ({unit})")
        else:
            self.p_up.setTitle(f"Total Up - all servers ({unit})")
            self.p_down.setTitle(f"Total Down - all servers ({unit})")
            self.p_clients.setTitle(f"Total Clients - all servers")

        for p in [self.p_clients, self.p_up, self.p_down]: 
            p.enableAutoRange(axis='y')      

        divisor_up, unit_up = self.get_scale_unit(total_up_bytes,)
        divisor_down, unit_down = self.get_scale_unit(total_down_bytes)

        self.lbl_total_clients.setText(f"Max Clients: {max_clients}")
        self.lbl_total_up.setText(f"Total Up: {total_up_bytes/divisor_up:.1f} {unit_up}")
        self.lbl_total_down.setText(f"Total Down: {total_down_bytes/divisor_down:.1f} {unit_down}") 

    def load_all_logs_into_memory(self):

        """Reads logs and creates a Global Total with reboot-resilient summing."""

        self.data_cache.clear()
        # Sort excluding the virtual IP for the file-reading phase
        actual_servers = [s for s in self.server_list if s['ip'] != "---.---.---.---"]        
        
        all_epochs = []
        for server in actual_servers:
            ip = server['ip']
            file_path = f"server_report_logs{AppState.conduit_id}/{ip}.log"
            if os.path.exists(file_path):
                print(f"Reading: {ip}")
                data = self.parse_log_file(file_path)
                self.data_cache[ip] = data
                if data['epochs']:
                    all_epochs.extend([data['epochs'][0], data['epochs'][-1]])
#        return

        if not all_epochs:
            return

        # --- SETUP FOR GLOBAL SUMMING ---
        start_t = int(min(all_epochs))
        end_t = int(max(all_epochs))
        
        server_ips = list(self.data_cache.keys())
        cursors = {ip: 0 for ip in server_ips}
        
        # Track offsets specifically for the Global Total calculation
        # This prevents 'reboot drops' from affecting the 255.255.255.255 data.
        up_offsets = {ip: 0 for ip in server_ips}
        down_offsets = {ip: 0 for ip in server_ips}
        
        total_epochs, total_clients, total_ups, total_downs = [], [], [], []

        # 3. Resample: Iterate every second
        for current_t in range(start_t, end_t + 1, 3600):
            s_clients = 0
            s_ups = 0
            s_downs = 0

            for ip in server_ips:
                data = self.data_cache[ip]
                if not data['clients']:
                    continue

                idx = cursors[ip]
                
                # Check for counter reset BEFORE moving to the next point. This happen when a server restart.
                if idx + 1 < len(data['epochs']) and data['epochs'][idx + 1] <= current_t:
                    # Look ahead: if next value is lower than current, it's a reboot
                    #if data['ups'][idx + 1] < data['ups'][idx]:
#                    up_offsets[ip] += data['ups'][idx]
                    #    print(f"📈 [Totalizer] Up-Reset detected on {ip} at {current_t}")
                    
                    #if data['downs'][idx + 1] < data['downs'][idx]:
#                    down_offsets[ip] += data['downs'][idx]
                    #    print(f"📈 [Totalizer] Down-Reset detected on {ip} at {current_t}")


                    # Now safely move the cursor forward
                    while idx + 1 < len(data['epochs']) and data['epochs'][idx + 1] <= current_t:
                        idx += 1
                    cursors[ip] = idx
                
                # Sum the value + any accumulated offsets for this server

                s_clients += data['clients'][idx]
                # s_ups     += (data['ups'][idx] + up_offsets[ip])
                s_ups     += data['ups'][idx]
                # s_downs   += (data['downs'][idx] + down_offsets[ip])
                s_downs   += data['downs'][idx]

            total_epochs.append(float(current_t))
            total_clients.append(s_clients)
            total_ups.append(s_ups)
            total_downs.append(s_downs)

        
        # 2. Create 1-minute (3600s) grid
        start_time = start_t
        end_time = end_t
        new_times = np.arange(start_time, end_time, 3600)

        # Interpolate values across the new grid
        # np.interp is highly optimized for this

        resampled_clients = np.interp(new_times, total_epochs, total_clients).round().astype(int).tolist()
        resampled_ups = np.interp(new_times, total_epochs, total_ups).astype(int).tolist()
        resampled_downs = np.interp(new_times, total_epochs, total_downs).astype(int).tolist()
        new_times_list = new_times.tolist()

        # Assign calculated totals to the cache key used by the GUI
        self.data_cache["---.---.---.---"] = {
            'epochs': new_times_list, 
            'clients': resampled_clients,
            'ups': resampled_ups, 
            'downs': resampled_downs
        }                

    def convert_utc_to_selected(self, dt_input, target_offset_str):
        """
        dt_input: Can be a '2026-02-21...' string OR a datetime object (from decimation)
        target_offset_str: '+0330'
        """
        try:
            # 1. Get a datetime object regardless of input type
            if isinstance(dt_input, str):
                utc_dt = datetime.strptime(dt_input, "%Y-%m-%d %H:%M:%S")
            else:
                utc_dt = dt_input  # It's already a datetime object
            
            # 2. Ensure it is marked as UTC
            utc_dt = utc_dt.replace(tzinfo=timezone.utc)

            # 3. Parse your selected offset (+/- HHMM)
            sign = 1 if target_offset_str[0] == '+' else -1
            hours = int(target_offset_str[1:3])
            minutes = int(target_offset_str[3:5])
        
            # 4. Create the target timezone object
            user_tz = timezone(timedelta(hours=sign * hours, minutes=sign * minutes))

            # 5. Convert UTC to the User's Timezone
            return utc_dt.astimezone(user_tz)
        
        except Exception as e:
            print(f"⚠️ Conversion error: {e}")
            return dt_input

    def parse_log_file(self, file_path):
        """Converts raw disk text into high-speed memory arrays with decimation."""
        raw_rows = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) == 4:
                        # parts: [timestamp_str, clients, ups, downs]
                        raw_rows.append(parts)                            
            
            # Convert decimated rows into the final cache format
            data = {'epochs': [], 'clients': [], 'ups': [], 'downs': []}
            target_offset = self.selected_timezone.get("offset", "+0000")

            for row in raw_rows:
                # row is (datetime_obj, avg_clients, avg_ups, anchor_down)
                # Convert UTC string -> Localized Datetime Object
#                last_ts = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
                local_dt = self.convert_utc_to_selected(str(row[0]), target_offset)                
                data['epochs'].append(local_dt.timestamp())
                data['clients'].append(int(row[1]))
                data['ups'].append(int(row[2]))
                data['downs'].append(int(row[3]))
                
            return data

        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return {'epochs': [], 'clients': [], 'ups': [], 'downs': []}

class RepairWorker(QThread):
    finished = pyqtSignal(str, bool)

    def __init__(self, name, entry):
        super().__init__()
        self.name = name
        self.entry = entry

    def run(self):
        try:
            local_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
            ip, user = self.entry['ip'], self.entry['user']
            port = self.entry.get('port', 22)
            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")

            conn = Connection(host=ip, user=user, port=port,
                              connect_kwargs={"key_filename": key_path, "timeout": 7})

            # --- STEP 1: FIREWALL CHECK ---
            check_cmd = f"firewall-cmd --list-rich-rules | grep '{local_ip}' | grep '61208'"
            firewall_ok = conn.sudo(check_cmd, hide=True, warn=True).ok

            if not firewall_ok:
                print(f"[{self.name}] IP change/missing detected. Updating firewall...")
                # Clean old rules
                rules = conn.sudo("firewall-cmd --list-rich-rules", hide=True).stdout
                for line in rules.splitlines():
                    if 'port="61208"' in line:
                        conn.sudo(f"firewall-cmd --permanent --remove-rich-rule='{line.strip()}'", hide=True)
                
                # Add new rule
                new_rule = f'rule family="ipv4" source address="{local_ip}" port protocol="tcp" port="61208" accept'
                conn.sudo(f"firewall-cmd --permanent --add-rich-rule='{new_rule}'", hide=True)
                conn.sudo("firewall-cmd --reload", hide=True)

            # --- STEP 2: SERVICE HEALTH CHECK (Put it here!) ---
            # Check if port is listening
            port_active = conn.sudo("ss -tulpn | grep :61208", warn=True, hide=True).ok
            
            if port_active:
                # Port is open, but is it "frozen"? Check API response locally
                api_responsive = conn.run("curl -s -m 2 http://127.0.0.1:61208/api/3/version", warn=True, hide=True).ok
                if not api_responsive:
                    print(f"[{self.name}] Service DEADLOCK detected. Restarting...")
                    conn.sudo("systemctl restart glancesweb", hide=True)
                else:
                    print(f"[{self.name}] Service is healthy.")
            else:
                print(f"[{self.name}] Service is DOWN. Starting...")
                conn.sudo("systemctl start glancesweb", hide=True)

            conn.close()
            self.finished.emit(self.name, True)
            
        except Exception as e:
            print(f"Repair Error on {self.name}: {e}")
            self.finished.emit(self.name, False)

    def run2(self):
        try:
            # 1. Get current local public IP
            local_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
            
            ip, user = self.entry['ip'], self.entry['user']
            port = self.entry.get('port', 22)
            home = os.path.expanduser("~")
            key_path = os.path.join(home, ".ssh", "id_conduit")

            conn = Connection(host=ip, user=user, port=port,
                              connect_kwargs={"key_filename": key_path, "timeout": 7})
            
            # 2. Check if the current local_ip is already allowed for this port
            # We search specifically for the rule containing both our IP and the port
            check_cmd = f"firewall-cmd --list-rich-rules | grep '{local_ip}' | grep '61208'"
            result = conn.sudo(check_cmd, hide=True, warn=True)

            if result.ok:
                # Our IP is already correctly configured! 
                # Just ensure the service is running and exit.
                print(f"[{self.name}] IP {local_ip} already authorized. Ensuring service is up...")
                conn.sudo("systemctl start glancesweb", hide=True, warn=True)
                conn.close()
                self.finished.emit(self.name, True)
                return

            # 3. If we are here, the IP has changed or is missing.
            # Clean out ONLY old rules that don't match our current IP
            print(f"[{self.name}] IP change detected. Updating firewall to {local_ip}...")
            rules = conn.sudo("firewall-cmd --list-rich-rules", hide=True).stdout
            for line in rules.splitlines():
                if 'port="61208"' in line:
                    conn.sudo(f"firewall-cmd --permanent --remove-rich-rule='{line.strip()}'", hide=True)
            
            # 4. Apply new rule
            new_rule = f'rule family="ipv4" source address="{local_ip}" port protocol="tcp" port="61208" accept'
            conn.sudo(f"firewall-cmd --permanent --add-rich-rule='{new_rule}'", hide=True)
            conn.sudo("firewall-cmd --reload", hide=True)
            
            # 5. Final service kick to ensure the deadlock we found earlier is cleared
            conn.sudo("systemctl restart glancesweb", warn=True, hide=True)
            
            conn.close()
            self.finished.emit(self.name, True)
            
        except Exception as e:
            print(f"Repair Error on {self.name}: {e}")
            self.finished.emit(self.name, False)

class GlancesWorker(QThread):
    stats_updated = pyqtSignal(str, float, float)
    needs_repair = pyqtSignal(str)

    def __init__(self, name, entry):
        super().__init__()
        self.name = name
        self.entry = entry
        self.ip = entry['ip']
        self.fail_count = 0
        self.is_repairing = False

    def check_ip_reachable(self):
        """Quickly check if the IP is even alive on the network."""
        try:
            # Try to open a socket to the port quickly
            socket.setdefaulttimeout(2)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.ip, 61208))
            s.close()
            return True
        except:
            return False

    def run(self):
        while True:
            if not self.is_repairing:
                try:
                    # 1. Fetch CPU
#                    r = requests.get(f"http://{self.ip}:61208/api/3/all", timeout=5)
                    r_cpu = requests.get(f"http://{self.ip}:61208/api/3/cpu", timeout=10)
                    # 2. Fetch MEM
                    r_mem = requests.get(f"http://{self.ip}:61208/api/3/mem", timeout=10)
                    
                    if r_cpu.status_code == 200 and r_mem.status_code == 200:
                        cpu_data = r_cpu.json()
                        mem_data = r_mem.json()
                        
                        # Note: Individual plugin endpoints return the dict directly
                        # Not wrapped in another key
                        cpu_val = cpu_data.get('total', 0.0)
                        mem_val = mem_data.get('percent', 0.0)
                        
                        self.stats_updated.emit(self.name, cpu_val, mem_val)
                        self.fail_count = 0 
                    else:
                        # If the service is there but the API path is wrong
                        print(f"[{self.name}] API Path Error: Check Glances Version")
                
                except requests.exceptions.Timeout:
                    # This should be MUCH rarer now that we aren't using /all
                    print(f"[{self.name}] Stats update timed out.")
                    self.stats_updated.emit(self.name, 0.0, 0.0)
                except requests.exceptions.ConnectionError:
                    self.fail_count += 1
                    if self.fail_count >= 3:
                        self.is_repairing = True
                        self.needs_repair.emit(self.name)
            
            self.sleep(5)


# --- 3. UI Components (Same as before) ---

class ServerTile(QWidget):
    def __init__(self, name, ip, display_mode="server", parent=None):
        super().__init__(parent)
        self.server_name = name
        self.ip_address = ip
        self.display_mode = display_mode 
        
        header_text = self.server_name.upper() if self.display_mode == "server" else self.ip_address

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        # Header Label - Curved top corners
        self.name_label = QLabel(header_text)
        self.name_label.setAlignment(Qt.AlignCenter)
        self.name_label.setFixedHeight(14) 
        # Added border-top-left-radius and border-top-right-radius
        self.name_label.setStyleSheet("""
            font-weight: bold; color: #FFFFFF; font-size: 11px; 
            background-color: #2c3e50; 
            border-top-left-radius: 4px; border-top-right-radius: 4px;
        """)
        layout.addWidget(self.name_label)

        # Combined Stats Label - Square (middle element)
        self.stats_label = QLabel("CPU: --%  MEM: --%")
        self.stats_label.setAlignment(Qt.AlignCenter)
        self.stats_label.setFixedHeight(14)
        self.stats_label.setStyleSheet("color: #FFFFFF; font-weight: 500; font-size: 9px; background-color: #2c3e50;")
        layout.addWidget(self.stats_label)

        # CPU Bar
        self.cpu_bar = QProgressBar()
        self.cpu_bar.setFixedHeight(14)
#        self.cpu_bar.setRange(0, 100)
#        self.cpu_bar.setFormat("  CPU")
        self.cpu_bar.setFormat("")
#        self.cpu_bar.setFormat(" CPU %p%")
        self.cpu_bar.setTextVisible(True)
        self.cpu_bar.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addWidget(self.cpu_bar)

        # Memory Bar - Curved bottom corners
        self.mem_bar = QProgressBar()
        self.mem_bar.setFixedHeight(14)
#        self.mem_bar.setRange(0, 100)
#        self.mem_bar.setFormat("  MEM")
        self.mem_bar.setFormat("")
#        self.mem_bar.setFormat(" MEM %p%")
        self.mem_bar.setTextVisible(True)
        self.mem_bar.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addWidget(self.mem_bar)
        
        '''
        self.cpu_bar_style = """
            QProgressBar {
                border: 1px solid #444;
                border-radius: 4px;
                background-color: #222;
                text-align: left; /* Keep text to the left */
                color: white;
                font-weight: bold;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #3498db; /* Blue for CPU */
                width: 1px;
            }
        """
        self.cpu_bar.setStyleSheet(self.cpu_bar_style)

        self.mem_bar_style = """
            QProgressBar {
                border: 1px solid #444;
                border-radius: 4px;
                background-color: #222;
                text-align: left; /* Keep text to the left */
                color: white;
                font-weight: bold;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #9b59b6; /* Blue for MEM */
                width: 1px;
            }
        """
        self.mem_bar.setStyleSheet(self.mem_bar_style)
        '''

        # Use a similar one for MEM with a different chunk color (e.g., #9b59b6)

        # Main Tile Container
        self.setStyleSheet("background-color: #1c2833; border-radius: 6px; border: 1px solid #34495e;")

    def set_repairing(self, state):
        if state:
#            self.stats_label.setText("NETWORK ERROR: Repairing...")
            self.stats_label.setText("CONN LOST: Re-verifying IP...")
            self.stats_label.setStyleSheet("background-color: #e67e22; color: white; font-size: 9px;")
        else:
            # This will be called when repair finishes
            self.update_ui(0, 0)

    def set_repairing2(self, state):
        if state:
            live_label_bg = "background-color: #2c3e50; color: #FFFFFF; font-weight: bold;"
            self.stats_label.setStyleSheet(f"{live_label_bg} font-size: 9px; font-weight: 500;")
#            self.stats_label.setText(f"IP CHANGED? Repairing...")
            self.stats_label.setText("CONN LOST: Re-verifying IP...")
            cpu_color = "#a3cb38"
            mem_color = "#a3cb38"
            base_bar_style = "QProgressBar { background-color: #2c3e50; border: none; color: white; font-size: 8px; font-weight: bold; border-radius: 0px; } "    
            self.cpu_bar.setStyleSheet(base_bar_style + f"QProgressBar::chunk {{ background-color: {cpu_color}; }}")
            self.mem_bar.setStyleSheet(base_bar_style + f"QProgressBar::chunk {{ background-color: {mem_color}; border-bottom-left-radius: 4px; border-bottom-right-radius: 4px; }}")
        else:
            self.update_ui(0, 0)

    def update_ui(self, cpu, mem):
        # 1. THE FIX: Re-apply 'Live' styles to labels to clear blackout
        live_label_bg = "background-color: #2c3e50; color: #FFFFFF; font-weight: bold;"
        
        self.name_label.setStyleSheet(f"{live_label_bg} font-size: 11px; border-top-left-radius: 4px; border-top-right-radius: 4px;")
        self.stats_label.setStyleSheet(f"{live_label_bg} font-size: 9px; font-weight: 500;")

        # 2. Update Text and Values
        self.stats_label.setText(f"CPU: {int(cpu)}%  MEM: {int(mem)}%")
        self.cpu_bar.setValue(int(cpu))
        self.mem_bar.setValue(int(mem))
        
        # 3. Bar Colors
#        cpu_color = "#e74c3c" if cpu > 85 else "#2ecc71"
#        mem_color = "#e74c3c" if mem > 85 else "#2ecc71"
        
        if cpu > 90 or mem > 90:
            cpu_color = "#e74c3c" # Red Crimson
            mem_color = "#e74c3c" # Red Crimson
        elif cpu > 70 or mem > 70:
            cpu_color = "#ffa500" # Orange
            mem_color = "#ffa500" # Orange
        else:
            cpu_color = "#2ecc71" # Green
            mem_color = "#2980b9" # Blue

        # Ensure bars don't keep blackout borders
        base_bar_style = "QProgressBar { background-color: #2c3e50; border: none; color: white; font-size: 8px; font-weight: bold; border-radius: 0px; } "
        
        self.cpu_bar.setStyleSheet(base_bar_style + f"QProgressBar::chunk {{ background-color: {cpu_color}; }}")
        self.mem_bar.setStyleSheet(base_bar_style + f"QProgressBar::chunk {{ background-color: {mem_color}; border-bottom-left-radius: 4px; border-bottom-right-radius: 4px; }}")

    def set_blackout_state(self):
        """Used when the service is unreachable but we aren't sure why yet."""
        self.stats_label.setText("GLANCES DOWN")
        black_bg = "background-color: #000000; color: #7f8c8d; border: 1px solid #222;"
        self.name_label.setStyleSheet(f"font-size: 11px; {black_bg}")
        self.stats_label.setStyleSheet(f"font-size: 9px; {black_bg}")
        
        self.cpu_bar.setValue(0)
        self.mem_bar.setValue(0)

    def set_blackout_state2(self):
        # 1. Force Stats to 0%
        self.stats_label.setText("CPU: 0%  MEM: 0%")
        
        # 2. Apply Blackout Style
        black_bg = "background-color: #000000; color: #555; border: 1px solid #222;"
        
        self.name_label.setStyleSheet(f"font-size: 11px; border-top-left-radius: 4px; border-top-right-radius: 4px; {black_bg}")
        self.stats_label.setStyleSheet(f"font-size: 9px; font-weight: 500; {black_bg}")
        
        # 3. Solid Black Bars
        blackout_bar = "QProgressBar { background-color: #000000; border: 1px solid #222; color: #444; font-size: 8px; border-radius: 0px; } QProgressBar::chunk { background-color: #000000; }"
        
        self.cpu_bar.setValue(0)
        self.mem_bar.setValue(0)
        self.cpu_bar.setStyleSheet(blackout_bar)
        self.mem_bar.setStyleSheet(blackout_bar)

# --- 4. Main Window ---
class ConduitDashboard(QMainWindow):
    def __init__(self,console, display_mode="server",json_file="servers.json"):
        super().__init__()

# This ensures the dashboard uses Fusion even if the parent app doesn't
        app = QApplication.instance()
        if app:
            app.setStyle(QStyleFactory.create("Fusion"))

        self.console = console
        self.display_mode = display_mode
        self.setWindowTitle("System-Health Dashboard")
        self.setGeometry(50, 50, 1300, 850)
#        self.setStyleSheet("QMainWindow { background-color: #121212; }")
        self.setStyleSheet("QMainWindow { background-color: #1e1e1e; }")

        main_layout = QVBoxLayout()
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        scroll = QScrollArea()
        scroll_content = QWidget()
        self.grid = QGridLayout(scroll_content)
        scroll.setWidgetResizable(True)
        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)

        self.tiles = {}
        self.workers = {}
        self.server_data = {} # To store original entry for repairs

        self.load_and_start(json_file)

    def set_display_mode(self, new_mode):
        self.display_mode = new_mode
        # Loop through all tiles and update their header text
        for tile in self.tiles.values():
            tile.display_mode = new_mode
            # Refresh the text immediately
            header_text = tile.server_name.upper() if new_mode == "server" else tile.ip_address
            tile.name_label.setText(header_text)

    def load_and_start(self,json_file):
        try:
            with open(json_file, 'r') as f:
                servers = json.load(f)
            
            cols = 7
            for i, entry in enumerate(servers):
                name = entry['server']
                self.server_data[name] = entry
                
                tile = ServerTile(name, entry['ip'],self.display_mode)
#                tile = ServerTile(name, entry['ip'],display_mode="ip")
                self.grid.addWidget(tile, i // cols, i % cols)
                self.tiles[name] = tile

                worker = GlancesWorker(name, entry)
                worker.stats_updated.connect(self.update_tile)
                worker.needs_repair.connect(self.trigger_repair)
                worker.start()
                self.workers[name] = worker
        except Exception as e:
            print(f"Startup error: {e}")

    def update_tile(self, name, cpu, mem):
        if name in self.tiles:
            # If the API fails or returns zeros, trigger blackout
            if cpu == 0.0 and mem == 0.0:
                self.tiles[name].set_blackout_state()
            else:
                self.tiles[name].update_ui(cpu, mem)

    def trigger_repair(self, name):
        self.tiles[name].set_repairing(True)
        # Launch repair in background so GUI stays smooth
        repairer = RepairWorker(name, self.server_data[name])
        repairer.finished.connect(self.on_repair_finished)
        repairer.start()
        # Prevent GC
        setattr(self, f"repair_{name}", repairer)

    def on_repair_finished(self, name, success):
        self.tiles[name].set_repairing(False)
        # Resume the monitor
        if name in self.workers:
            self.workers[name].fail_count = 0
            self.workers[name].is_repairing = False

if __name__ == "__main__":
    app = QApplication(sys.argv); gui = ConduitGUI(); gui.show(); sys.exit(app.exec_())