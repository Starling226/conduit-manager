#!/usr/bin/python3
import os
from datetime import datetime
import subprocess
import re

def parse_to_bytes(size_str):
    units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    try:
        parts = size_str.split()
        if len(parts) < 2: return 0
        number, unit = parts[0], parts[1]
        return int(float(number) * units.get(unit.upper(), 1))
    except Exception:
        return 0

def check_if_log_exist():
    base_dir = "/opt/conduit"
    filename = f"{datetime.now().year}-conduit.log"
    return [os.path.join(base_dir, filename)] if os.path.exists(os.path.join(base_dir, filename)) else []

def parse_record(line):
    # Dynamic detection of version
    if "Connecting" in line:
        pattern = r"(\d{4}-\d{2}-\d{2}.\d{2}:\d{2}:\d{2}).*?Connected:\s*(\d+).*?Up:\s*([\d\.]+\s*\w+).*?Down:\s*([\d\.]+\s*\w+)"
        match = re.search(pattern, line)
        if match: return match.groups()
    else:
        pattern = r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})[+-]\d{4}.*?Clients:\s*(\d+).*?Up:\s*([\d\.]+\s*\w+).*?Down:\s*([\d\.]+\s*\w+)"
        match = re.search(pattern, line)
        if match:
            # Constructing the list of 4
            result = [
                f"{match.group(1)} {match.group(2)}", 
                match.group(3),                       
                match.group(4),                       
                match.group(5)                        
            ]
            return result
        else:
            return None

    return None

def get_status():
    status_check = subprocess.run(["systemctl", "is-active", "conduit.service"], capture_output=True, text=True)
    if status_check.stdout.strip() != "active":
        return []

    logs_exist = len(check_if_log_exist()) > 0
#    since = "'1 hour ago'" if logs_exist else "'10 years ago'" # Get all if first run
    
#    cmd = (
#        f"journalctl -u conduit.service --since {since} --no-pager -o short-iso | "
#        f"grep '[STATS]' | sed 's/.*conduit\\[[0-9]*\\]: //'"
#    )

    if logs_exist:
        cmd = (
            f"journalctl -u conduit.service --since  '1 hour ago' --no-pager -o short-iso | "
            f"grep '[STATS]' | "
            f"sed 's/.*conduit\\[[0-9]*\\]: //'"
        )
    else:
        cmd = (
            f"journalctl -u conduit.service --no-pager -o short-iso"
        )

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        lines = result.stdout.strip().splitlines()
    except Exception:
        return []

    data_points = []
    for line in lines:
        if (res := parse_record(line)) is not None:
            dt_str, clients, up_str, down_str = res
            data_points.append({
                'dt': datetime.strptime(dt_str.replace('T', ' '), "%Y-%m-%d %H:%M:%S"),
                'c': int(clients),
                'u': parse_to_bytes(up_str),
                'd': parse_to_bytes(down_str)
            })

    if not data_points: return []

    # Process and Group by Hour
    hourly_results = []
    current_hour_data = []
    
    # Trackers for restart compensation
    offset_up = 0
    offset_down = 0
    prev_raw_u = data_points[0]['u']
    prev_raw_d = data_points[0]['d']

    for i, p in enumerate(data_points):
        # 1. Restart Compensation Logic
        if p['u'] < prev_raw_u: offset_up += prev_raw_u
        if p['d'] < prev_raw_d: offset_down += prev_raw_d
        
        # Adjusted values
        adj_u = p['u'] + offset_up
        adj_d = p['d'] + offset_down
        
        prev_raw_u, prev_raw_d = p['u'], p['d']

        # 2. Hourly grouping
        this_hour = p['dt'].replace(minute=0, second=0)
        
        if not current_hour_data or current_hour_data[0]['hour'] == this_hour:
            current_hour_data.append({'hour': this_hour, 'c': p['c'], 'u': adj_u, 'd': adj_d})
        else:
            # Process previous hour
            hourly_results.append(calculate_hour_stats(current_hour_data))
            current_hour_data = [{'hour': this_hour, 'c': p['c'], 'u': adj_u, 'd': adj_d}]

    # Add the last hour in progress
    if current_hour_data:
        hourly_results.append(calculate_hour_stats(current_hour_data))

    return hourly_results

def calculate_hour_stats(hour_list):
    avg_clients = sum(d['c'] for d in hour_list) / len(hour_list)
    # Since values are cumulative and adjusted for restarts, 
    # the traffic for this hour is Last - First
    up_diff = hour_list[-1]['u'] - hour_list[0]['u']
    down_diff = hour_list[-1]['d'] - hour_list[0]['d']
    
    return {
        "time": hour_list[-1]['hour'].strftime("%Y-%m-%d %H:%M:%S"),
        "clients": int(round(avg_clients)),
        "up": max(0, up_diff),
        "down": max(0, down_diff)
    }

def get_stat():
    results = get_status()
    if not results:
        print("No data available.")
        return

    current_year = datetime.now().year
    filename = f"/opt/conduit/{current_year}-conduit.log"
    os.makedirs("/opt/conduit", exist_ok=True)

    with open(filename, "a") as f:
        for res in results:
            log_row = f"{res['time']}, {res['clients']}, {res['up']}, {res['down']}\n"
            f.write(log_row)
            print(f"Logged: {log_row.strip()}")

if __name__ == "__main__":
    get_stat()