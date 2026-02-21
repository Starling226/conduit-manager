#!/usr/bin/python3
import os
import re
import subprocess
import sys
import argparse
from datetime import datetime

# Prevent crash on large integer to string conversion
sys.set_int_max_str_digits(0)

def parse_to_bytes(size_str):
    units = {"B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    try:
        match = re.search(r"([\d\.]+)\s*([a-zA-Z]*)", size_str)
        if not match: return 0
        num_str = match.group(1)
        if len(num_str.split('.')[0]) > 15: return 0 
        number = float(num_str)
        unit_key = match.group(2).upper()[0] if match.group(2) else "B"
        return int(number * units.get(unit_key, 1))
    except:
        return 0

def parse_record(line):
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

def get_status(work_dir, service):
    filename = os.path.join(work_dir, f"{datetime.now().year}-conduit.log")
    since = "'120 minutes ago'" if os.path.exists(filename) else f"'{datetime.now().year}-01-01 00:00:00'"

    cmd = (
        f"journalctl -u {service} "
        f"--since {since} --no-pager -o short-iso | "
        f"awk -F' CONDUIT_JSON: ' '{{ "
        f"split($1, a, \" \"); "
        f"split($2, b, \",\"); "
        f"print a[1] \",\" b[1] \",\" b[2] \",\" b[3] "
        f"}}'"
    )   
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        lines = result.stdout.strip().splitlines()
    except Exception as e:
        print(f"❌ Error reading journalctl for {service}: {e}")
        return []

    raw_points = []

    for line in lines:

        # 1. Regex to extract: Date, Clients, UP, DOWN
        if (res := parse_record(line)) is not None:
            dt_raw, clients, up_bytes, down_bytes = res
                
            # 2. Format data
            try:
                dt_obj = datetime.strptime(dt_raw, "%Y-%m-%dT%H:%M:%S%z")  # compatible with python 3.9
#                dt_obj = datetime.fromisoformat(dt_raw) # has isseus with python older than 3.11
                raw_points.append({
                    'dt': dt_obj,
                    'c': clients,
                    'u': up_bytes,
                    'd': down_bytes
                })
            except ValueError as ve:
                print(f"⚠️ Skipping line due to date error: {dt_raw}")
                continue

    if len(raw_points) < 2: return []

    adj_points = []
    off_u, off_d = 0, 0
    for i in range(len(raw_points)):
        if i > 0:
            if raw_points[i]['u'] < raw_points[i-1]['u']: off_u += raw_points[i-1]['u']
            if raw_points[i]['d'] < raw_points[i-1]['d']: off_d += raw_points[i-1]['d']
        adj_points.append({'dt': raw_points[i]['dt'], 'c': raw_points[i]['c'], 
                           'u': raw_points[i]['u'] + off_u, 'd': raw_points[i]['d'] + off_d})

    hourly_results = []

    log_tz = raw_points[0]['dt'].tzinfo
    now_hour = datetime.now(log_tz).replace(minute=0, second=0, microsecond=0)
    

#    now_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
    groups = {}
    for p in adj_points:
        h = p['dt'].replace(minute=0, second=0, microsecond=0)
        if h not in groups: groups[h] = []
        groups[h].append(p)

    for h in sorted(groups.keys()):
        if h >= now_hour: continue
        grp = groups[h]
        baseline = next((p for p in reversed(adj_points) if p['dt'] < h), grp[0])
        up, dw = grp[-1]['u'] - baseline['u'], grp[-1]['d'] - baseline['d']
        
        if up > 2*1024**4 or dw > 2*1024**4: continue

        hourly_results.append({
            "time": h.strftime("%Y-%m-%d %H:%M:%S"),
            "clients": int(round(sum(d['c'] for d in grp) / len(grp))),
            "up": max(0, up), "down": max(0, dw)
        })
    return hourly_results

def get_stat(work_dir, service):
    # --- PRE-FLIGHT PERMISSION CHECK ---
    if not os.path.exists(work_dir):
        try:
            os.makedirs(work_dir, exist_ok=True)
            print(f"📁 Created working directory: {work_dir}")
        except Exception as e:
            print(f"❌ CRITICAL: Could not create directory {work_dir}. Error: {e}")
            return

    if not os.access(work_dir, os.W_OK):
        print(f"❌ CRITICAL: Directory {work_dir} is NOT writable. Check permissions.")
        return

    results = get_status(work_dir, service)
    if not results: 
        print(f"⚠️ No new data found for {service} in the last 120 minutes.")
        return
    
    filename = os.path.join(work_dir, f"{datetime.now().year}-conduit.log")
    
    existing = set()
    if os.path.exists(filename):
        with open(filename, "r") as r:
            for line in r: existing.add(line.split(',')[0].strip())
            
    try:
        with open(filename, "a") as f:
            for res in results:
                if res['time'] not in existing:
                    f.write(f"{res['time']}, {res['clients']}, {res['up']}, {res['down']}\n")
                    print(f"✅ Logged {res['time']}")

    except Exception as e:
        print(f"❌ Error writing to log file: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Conduit Stat Logger")
    parser.add_argument("--work_dir", default="/opt/conduit", help="Base directory for logs")
    parser.add_argument("--service", default="conduit-monitor.service", help="Systemd service name")
    
    args = parser.parse_args()
    get_stat(args.work_dir, args.service)