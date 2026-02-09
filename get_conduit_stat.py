#!/usr/bin/python3
import os
import re
import subprocess
import sys
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
    if "Connecting" in line:
        pattern = r"(\d{4}-\d{2}-\d{2}.\d{2}:\d{2}:\d{2}).*?Connected:\s*(\d+).*?Up:\s*([\d\.]+\s*\w+).*?Down:\s*([\d\.]+\s*\w+)"
    else:
        pattern = r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}).*?Clients:\s*(\d+).*?Up:\s*([\d\.]+\s*\w+).*?Down:\s*([\d\.]+\s*\w+)"
    match = re.search(pattern, line)
    if match:
        if "Connecting" in line:
            return match.groups()

        return (f"{match.group(1)} {match.group(2)}", match.group(3), match.group(4), match.group(5))
    return None
  
def get_status():
    base_dir = "/opt/conduit"
    filename = os.path.join(base_dir, f"{datetime.now().year}-conduit.log")
    since = "'120 minutes ago'" if os.path.exists(filename) else f"'{datetime.now().year}-01-01 00:00:00'"

    cmd = (f"journalctl -u conduit.service --since {since} --no-pager -o short-iso")

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        lines = result.stdout.strip().splitlines()
    except:
        return []

    raw_points = []
    for line in lines:
        if (res := parse_record(line)) is not None:
            raw_points.append({
                'dt': datetime.strptime(res[0].replace('T', ' '), "%Y-%m-%d %H:%M:%S"),
                'c': int(res[1]),
                'u': parse_to_bytes(res[2]),
                'd': parse_to_bytes(res[3])
            })

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
    now_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
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
        
        # Limit check (2TB)
        if up > 2*1024**4 or dw > 2*1024**4: continue

        hourly_results.append({
            "time": h.strftime("%Y-%m-%d %H:%M:%S"),
            "clients": int(round(sum(d['c'] for d in grp) / len(grp))),
            "up": max(0, up), "down": max(0, dw)
        })
    return hourly_results

def get_stat():
    results = get_status()
    if not results: return
    base_dir = "/opt/conduit"
    os.makedirs(base_dir, exist_ok=True)
    filename = os.path.join(base_dir, f"{datetime.now().year}-conduit.log")
    existing = set()
    if os.path.exists(filename):
        with open(filename, "r") as r:
            for line in r: existing.add(line.split(',')[0].strip())
    with open(filename, "a") as f:
        for res in results:
            if res['time'] not in existing:
                f.write(f"{res['time']}, {res['clients']}, {res['up']}, {res['down']}\n")
                print(f"✅ Logged {res['time']}")

if __name__ == "__main__":
    get_stat()