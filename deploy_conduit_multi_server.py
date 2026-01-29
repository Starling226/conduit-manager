import os
import sys
from fabric import Connection, Config
from paramiko import AutoAddPolicy

def deploy_all():
    print("=== Multi-Server Conduit Automated Deployer (Key + Port) ===")
    
    # --- PHASE 0: PREPARE PUBLIC KEY ---
    home_path = os.path.expanduser("~")
    pub_key_path = os.path.join(home_path, ".ssh", "id_conduit.pub")
    
    if not os.path.exists(pub_key_path):
        print(f"[ERROR] Public key not found at: {pub_key_path}")
        print(fr'Run this in PowerShell first: ssh-keygen -t ed25519 -f "{home_path}\.ssh\id_conduit"')
        return

    with open(pub_key_path, "r") as f:
        public_key_content = f.read().strip()

    # --- PHASE 1: LOAD SERVERS ---
    try:
        with open("ip.txt", "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            print("Error: 'ip.txt' is empty.")
            return
    except FileNotFoundError:
        print("Error: 'ip.txt' not found. Please create it.")
        return

    # --- PHASE 2: GATHER INPUTS ---
    default_port = input("Default SSH Port [22]: ") or "22"
    user = input("SSH Username [root]: ") or "root"
    password = input("SSH Password: ")
    max_clients = input("Max Clients [200]: ") or "200"
    bandwidth = input("Bandwidth Mbps [40.0]: ") or "40.0"

    print(f"\n[*] Processing {len(lines)} servers...")
    
    config = Config(overrides={'run': {'pty': True}, 'timeouts': {'connect': 20}})
    results = {"success": [], "failed": []}

    # --- PHASE 3: PROCESS LOOP ---
    for entry in lines:
        # Check if entry is IP or IP:PORT
        if ":" in entry:
            ip, port = entry.split(":")
        else:
            ip = entry
            port = default_port

        print(f"\n>>> Processing Server: {ip}:{port}")
        
        connect_kwargs = {
            "password": password,
            "look_for_keys": False,
            "allow_agent": False
        }

        conn = Connection(host=ip, user=user, port=int(port), connect_kwargs=connect_kwargs, config=config)
        conn.client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            conn.open()

            # --- KEY INJECTION ---
            print(f"[{ip}] Injecting SSH key...")
            conn.run("mkdir -p ~/.ssh && chmod 700 ~/.ssh", hide=True)
            conn.run(f'echo "{public_key_content}" >> ~/.ssh/authorized_keys', hide=True)
            conn.run("chmod 600 ~/.ssh/authorized_keys", hide=True)

            # --- CLEANUP & SYSTEM SETUP ---
            print(f"[{ip}] Cleaning and updating system...")
            conn.run("systemctl stop conduit", warn=True, hide=True)
            conn.run("rm -f /opt/conduit/conduit", warn=True, hide=True)
            conn.run("mkdir -p /opt/conduit", warn=True, hide=True)

            if conn.run("command -v dnf", warn=True, hide=True).ok:
                conn.run("dnf install wget firewalld curl -y", hide=True)
            else:
                conn.run("apt-get update -y", hide=True)
                conn.run("apt-get install wget firewalld curl -y", hide=True)

            # --- FIREWALL & CONDUIT ---
            conn.run("systemctl start firewalld && firewall-cmd --permanent --add-port=443/tcp && firewall-cmd --reload", hide=True, warn=True)

            print(f"[{ip}] Downloading and Installing Conduit...")
            conn.run("curl -L -o /opt/conduit/conduit https://github.com/ssmirr/conduit/releases/download/e421eff/conduit-linux-amd64", hide=True)
            conn.run("chmod +x /opt/conduit/conduit")
            conn.run("/opt/conduit/conduit service install", hide=True)
            
            service_file = "/etc/systemd/system/conduit.service"
            cmd = f"/opt/conduit/conduit start --max-clients {max_clients} --bandwidth {bandwidth} --data-dir /var/lib/conduit"
            conn.run(f"sed -i 's|^ExecStart=.*|ExecStart={cmd}|' {service_file}")

            # --- START ---
            conn.run("systemctl daemon-reload && systemctl enable conduit && systemctl start conduit", hide=True)
            
            print(f"[OK] {ip} successfully deployed.")
            results["success"].append(ip)

        except Exception as e:
            print(f"[ERROR] {ip} failed: {e}")
            results["failed"].append(ip)
        finally:
            conn.close()

    # --- FINAL SUMMARY ---
    print("\n" + "="*40)
    print(f"DEPLOYMENT SUMMARY")
    print(f"Successfully Deployed: {len(results['success'])}")
    print(f"Failed: {len(results['failed'])}")
    print("="*40)

if __name__ == "__main__":
    deploy_all()