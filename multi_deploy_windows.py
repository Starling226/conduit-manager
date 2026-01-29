# pip install fabric paramiko
import sys
from fabric import Connection, Config
from paramiko import AutoAddPolicy

def deploy_all():
    print("=== Multi-Server Conduit Automated Clean Deployer ===")
    
    # 1. Load IPs from servers.txt
    try:
        with open("servers.txt", "r") as f:
            ips = [line.strip() for line in f if line.strip()]
        if not ips:
            print("Error: 'servers.txt' is empty.")
            return
    except FileNotFoundError:
        print("Error: 'servers.txt' not found. Please create it with one IP per line.")
        return

    print(f"[*] Found {len(ips)} servers.")

    # 2. Gather Inputs with Defaults
    user = input("SSH Username [root]: ") or "root"
    password = input("SSH Password: ") # Visible input
    max_clients = input("Max Clients [200]: ") or "200"
    bandwidth = input("Bandwidth Mbps [40.0]: ") or "40.0"

    print(f"\n[*] Starting deployment for {len(ips)} servers using password: {password}")
    
    # 3. Stable Connection Config
    config = Config(overrides={'run': {'pty': True}, 'timeouts': {'connect': 20}})
    connect_kwargs = {
        "password": password,
        "look_for_keys": False,
        "allow_agent": False,
        "disabled_algorithms": dict(pubkeys=["rsa-sha2-256", "rsa-sha2-512"])
    }

    results = {"success": [], "failed": []}

    # 4. Process Loop
    for ip in ips:
        print(f"\n>>> Processing Server: {ip}")
        conn = Connection(host=ip, user=user, connect_kwargs=connect_kwargs, config=config)
        conn.client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            # Force stable session open
            conn.open()

            # --- PHASE 0: CLEANUP ---
            print(f"[{ip}] Stopping old service and cleaning files...")
            conn.run("systemctl stop conduit", warn=True, hide=True)
            conn.run("rm -f /opt/conduit/conduit", warn=True, hide=True)
            conn.run("rm -f /var/lib/conduit", warn=True, hide=True)
            conn.run("mkdir -f /opt/conduit", warn=True, hide=True)

            # --- PHASE 1: SYSTEM SETUP ---
            print(f"[{ip}] Updating system tools...")

            if conn.run("command -v dnf", warn=True, hide=True).ok:
                conn.run("dnf install epel-release -y", hide=True)
                conn.run("dnf install wget firewalld curl tcpdump bind-utils net-tools vim htop nload iftop nethogs -y", hide=True)
            else:
                conn.run("apt-get update -y", hide=True)
                conn.run("apt-get install wget firewalld curl tcpdump dnsutils net-tools vim htop nload iftop nethogs -y", hide=True)

            # --- PHASE 2: FIREWALL ---
            conn.run("systemctl start firewalld && firewall-cmd --permanent --add-port=443/tcp && firewall-cmd --reload", hide=True, warn=True)

            # --- PHASE 3: CONDUIT DEPLOY ---
            print(f"[{ip}] Downloading and Installing Conduit...")
            conn.run("curl -L -o /opt/conduit/conduit https://github.com/ssmirr/conduit/releases/download/e421eff/conduit-linux-amd64", hide=True)
            conn.run("chmod +x /opt/conduit/conduit")
            conn.run("/opt/conduit/conduit service install", hide=True)
            
            # Apply custom settings
            service_file = "/etc/systemd/system/conduit.service"
            cmd = f"/opt/conduit/conduit start --max-clients {max_clients} --bandwidth {bandwidth} --data-dir /var/lib/conduit"
            conn.run(f"sed -i 's|^ExecStart=.*|ExecStart={cmd}|' {service_file}")
            conn.run("sed -i 's/ProtectSystem=strict/ProtectSystem=full/' {service_file}")

            # --- PHASE 4: START ---
            conn.run("systemctl daemon-reload && systemctl enable conduit && systemctl start conduit", hide=True)
            
            print(f"[OK] {ip} successfully deployed.")
            results["success"].append(ip)

        except Exception as e:
            print(f"[ERROR] {ip} failed: {e}")
            results["failed"].append(ip)
        finally:
            conn.close()

    # 5. Final Summary
    print("\n" + "="*40)
    print(f"DELETION SUMMARY")
    print(f"Successfully Deployed: {len(results['success'])}")
    print(f"Failed: {len(results['failed'])}")
    if results["failed"]:
        print(f"Check these IPs: {', '.join(results['failed'])}")
    print("="*40)

if __name__ == "__main__":
    deploy_all()