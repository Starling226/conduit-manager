# pip install fabric paramiko
import sys
from fabric import Connection, Config
from paramiko import AutoAddPolicy

def deploy():
    print("\n--- Psiphon Conduit Clean Deployer (Visible Input) ---")
    
    # --- INPUTS WITH DEFAULTS ---
    host = input("Server IP Address: ")
    user = input("SSH Username [root]: ") or "root"
    password = input("SSH Password: ")
    max_clients = input("Max Clients [200]: ") or "200"
    bandwidth = input("Bandwidth Mbps [5.0]: ") or "40.0"

    # --- PRE-FLIGHT CHECK ---
    print(f"\n[*] Target: {user}@{host}")
    print(f"[*] Password: {password}") 
    confirm = input("Press Enter to start (stops existing service first)...")

    config = Config(overrides={'run': {'pty': True}, 'timeouts': {'connect': 20}})
    connect_kwargs = {
        "password": password,
        "look_for_keys": False,
        "allow_agent": False,
        "disabled_algorithms": dict(pubkeys=["rsa-sha2-256", "rsa-sha2-512"])
    }

    conn = Connection(host=host, user=user, connect_kwargs=connect_kwargs, config=config)
    conn.client.set_missing_host_key_policy(AutoAddPolicy())

    try:
        conn.open()
        print(f"[*] Authenticated.")

        # --- PHASE 0: CLEANUP ---
        print("[*] Checking for existing Conduit service...")
        # Stop service if it exists (warn=True prevents crashing if it's not there)
        conn.run("systemctl stop conduit", warn=True, hide=True)
        conn.run("systemctl disable conduit", warn=True, hide=True)
        
        # Remove old binary to ensure fresh download
        print("[*] Removing old files...")
        conn.run("rm -f /opt/conduit/conduit", warn=True)
        conn.run("rm -f /var/lib/conduit", warn=True)
        conn.run("mkdir -f /opt/conduit", warn=True)

        # --- PHASE 1: SYSTEM SETUP ---
        print("[*] Installing system tools...")
        if conn.run("command -v dnf", warn=True, hide=True).ok:
            conn.run("dnf install epel-release -y", hide=True)
            conn.run("dnf install wget firewalld curl tcpdump bind-utils net-tools vim htop nload iftop nethogs -y", hide=True)
        else:
            conn.run("apt-get update -y", hide=True)
            conn.run("apt-get install wget firewalld curl tcpdump dnsutils net-tools vim htop nload iftop nethogs -y", hide=True)

        # --- PHASE 2: FIREWALL ---
        print("[*] Configuring firewall...")
        conn.run("systemctl start firewalld && firewall-cmd --permanent --add-port=443/tcp && firewall-cmd --reload", hide=True, warn=True)

        # --- PHASE 3: CONDUIT INSTALL ---
        print("[*] Downloading Conduit...")
        conn.run("curl -L -o /opt/conduit/conduit https://github.com/ssmirr/conduit/releases/download/e421eff/conduit-linux-amd64", hide=True)
        conn.run("chmod +x /opt/conduit/conduit")
        
        # Re-install service definition
        conn.run("/opt/conduit/conduit service install", hide=True)
        
        # Apply settings
        service_file = "/etc/systemd/system/conduit.service"
        cmd = f"/opt/conduit/conduit start --max-clients {max_clients} --bandwidth {bandwidth} --data-dir /var/lib/conduit"
        
        conn.run(f"sed -i 's|^ExecStart=.*|ExecStart={cmd}|' {service_file}")
        conn.run(f"sed -i 's/ProtectSystem=strict/ProtectSystem=full/' {service_file}")

        # --- PHASE 4: START ---
        print("[*] Launching fresh service...")
        conn.run("systemctl daemon-reload && systemctl enable conduit && systemctl start conduit", hide=True)

        print(f"\n[SUCCESS] Server {host} is re-installed and live!")

    except Exception as e:
        print(f"\n[ERROR] Deployment failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    deploy()