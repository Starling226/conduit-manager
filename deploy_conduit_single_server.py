import sys
import os
from fabric import Connection, Config
from paramiko import AutoAddPolicy

def deploy():
    print("\n--- Psiphon Conduit Deployer (Port & SSH Key Support) ---")
    
    # --- 1. GET LOCAL PUBLIC KEY PATH ---
    home_path = os.path.expanduser("~")
    pub_key_path = os.path.join(home_path, ".ssh", "id_conduit.pub")
    
    # Check if the key exists before starting
    if not os.path.exists(pub_key_path):
        print(f"[ERROR] Public key not found at: {pub_key_path}")
        print(f"Please run this in PowerShell first: ssh-keygen -t ed25519 -f \"{home_path}\\.ssh\\id_conduit\"")
        return

    with open(pub_key_path, "r") as f:
        public_key_content = f.read().strip()

    # --- 2. INPUTS WITH DEFAULTS ---
    host = input("Server IP Address: ")
    port_input = input("SSH Port [22]: ") or "22"
    user = input("SSH Username [root]: ") or "root"
    password = input("SSH Password: ")
    max_clients = input("Max Clients [200]: ") or "200"
    bandwidth = input("Bandwidth Mbps [5.0]: ") or "40.0"

    print(f"\n[*] Target: {user}@{host}:{port_input}")
    confirm = input("Press Enter to start setup and inject SSH key...")

    # Configure connection with the specified port
    config = Config(overrides={'run': {'pty': True}, 'timeouts': {'connect': 20}})
    connect_kwargs = {
        "password": password,
        "look_for_keys": False,
        "allow_agent": False
    }

    # Pass port=int(port_input) to ensure Fabric connects to the right service
    conn = Connection(
        host=host, 
        user=user, 
        port=int(port_input), 
        connect_kwargs=connect_kwargs, 
        config=config
    )
    conn.client.set_missing_host_key_policy(AutoAddPolicy())

    try:
        conn.open()
        print(f"[*] Authenticated with password on port {port_input}.")

        # --- PHASE 0: SSH KEY INJECTION ---
        print("[*] Setting up SSH key-based access...")
        conn.run("mkdir -p ~/.ssh && chmod 700 ~/.ssh", hide=True)
        conn.run(f'echo "{public_key_content}" >> ~/.ssh/authorized_keys', hide=True)
        conn.run("chmod 600 ~/.ssh/authorized_keys", hide=True)
        print("[*] SSH Public Key injected successfully.")

        # --- PHASE 1: CLEANUP & SYSTEM SETUP ---
        print("[*] Stopping existing services...")
        conn.run("systemctl stop conduit", warn=True, hide=True)
        
        print("[*] Installing system tools...")
        if conn.run("command -v dnf", warn=True, hide=True).ok:
            conn.run("dnf install epel-release -y", hide=True)
            conn.run("dnf install wget firewalld curl tcpdump -y", hide=True)
        else:
            conn.run("apt-get update -y", hide=True)
            conn.run("apt-get install wget firewalld curl tcpdump -y", hide=True)

        # --- PHASE 2: FIREWAL) ---
        print("[*] Configuring firewall...")
        # Ensure firewalld is running and allow traffic on 443
        conn.run("systemctl start firewalld && firewall-cmd --permanent --add-port=443/tcp && firewall-cmd --reload", hide=True, warn=True)

        # --- PHASE 3: CONDUIT INSTALL ---
        print("[*] Downloading and installing Conduit...")
        conn.run("mkdir -p /opt/conduit", hide=True)
        conn.run("curl -L -o /opt/conduit/conduit https://github.com/ssmirr/conduit/releases/download/e421eff/conduit-linux-amd64", hide=True)
        conn.run("chmod +x /opt/conduit/conduit")
        conn.run("/opt/conduit/conduit service install", hide=True)
        
        # Apply settings to the service file
        service_file = "/etc/systemd/system/conduit.service"
        cmd = f"/opt/conduit/conduit start --max-clients {max_clients} --bandwidth {bandwidth} --data-dir /var/lib/conduit"
        conn.run(f"sed -i 's|^ExecStart=.*|ExecStart={cmd}|' {service_file}")
        # Ensure data directory exists
        conn.run("mkdir -p /var/lib/conduit", hide=True)

        # --- PHASE 4: START ---
        print("[*] Launching service...")
        conn.run("systemctl daemon-reload && systemctl enable conduit && systemctl start conduit", hide=True)

        print(f"\n[SUCCESS] Server {host}:{port_input} is live!")
        print(f"SSH keys are now configured for {user}.")

    except Exception as e:
        print(f"\n[ERROR] Deployment failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    deploy()