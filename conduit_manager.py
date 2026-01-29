import sys
import os
from fabric import Connection, Config

def load_servers(filename):
    """Loads names and IPs from servers.txt (Name, IP, Port, User)"""
    servers = []
    if not os.path.exists(filename):
        return None
    
    with open(filename, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    
    # Expected format: name,ip,port,user
    for line in lines[1:]: # Skip header
        parts = [p.strip().replace('"', '').replace("'", "") for p in line.split(',')]
        if len(parts) >= 4:
            servers.append({
                "name": parts[0],
                "ip": parts[1],
                "port": int(parts[2]),
                "user": parts[3]
            })
    return servers

def select_server(server_list):
    print("\nAvailable Servers:")
    for idx, s in enumerate(server_list, 1):
        print(f"{idx}. {s['name']} ({s['ip']})")
    
    choice = input("\nSelect server number: ").strip()
    try:
        return server_list[int(choice) - 1]
    except:
        print("[!] Invalid selection.")
        return None

def manage_conduit():
    # Automatically define the key path
    home_path = os.path.expanduser("~")
    key_path = os.path.join(home_path, ".ssh", "id_conduit")

    print(f"{'='*45}")
    print("      CONDUIT SERVICE CONTROL CENTER")
    print(f"{'='*45}")

    print("\n[M] Manual IP Entry")
    print("[L] Load from servers.txt")
    mode = input("\nChoose entry mode (M/L): ").strip().upper()

    server_list = None
    target = None

    if mode == 'L':
        server_list = load_servers("servers.txt")
        if not server_list:
            print("[!] Could not find servers.txt. Switching to Manual.")
            mode = 'M'
        else:
            target = select_server(server_list)
            if not target: return

    if mode == 'M' or not target:
        ip = input("Enter Server IP Address: ").strip()
        port = input("Enter Port [22]: ").strip() or "22"
        user = input("Enter username [root]: ").strip() or "root"
        target = {"name": "Manual Entry", "ip": ip, "port": int(port), "user": user}

    config = Config(overrides={'run': {'pty': True}})
    
    # Static connection settings using the automated key path
    connect_kwargs = {
        "key_filename": key_path,
        "look_for_keys": False,
        "allow_agent": False
    }

    try:
        conn = Connection(
            host=target['ip'], 
            user=target['user'], 
            port=target['port'], 
            connect_kwargs=connect_kwargs, 
            config=config
        )

        is_root = (target['user'].lower() == "root")

        while True:
            print(f"\n--- Managing: {target['name']} ({target['ip']}:{target['port']}) ---")
            print(f"Auth: Automated SSH Key (id_conduit)")
            print("-" * 45)
            print("1. START conduit")
            print("2. STOP conduit")
            print("3. RESTART conduit")
            print("4. STATUS conduit")
            print("5. RESET conduit (DANGER)")
            
            if server_list:
                print("6. CHANGE Active Server")
                print("7. EXIT")
            else:
                print("6. EXIT")
            
            cmd_choice = input("\nAction: ").strip()

            if cmd_choice in ['1', '2', '3', '5'] and not is_root:
                print("\n[!] This action requires root user.")
                continue

            if cmd_choice == '1':
                conn.run("systemctl start conduit")
            elif cmd_choice == '2':
                conn.run("systemctl stop conduit")
            elif cmd_choice == '3':
                conn.run("systemctl restart conduit")
            elif cmd_choice == '4':
                conn.run("systemctl status conduit", warn=True)
            elif cmd_choice == '5':
                print("\n" + "!"*50)
                print("DANGER: Clearing /var/lib/conduit/*")
                confirm = input("Are you sure? (Yes/No): ").strip().lower()
                if confirm == 'yes':
                    conn.run("systemctl stop conduit", warn=True)
                    conn.run("rm -rf /var/lib/conduit/*")
                    conn.run("systemctl start conduit")
                    conn.run("systemctl status conduit", warn=True)
            
            elif cmd_choice == '6' and server_list:
                new_target = select_server(server_list)
                if new_target:
                    target = new_target
                    conn.close()
                    # Re-initialize connection with new target
                    conn = Connection(host=target['ip'], user=target['user'], port=target['port'], connect_kwargs=connect_kwargs, config=config)
                    is_root = (target['user'].lower() == "root")
                    continue 
            
            elif (cmd_choice == '7' and server_list) or (cmd_choice == '6' and not server_list):
                conn.close()
                return 
            else:
                print("[!] Invalid action.")

    except Exception as e:
        print(f"\n[!] Connection Error: {e}")
        print(f"Ensure your private key exists at: {key_path}")

if __name__ == "__main__":
    try:
        manage_conduit()
    except KeyboardInterrupt:
        print("\n\n[!] Exit requested.")