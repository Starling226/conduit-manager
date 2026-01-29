# Psiphon Conduit Setup for Windows

This repository provides a suite of tools designed for Windows users to deploy, monitor, and manage **Psiphon Conduit** on remote Linux servers.

## Download and Preparations

1. **Create Directory:** Create a folder named `Conduit` in your `C:\` partition.
2. **Download Scripts:** Save the following scripts into `C:\Conduit`:
   * `deploy_conduit_single_server.py`
   * `deploy_conduit_multi_server.py`
   * `conduit_status_windows.py`
   * `conduit_manager_windows.py`
   
   
## Python Installation

1. **Download Python:** Visit [python.org/downloads](https://www.python.org/downloads) and download the latest version for Windows. Install with default parameters, ensuring you check the box **"Add Python to PATH."**
2. **Open PowerShell:** Type `cmd` in your Windows search bar and press Enter to open the Command Prompt.
3. **Navigate and Verify:**
   ```powershell
   cd C:\Conduit
   dir
   
Setup Pip: Ensure the Python package manager is up to date:  
```powershell 
py -m ensurepip --upgrade   

Install Required Packages:
```powershell
py -m pip install fabric paramiko

---

### Section 3: Deployment
```markdown
## Conduit Deployment

### Single Server
Run the following command to deploy to a single target. You will be prompted for the IP address and root password:
```powershell
py deploy_conduit_single_server.py


### Multi Server
For batch deployment, create a file named ip.txt in the C:\Conduit folder. Add one IP address per line. This script assumes all servers share the same root password.
```powershell
py deploy_conduit_multi_server.py

---

### Section 4: Monitoring
```markdown
## Monitoring

After installation, the Psiphon network requires time for vetting and propagation. This can take anywhere from a few minutes to several hours.

To monitor your current server status, run:
```powershell
py conduit_status_windows.py

Cycle: This script runs every hour by default.

Customization: To change the interval, edit CHECK_INTERVAL_SECONDS (line 14) in conduit_status_windows.py. Do not set this lower than 300 seconds (5 minutes).

---

### Section 5: Management and servers.txt
```markdown
## Management

The `conduit_manager_windows.py` script allows you to check status, stop, start, restart, or reset the service. Sometime even after few hours you have no clients; in that case, you might reset the conduit to get fresh keys and likely get clients.

### Using servers.txt
For the Management and Monitoring scripts to work with multiple servers, create a `servers.txt` file in the same directory.

**Format:**
`name,hostname,port,username,password`

**Example:**
`MyServer,123.45.67.89,22,root,Password123`

Section 6: Troubleshooting and Notes

## Troubleshooting

| Issue | Potential Cause | Solution |
| :--- | :--- | :--- |
| **Connection Timeout** | Firewall is blocking Port 22. | Ensure Port 22 is open in your VPS cloud firewall. |
| **Authentication Failed** | Incorrect password or root disabled. | Ensure `PermitRootLogin yes` is set in `/etc/ssh/sshd_config`. |
| **Permission Denied** | Not logged in as root. | Non-Status actions (Start/Stop/Reset) require root access. |

## Important Notes
* **SSH Port:** These scripts use the standard **SSH Port 22** for all connections.
* **Security Warning:** The `servers.txt` file contains plain-text passwords. **DO NOT** upload this file to GitHub.


---

---

## Disclaimer

**Use this software at your own risk.** These scripts are provided "as is" without any warranty of any kind. 

* **No Liability:** The author(s) assume **no liability** for loss of data, server downtime, or any damages resulting from the use of this code.
* **Third-Party Binaries:** These scripts are designed to download and install the official **Psiphon Conduit binary**. The author of these scripts is **not responsible** for the maintenance, security, or functionality of the Conduit binary itself.
* **Affiliation:** This project is an independent community tool and is **not** officially affiliated with or endorsed by the Psiphon team.




