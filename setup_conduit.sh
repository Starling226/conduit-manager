#!/bin/bash

# Step 1: Change to user home directory
cd "$HOME" || exit

# Step 2: Ensure pip is updated and install dependencies
# We use python3 on Linux. We also add 'python3-pip' reminder 
# as some Linux distros don't include it by default.
echo "[*] Updating pip and installing dependencies..."
python3 -m pip install --upgrade pip
python3 -m pip install fabric paramiko PyQt5

# Step 3: Setup SSH directory and keys
if [ ! -d ".ssh" ]; then
    mkdir -p ".ssh"
    chmod 700 ".ssh"
fi

cd .ssh || exit

# Generate key only if it doesn't exist to avoid overwriting
if [ ! -f "id_conduit" ]; then
    echo "[*] Generating SSH key: id_conduit"
    ssh-keygen -t ed25519 -f id_conduit -N ""
else
    echo "[!] id_conduit already exists. Skipping keygen."
fi

# Step 4: Conditional Directory Change
# Linux doesn't have C:\, so we check for /opt/conduit or a local folder
if [ -d "/opt/conduit" ]; then
    cd "/opt/conduit" || exit
    echo "[*] Moved to /opt/conduit"
elif [ -d "$HOME/Conduit" ]; then
    cd "$HOME/Conduit" || exit
    echo "[*] Moved to $HOME/Conduit"
else
    echo ""
    echo "[NOTICE] Conduit directory not found. Staying in $(pwd)"
fi

# Step 5: Hand over control (Keep the terminal open)
exec $SHELL
