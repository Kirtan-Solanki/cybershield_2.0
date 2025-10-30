#!/bin/bash
echo "Installing CyberShield AI Dependencies..."
pip install -r requirements_advanced.txt

# Additional system dependencies (Kali Linux)
sudo apt update
sudo apt install -y nmap python3-full build-essential

echo "Installation complete!"
echo "Run: python cybershield_ai.py"
