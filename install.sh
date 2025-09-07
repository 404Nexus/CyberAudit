#!/bin/bash
# 🛠 CyberAudit.sh - Dependency Installer

echo -e "\033[1;34m[*] Installing dependencies for CyberAudit.sh...\033[0m"

# Update package lists
sudo apt update -y

# Essential tools
sudo apt install -y git curl wget unzip python3 python3-pip jq nmap masscan golang ffuf ruby build-essential

# Python dependencies for smuggler / xsstrike
pip3 install --upgrade pip
pip3 install requests beautifulsoup4 colorama

# Install Go tools
echo -e "\033[1;34m[*] Installing Go-based tools...\033[0m"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OWASP/Amass/v3/...@latest
go install github.com/projectdiscovery/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Ruby tools (WPScan)
sudo gem install wpscan

# Install Nikto
sudo apt install -y nikto

# Install testssl.sh
git clone https://github.com/drwetter/testssl.sh.git ~/tools/testssl.sh

# Install additional tools if missing
git clone https://github.com/mandatoryprogrammer/xsstrike.git ~/tools/xsstrike
git clone https://github.com/mandatoryprogrammer/smuggler.git ~/tools/smuggler

# Give executable permissions
chmod +x ~/tools/xsstrike/xsstrike.py
chmod +x ~/tools/smuggler/smuggler.py

echo -e "\033[1;32m[+] Installation complete! All tools are ready.\033[0m"
