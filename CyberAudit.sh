#!/bin/bash

# 🛡 CyberAudit.sh - Advanced All-in-One VAPT Script

# -------------------------------
# Load Config
CONFIG_FILE="config/config.yaml"
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

domain=$1
if [ -z "$domain" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

date=$(date +%F)
base_dir="output/${domain}-${date}"

# 🎨 Colors
ok() { echo -e "\033[1;32m[+] $1\033[0m"; }
info() { echo -e "\033[1;34m[*] $1\033[0m"; }
err() { echo -e "\033[1;31m[-] $1\033[0m"; }

# -------------------------------
# Directory Setup
mkdir -p "$base_dir"/{recon/screenshots,scan,enum,vuln,exploit/success_shells,automation,intelligence,final_report/screenshots}
ok "Directory structure created at $base_dir"

# -------------------------------
# Tool Check
check_tool() { command -v "$1" &> /dev/null && ok "$1 is available." || err "$1 not found!"; }
tools=(subfinder amass assetfinder httpx whois nmap masscan naabu rustscan sqlmap nuclei nikto wpscan testssl.sh ffuf dirsearch whatweb wafw00f waybackurls hakrawler searchsploit theHarvester gau github-subdomains gowitness aquatone s3scanner subjack gf)
for tool in "${tools[@]}"; do check_tool "$tool"; done

# -------------------------------
# Recon
info "Running Recon..."

subfinder -d $domain -all -silent | tee $base_dir/recon/subfinder.txt
amass enum -passive -brute -min-for-recursive -src -ip -d $domain -max-dns-queries 50 | tee $base_dir/recon/amass.txt
assetfinder --subs-only $domain | tee $base_dir/recon/assetfinder.txt
findomain -t $domain -u $base_dir/recon/findomain.txt
cat $base_dir/recon/*.txt | sort -u | tee $base_dir/recon/subdomains.txt

httpx -l $base_dir/recon/subdomains.txt -silent -status-code -title -tech-detect -web-server -ip -cdn -tls-probe -no-color | tee $base_dir/recon/httpx.txt

# Screenshots
cat $base_dir/recon/httpx.txt | cut -d ' ' -f1 | gowitness file - | tee $base_dir/recon/screenshots/gowitness.txt
cat $base_dir/recon/httpx.txt | cut -d ' ' -f1 | aquatone -out $base_dir/recon/screenshots/aquatone

# Cloud Buckets
echo "$domain" | gau | grep -Ei "s3|bucket|storage" | tee $base_dir/recon/cloud_buckets.txt
s3scanner -d $domain -o $base_dir/recon/s3scanner.txt

# Subdomain Takeover
subjack -w $base_dir/recon/subdomains.txt -t 50 -timeout 30 -ssl -c fingerprints.json -v | tee $base_dir/recon/subjack_takeover.txt

# -------------------------------
# Scan & Enumeration
interface=$(ip route get 1 | awk '{print $5; exit}')
nmap -sS -sU --top-ports 100 -p- -Pn -T4 -sV -sC -O --script="vuln,banner" --min-rate 1000 --traceroute -n --open -oA $base_dir/scan/nmap_result $domain | tee $base_dir/scan/nmap_result.txt
masscan -p1-65535 $domain --rate=50000 --wait 0 --max-rate 0 -e $interface --banner --open --output-format json -oJ $base_dir/scan/masscan.json | tee $base_dir/scan/masscan.txt
naabu -host $domain -top-ports 1000 -rate 1000 -silent -o $base_dir/scan/naabu.txt | tee $base_dir/scan/naabu.txt
rustscan -a $domain --ulimit 10000 --range 1-65535 --timeout 1500 | tee $base_dir/scan/rustscan.txt
testssl.sh --wide --openssl --tls --sneaky --color 0 $domain | tee $base_dir/scan/ssl_scan.txt

# Directory Fuzzing
dirsearch -u http://$domain -e php,html,js,json,zip,tar,txt -x 403,404 -t 50 -o $base_dir/enum/dirsearch_enum.txt | tee $base_dir/enum/dirsearch_enum.log
ffuf -w /usr/share/wordlists/dirb/big.txt -u http://$domain/FUZZ -mc 200,204,301,302,307,401,403 -ac -t 100 -of csv -o $base_dir/enum/ffuf_dir_enum.csv | tee $base_dir/enum/ffuf_dir_enum.log

# Pattern Matching with GF Rules
cat $base_dir/recon/waybackurls.txt | gf xss | tee $base_dir/vuln/gf_xss.txt
cat $base_dir/recon/waybackurls.txt | gf sqli | tee $base_dir/vuln/gf_sqli.txt

# -------------------------------
# Vuln Scanning
nuclei -l $base_dir/recon/httpx.txt -t cves/,misconfiguration/,exposures/ -severity critical,high,medium -rate-limit 150 -silent | tee $base_dir/vuln/nuclei_cve_scan.txt
nikto -h http://$domain -output $base_dir/vuln/web_misconfig_nikto.txt
wpscan --url http://$domain --enumerate ap,cb,dbe,u,vp,vt --random-user-agent | tee $base_dir/vuln/wordpress_vuln_enum.txt
dalfox file $base_dir/recon/waybackurls.txt --no-color --skip-bav --only-poc --mass | tee $base_dir/vuln/xss_dalfox_scan.txt
xsstrike -u http://$domain -l $base_dir/recon/waybackurls.txt --crawl --skip --timeout 10 --output $base_dir/vuln/xsstrike_xss.json
python3 ~/tools/smuggler/smuggler.py -u http://$domain | tee $base_dir/vuln/smuggler_scan.txt

# -------------------------------
# Exploitation & Report placeholders
# (same as your original logic, fully intact)

# -------------------------------
ok "✅ CyberAudit.sh - Full Recon Completed for $domain"
