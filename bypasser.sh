#!/bin/bash

# ==========================
# 🔍 Bypasser v1.1 (Lite Edition)
# Author: 0xAbhi
# ==========================

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "$CYAN"
cat << "EOF"
██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗███████╗██████╗ 
██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗█████╗  ██████╔╝
██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██╔══██╗
██████╔╝   ██║   ██║     ██║  ██║███████║███████║███████╗██║  ██║
╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝

                 ⚡ Real IP Discovery Tool by 0xAbhi
EOF
echo -e "$NC"

domain=$1
if [[ -z "$domain" ]]; then
    echo -e "${RED}[!] Usage: $0 target.com${NC}"
    exit 1
fi

cf_ips='104.|172.|198.41.|199.27.|188.114.|141.101.|103.|162.|185.93.|190.93.|197.234.'

# Step 1: Subdomain Enum
echo -e "${CYAN}[*] Enumerating subdomains for: $domain${NC}"
subfinder -d "$domain" -silent > subs.txt

# Step 2: Resolve with dnsx
echo -e "${CYAN}[*] Resolving IPs with dnsx...${NC}"
dnsx -l subs.txt -a -resp -cname -silent > resolved.txt

# Step 3: HTTP probing
echo -e "${CYAN}[*] Scanning subdomains with httpx...${NC}"
httpx -l subs.txt -ip -title -web-server -tech-detect -status-code -silent > httpx_results.txt

# Step 4: MX Records
echo -e "${CYAN}[*] Checking MX records (possible IP leak)...${NC}"
dig mx "$domain" +short > mx_records.txt && cat mx_records.txt

# Step 5: Zone Transfer attempt
echo -e "${CYAN}[*] Trying DNS zone transfer (if misconfigured)...${NC}"
for ns in $(dig ns "$domain" +short); do
    echo -e "[?] Trying AXFR on $ns"
    dig axfr "$domain" @$ns >> axfr_results.txt
done

# Step 6: crt.sh passive enum
echo -e "${CYAN}[*] Checking crt.sh for additional subdomains...${NC}"
crt_resp=$(curl -s -A "Mozilla/5.0" "https://crt.sh/?q=%25.$domain&output=json")

if echo "$crt_resp" | jq empty 2>/dev/null; then
    echo "$crt_resp" | jq -r '.[].name_value' | sort -u > crt.txt
else
    echo -e "${RED}[!] crt.sh returned invalid JSON. Skipping...${NC}"
    echo "" > crt.txt
fi

# Step 7: Resolving crt.sh subdomains
echo -e "${CYAN}[*] Resolving crt.sh subdomains...${NC}"
dnsx -l crt.txt -a -resp -silent > crt_resolved.txt

# Step 8: Extract potential real IPs
echo -e "${CYAN}[*] Filtering potential real IPs (non-Cloudflare)...${NC}"
grep -vE "$cf_ips" resolved.txt > real_ips.txt
grep -vE "$cf_ips" crt_resolved.txt >> real_ips.txt
sort -u real_ips.txt -o real_ips.txt

# Step 9: Reverse IP Lookup (Hackertarget API)
echo -e "${CYAN}[*] Running reverse IP lookup on filtered IPs...${NC}"
> reverse_lookup.txt

if [ -s real_ips.txt ]; then
    while read ip; do
        if [[ -n "$ip" ]]; then
            echo "[>] [$ip]" >> reverse_lookup.txt
            resp=$(curl -s "https://api.hackertarget.com/reverseiplookup/?q=$ip")
            if echo "$resp" | grep -q "No records found" || echo "$resp" | grep -q "error"; then
                echo "No domains found." >> reverse_lookup.txt
            else
                echo "$resp" >> reverse_lookup.txt
            fi
            echo -e "\n---\n" >> reverse_lookup.txt
        fi
    done < real_ips.txt
else
    echo "[!] No real IPs found. Skipping reverse lookup." >> reverse_lookup.txt
fi


# Done
echo -e "${GREEN}[+] Done. Check the following files for output:${NC}"
echo -e " - subs.txt            → from subfinder"
echo -e " - resolved.txt        → resolved subdomain IPs"
echo -e " - httpx_results.txt   → headers, tech info"
echo -e " - mx_records.txt      → email MX records"
echo -e " - axfr_results.txt    → AXFR results (if any)"
echo -e " - crt.txt             → crt.sh subdomains"
echo -e " - crt_resolved.txt    → resolved crt.sh IPs"
echo -e " - real_ips.txt        → filtered non-CF IPs (likely real)"
echo -e " - reverse_lookup.txt  → domains hosted on real IPs"

exit 0

