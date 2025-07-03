#!/bin/bash

# ==========================
# 🔍 Bypasser v1.1 (Lite Edition) - FIXED
# Author: 0xAbhi
# ==========================

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
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

# Check dependencies
check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}[!] $1 not found. Please install it.${NC}"
        exit 1
    fi
}

domain=$1
if [[ -z "$domain" ]]; then
    echo -e "${RED}[!] Usage: $0 target.com${NC}"
    exit 1
fi

# Verify required tools
check_dependency "subfinder"
check_dependency "dnsx"
check_dependency "httpx"
check_dependency "dig"
check_dependency "curl"
check_dependency "jq"

cf_ips='104\.|172\.|198\.41\.|199\.27\.|188\.114\.|141\.101\.|103\.|162\.|185\.93\.|190\.93\.|197\.234\.'

# Create output directory
output_dir="bypasser_output_$domain"
mkdir -p "$output_dir"

# Step 1: Subdomain Enum
echo -e "${CYAN}[*] Enumerating subdomains for: $domain${NC}"
subfinder -d "$domain" -silent > "$output_dir/subs.txt"

# Step 2: Resolve with dnsx (A records only)
echo -e "${CYAN}[*] Resolving IPs with dnsx...${NC}"
dnsx -l "$output_dir/subs.txt" -a -resp -silent > "$output_dir/resolved.txt"

# Step 3: HTTP probing
echo -e "${CYAN}[*] Scanning subdomains with httpx...${NC}"
httpx -l "$output_dir/subs.txt" -ip -title -web-server -tech-detect -status-code -silent > "$output_dir/httpx_results.txt"

# Step 4: MX Records
echo -e "${CYAN}[*] Checking MX records (possible IP leak)...${NC}"
dig mx "$domain" +short > "$output_dir/mx_records.txt"
echo -e "${YELLOW}$(cat $output_dir/mx_records.txt)${NC}"

# Step 5: Zone Transfer attempt
echo -e "${CYAN}[*] Trying DNS zone transfer (if misconfigured)...${NC}"
> "$output_dir/axfr_results.txt"
for ns in $(dig ns "$domain" +short); do
    echo -e "[?] Trying AXFR on $ns"
    dig axfr "$domain" @"$ns" >> "$output_dir/axfr_results.txt"
done

# Step 6: crt.sh passive enum
echo -e "${CYAN}[*] Checking crt.sh for additional subdomains...${NC}"
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/^*.//' | sort -u > "$output_dir/crt.txt"

# Step 7: Resolving crt.sh subdomains (A records only)
echo -e "${CYAN}[*] Resolving crt.sh subdomains...${NC}"
dnsx -l "$output_dir/crt.txt" -a -resp -silent > "$output_dir/crt_resolved.txt"

# Step 8: Extract potential real IPs (IPv4 only)
echo -e "${CYAN}[*] Filtering potential real IPs (non-Cloudflare)...${NC}"
grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$output_dir/resolved.txt" | grep -vE "$cf_ips" > "$output_dir/real_ips.txt"
grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$output_dir/crt_resolved.txt" | grep -vE "$cf_ips" >> "$output_dir/real_ips.txt"
sort -u "$output_dir/real_ips.txt" -o "$output_dir/real_ips.txt"

# Step 9: Reverse IP Lookup (Hackertarget API)
echo -e "${CYAN}[*] Running reverse IP lookup on filtered IPs...${NC}"
> "$output_dir/reverse_lookup.txt"
for ip in $(awk '{print $2}' "$output_dir/real_ips.txt" | sort -u); do
    echo -e "[>] Reverse lookup for $ip" | tee -a "$output_dir/reverse_lookup.txt"
    curl -s "https://api.hackertarget.com/reverseiplookup/?q=$ip" | tee -a "$output_dir/reverse_lookup.txt"
    echo -e "\n---\n" >> "$output_dir/reverse_lookup.txt"
    sleep 1.5
done

# Done
echo -e "${GREEN}[+] Done. Output saved to: $output_dir/${NC}"
echo -e " - subs.txt            : $(wc -l < "$output_dir/subs.txt") subdomains"
echo -e " - resolved.txt        : $(wc -l < "$output_dir/resolved.txt") resolved records"
echo -e " - real_ips.txt        : $(wc -l < "$output_dir/real_ips.txt") potential real IPs"
echo -e " - reverse_lookup.txt  : reverse DNS results"

exit 0
