#!/bin/bash

# ======================================================
# 🔍 Bypasser v2.2 - CloudFlare & CDN Bypass Toolkit
# Author: 0xR4bbit/Abhi
# ======================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

# Banner
echo -e "${CYAN}"
cat << "EOF"
██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗███████╗██████╗ 
██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗█████╗  ██████╔╝
██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██╔══██╗
██████╔╝   ██║   ██║     ██║  ██║███████║███████║███████╗██║  ██║
╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
EOF
echo -e "${BLUE}             ⚡ Real IP Discovery & CDN Bypass Toolkit by 0xR4bbit${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}[!] Warning: Running as root is not recommended for security reasons.${NC}"
    sleep 2
fi

# Dependency check
check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[✗] $1 not found. Please install it:${NC}"
        
        case "$1" in
            subfinder) echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
            dnsx)      echo "  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest" ;;
            httpx)     echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
            jq)        echo "  sudo apt install jq" ;;
            dig)       echo "  sudo apt install dnsutils" ;;
            curl)      echo "  sudo apt install curl" ;;
            parallel)  echo "  sudo apt install parallel" ;;
            ipcalc)    echo "  sudo apt install ipcalc" ;;
            *)         echo "  Check your package manager for installation" ;;
        esac
        
        exit 1
    fi
}

domain="$1"
if [[ -z "$domain" ]]; then
    echo -e "${RED}[!] Usage: $0 target.com${NC}"
    exit 1
fi

# Validate domain format
if ! [[ "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo -e "${RED}[✗] Invalid domain format: $domain${NC}"
    exit 1
fi

# Required tools
tools=("subfinder" "dnsx" "httpx" "dig" "curl" "jq" "parallel" "ipcalc")
echo -e "${CYAN}[*] Verifying dependencies...${NC}"
for tool in "${tools[@]}"; do
    check_dependency "$tool"
    echo -e "  ${GREEN}[✓]${NC} $tool"
done

# Cloudflare IP ranges (updated 2023)
cf_ips=(
    "104.16.0.0/12" "172.64.0.0/13" "173.245.48.0/20" "103.21.244.0/22"
    "103.22.200.0/22" "103.31.4.0/22" "141.101.64.0/18" "108.162.192.0/18"
    "190.93.240.0/20" "188.114.96.0/20" "197.234.240.0/22" "198.41.128.0/17"
    "162.158.0.0/15" "172.64.0.0/13" "131.0.72.0/22" "2400:cb00::/32"
    "2606:4700::/32" "2803:f800::/32" "2405:b500::/32" "2405:8100::/32"
    "2a06:98c0::/29" "2c0f:f248::/32"
)

# Create output directory with timestamp
timestamp=$(date +"%Y%m%d-%H%M%S")
output_dir="bypasser_${domain}_${timestamp}"
mkdir -p "$output_dir"
echo -e "${CYAN}[*] Output directory: ${GREEN}$output_dir${NC}"

# Log file
log_file="$output_dir/execution.log"
exec > >(tee -a "$log_file") 2>&1

# Step 1: Subdomain Enumeration
echo -e "\n${CYAN}[*] Enumerating subdomains for: ${YELLOW}$domain${NC}"
subfinder -d "$domain" -silent | tee "$output_dir/subs_raw.txt" | wc -l | \
  awk -v CYAN="$CYAN" -v GREEN="$GREEN" -v NC="$NC" \
  '{printf CYAN"[*] Found " GREEN"%d" CYAN" subdomains" NC "\n", $1}'

# Step 2: Resolve with dnsx (A records only)
echo -e "${CYAN}[*] Resolving IPs with dnsx...${NC}"
dnsx -l "$output_dir/subs_raw.txt" -a -resp -silent -o "$output_dir/resolved.txt"
resolved_count=$(grep -c . "$output_dir/resolved.txt" 2>/dev/null || echo 0)
echo -e "  ${GREEN}[+]${NC} Resolved ${GREEN}$resolved_count${NC} subdomains"

# Step 3: HTTP probing
echo -e "${CYAN}[*] Scanning subdomains with httpx...${NC}"
httpx -l "$output_dir/subs_raw.txt" -ip -title -web-server -tech-detect -status-code -silent \
  -o "$output_dir/httpx_results.txt" -csv -csv-output "$output_dir/httpx_results.csv"
httpx_count=$(grep -c . "$output_dir/httpx_results.txt" 2>/dev/null || echo 0)
echo -e "  ${GREEN}[+]${NC} Found ${GREEN}$httpx_count${NC} live hosts"

# Step 4: DNS Records Check
echo -e "${CYAN}[*] Checking critical DNS records...${NC}"

# MX Records
echo -e "${BLUE}  MX Records:${NC}" | tee -a "$output_dir/dns_records.txt"
dig mx "$domain" +short | tee -a "$output_dir/dns_records.txt"

# TXT Records
echo -e "\n${BLUE}  TXT Records:${NC}" | tee -a "$output_dir/dns_records.txt"
dig txt "$domain" +short | tee -a "$output_dir/dns_records.txt"

# NS Records
echo -e "\n${BLUE}  Name Servers:${NC}" | tee -a "$output_dir/dns_records.txt"
dig ns "$domain" +short | tee -a "$output_dir/dns_records.txt"

# Step 5: Zone Transfer attempt (IPv4 only with TCP)
echo -e "\n${CYAN}[*] Trying DNS zone transfer...${NC}"
> "$output_dir/axfr_results.txt"

nameservers=($(dig ns "$domain" +short))
if [ ${#nameservers[@]} -eq 0 ]; then
    echo -e "  ${RED}[✗] No nameservers found for $domain${NC}"
else
    for ns in "${nameservers[@]}"; do
        echo -e "${YELLOW}[>] Trying AXFR on $ns${NC}" | tee -a "$output_dir/axfr_results.txt"
        dig +tcp axfr "$domain" @"$ns" >> "$output_dir/axfr_results.txt" 2>&1
        echo -e "\n---\n" >> "$output_dir/axfr_results.txt"
    done

    # Check if AXFR succeeded
    if grep -q "Transfer failed" "$output_dir/axfr_results.txt" || ! grep -q "IN" "$output_dir/axfr_results.txt"; then
        echo -e "  ${YELLOW}[!] No successful zone transfers${NC}"
    else
        echo -e "  ${GREEN}[✓] SUCCESS: Zone transfer completed!${NC}"
    fi
fi

# Step 6: crt.sh passive enum
echo -e "\n${CYAN}[*] Checking crt.sh for additional subdomains...${NC}"
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | \
  sed 's/^\*\.//;s/^\.//' | sort -u | tee "$output_dir/crt.txt" | wc -l | \
  awk -v CYAN="$CYAN" -v GREEN="$GREEN" -v NC="$NC" \
  '{printf CYAN"[*] Found " GREEN"%d" CYAN" new subdomains from crt.sh" NC "\n", $1}'

# Step 7: Resolving crt.sh subdomains
echo -e "${CYAN}[*] Resolving crt.sh subdomains...${NC}"
dnsx -l "$output_dir/crt.txt" -a -resp -silent -o "$output_dir/crt_resolved.txt"
crt_count=$(grep -c . "$output_dir/crt_resolved.txt" 2>/dev/null || echo 0)
echo -e "  ${GREEN}[+]${NC} Resolved ${GREEN}$crt_count${NC} crt.sh subdomains"

# Step 8: Extract potential real IPs
echo -e "\n${CYAN}[*] Filtering potential real IPs...${NC}"

# Combine all resolved IPs
cat "$output_dir/resolved.txt" "$output_dir/crt_resolved.txt" | \
  grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
  sort -u > "$output_dir/all_ips.txt"

# Filter Cloudflare IPs
> "$output_dir/cf_ips.txt"
> "$output_dir/real_ips.txt"

for ip in $(cat "$output_dir/all_ips.txt"); do
    is_cf=false
    for range in "${cf_ips[@]}"; do
        if ipcalc -n "$ip" "$range" 2>/dev/null | grep -q "Network:"; then
            echo "$ip" >> "$output_dir/cf_ips.txt"
            is_cf=true
            break
        fi
    done
    if ! $is_cf; then
        echo "$ip" >> "$output_dir/real_ips.txt"
    fi
done

cf_count=$(wc -l < "$output_dir/cf_ips.txt")
real_count=$(wc -l < "$output_dir/real_ips.txt")
echo -e "  ${GREEN}[+]${NC} Cloudflare IPs: ${YELLOW}$cf_count${NC}"
echo -e "  ${GREEN}[+]${NC} Potential real IPs: ${GREEN}$real_count${NC}"

# Step 9: Reverse IP Lookup (Multi-source)
reverse_lookup() {
    ip="$1"
    echo -e "\n[>] Reverse lookup for $ip"
    
    # Hackertarget API
    echo "=== Hackertarget ==="
    curl -s "https://api.hackertarget.com/reverseiplookup/?q=$ip"
    
    # ViewDNS API (limited free tier)
    echo -e "\n\n=== ViewDNS ==="
    curl -s "https://api.viewdns.info/reverseip/?host=$ip&apikey=freeapi&output=json" | \
      jq -r '.response.domains[]?' 2>/dev/null
    
    # Local DNS lookup
    echo -e "\n\n=== Local DNS ==="
    host "$ip" | awk '/pointer/ {print $NF}' 2>/dev/null
    
    echo -e "\n---"
}

export -f reverse_lookup

echo -e "\n${CYAN}[*] Running reverse IP lookup on potential real IPs...${NC}"
if [ -s "$output_dir/real_ips.txt" ]; then
    cat "$output_dir/real_ips.txt" | parallel -j 4 \
        "reverse_lookup {}" > "$output_dir/reverse_lookup.txt" 2>&1
    
    # Count discovered domains
    domain_count=$(grep -cE '===|pointer' "$output_dir/reverse_lookup.txt" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}[+]${NC} Found ${GREEN}$domain_count${NC} domains on these IPs"
else
    echo -e "  ${YELLOW}[!] No real IPs found for reverse lookup${NC}"
fi

# Step 10: Summary Report
echo -e "\n${GREEN}===================================================${NC}"
echo -e "${GREEN}                   SCAN SUMMARY                     ${NC}"
echo -e "${GREEN}===================================================${NC}"
echo -e "  Target Domain:       ${YELLOW}$domain${NC}"
echo -e "  Subdomains Found:    ${GREEN}$(wc -l < "$output_dir/subs_raw.txt")${NC}"
echo -e "  Live Hosts:          ${GREEN}$httpx_count${NC}"
echo -e "  Cloudflare IPs:      ${YELLOW}$cf_count${NC}"
echo -e "  Potential Real IPs:  ${GREEN}$real_count${NC}"
echo -e "  Reverse Lookup:      ${GREEN}$domain_count domains discovered${NC}"
echo -e "${GREEN}===================================================${NC}"

# Final output locations
echo -e "\n${CYAN}[*] Output Files:${NC}"
echo -e "  - Full subdomains:    $output_dir/subs_raw.txt"
echo -e "  - Resolved IPs:       $output_dir/resolved.txt"
echo -e "  - Live hosts:         $output_dir/httpx_results.csv"
echo -e "  - DNS Records:        $output_dir/dns_records.txt"
echo -e "  - Real IPs:           $output_dir/real_ips.txt"
echo -e "  - Reverse Lookup:     $output_dir/reverse_lookup.txt"
echo -e "  - Execution Log:      $output_dir/execution.log"

echo -e "\n${GREEN}[✓] Scan completed successfully!${NC}"
exit 0
