\#!/bin/bash

# ======================================================

# 🔍 Bypasser v2.2 - CloudFlare & CDN Bypass Toolkit

# Author: 0xR4bbit/Abhi

# ======================================================

RED='\033\[0;31m'
GREEN='\033\[0;32m'
CYAN='\033\[0;36m'
YELLOW='\033\[1;33m'
BLUE='\033\[1;34m'
NC='\033\[0m'

# Banner

echo -e "\${CYAN}"
cat << "EOF"
██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗███████╗██████╗
██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗█████╗  ██████╔╝
██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██╔══██╗
██████╔╝   ██║   ██║     ██║  ██║███████║███████║███████╗██║  ██║
╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
EOF
echo -e "\${BLUE}             ⚡ Real IP Discovery & CDN Bypass Toolkit by 0xR4bbit\${NC}"

# Check if running as root

if \[\[ \$EUID -eq 0 ]]; then
echo -e "\${YELLOW}\[!] Warning: Running as root is not recommended for security reasons.\${NC}"
sleep 2
fi

# Dependency check

check\_dependency() {
if ! command -v "\$1" &> /dev/null; then
echo -e "\${RED}\[✗] \$1 not found. Please install it:\${NC}"

```
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
```

}

domain="\$1"
if \[\[ -z "\$domain" ]]; then
echo -e "\${RED}\[!] Usage: \$0 target.com\${NC}"
exit 1
fi

# Validate domain format

if ! \[\[ "\$domain" =\~ ^\[a-zA-Z0-9]\[a-zA-Z0-9.-]+.\[a-zA-Z]{2,}\$ ]]; then
echo -e "\${RED}\[✗] Invalid domain format: \$domain\${NC}"
exit 1
fi

# Required tools

tools=("subfinder" "dnsx" "httpx" "dig" "curl" "jq" "parallel" "ipcalc")
echo -e "\${CYAN}\[\*] Verifying dependencies...\${NC}"
for tool in "\${tools\[@]}"; do
check\_dependency "\$tool"
echo -e "  \${GREEN}\[✓]\${NC} \$tool"
done

# Cloudflare IP ranges (updated 2023)

cf\_ips=(
"104.16.0.0/12" "172.64.0.0/13" "173.245.48.0/20" "103.21.244.0/22"
"103.22.200.0/22" "103.31.4.0/22" "141.101.64.0/18" "108.162.192.0/18"
"190.93.240.0/20" "188.114.96.0/20" "197.234.240.0/22" "198.41.128.0/17"
"162.158.0.0/15" "172.64.0.0/13" "131.0.72.0/22"
)

# Create output directory with timestamp

timestamp=\$(date +"%Y%m%d-%H%M%S")
output\_dir="bypasser\_\${domain}\_\${timestamp}"
mkdir -p "\$output\_dir"
echo -e "\${CYAN}\[\*] Output directory: \${GREEN}\$output\_dir\${NC}"

# Log file

log\_file="\$output\_dir/execution.log"
exec > >(tee -a "\$log\_file") 2>&1

# Step 1: Subdomain Enumeration

echo -e "\n\${CYAN}\[*] Enumerating subdomains for: \${YELLOW}\$domain\${NC}"
subfinder -d "\$domain" -silent | tee "\$output\_dir/subs\_raw\.txt" | wc -l |&#x20;
awk -v CYAN="\$CYAN" -v GREEN="\$GREEN" -v NC="\$NC"&#x20;
'{printf CYAN"\[*] Found " GREEN"%d" CYAN" subdomains" NC "\n", \$1}'

# Step 2: Resolve with dnsx (A records only)

echo -e "\${CYAN}\[\*] Resolving IPs with dnsx...\${NC}"
dnsx -l "\$output\_dir/subs\_raw\.txt" -a -resp -silent -o "\$output\_dir/resolved.txt"
resolved\_count=\$(grep -c . "\$output\_dir/resolved.txt" 2>/dev/null || echo 0)
echo -e "  \${GREEN}\[+]\${NC} Resolved \${GREEN}\$resolved\_count\${NC} subdomains"

# Step 3: HTTP probing

echo -e "\${CYAN}\[\*] Scanning subdomains with httpx...\${NC}"
httpx -l "\$output\_dir/subs\_raw\.txt" -ip -title -web-server -tech-detect -status-code -silent&#x20;
-o "\$output\_dir/httpx\_results.txt" -csv-output "\$output\_dir/httpx\_results.csv"
httpx\_count=\$(grep -c . "\$output\_dir/httpx\_results.txt" 2>/dev/null || echo 0)
echo -e "  \${GREEN}\[+]\${NC} Found \${GREEN}\$httpx\_count\${NC} live hosts"

# Step 4: DNS Records Check

echo -e "\${CYAN}\[\*] Checking critical DNS records...\${NC}"
echo -e "\${BLUE}  MX Records:\${NC}" | tee -a "\$output\_dir/dns\_records.txt"
dig mx "\$domain" +short | tee -a "\$output\_dir/dns\_records.txt"
echo -e "\n\${BLUE}  TXT Records:\${NC}" | tee -a "\$output\_dir/dns\_records.txt"
dig txt "\$domain" +short | tee -a "\$output\_dir/dns\_records.txt"
echo -e "\n\${BLUE}  Name Servers:\${NC}" | tee -a "\$output\_dir/dns\_records.txt"
dig ns "\$domain" +short | tee -a "\$output\_dir/dns\_records.txt"

# Step 5: Zone Transfer attempt (IPv4 only with TCP)

echo -e "\n\${CYAN}\[\*] Trying DNS zone transfer...\${NC}"

> "\$output\_dir/axfr\_results.txt"
> nameservers=(\$(dig ns "\$domain" +short))
> if \[ \${#nameservers\[@]} -eq 0 ]; then
> echo -e "  \${RED}\[✗] No nameservers found for \$domain\${NC}"
> else
> for ns in "\${nameservers\[@]}"; do
> echo -e "\${YELLOW}\[>] Trying AXFR on \$ns\${NC}" | tee -a "\$output\_dir/axfr\_results.txt"
> dig +tcp axfr "\$domain" @"\$ns" >> "\$output\_dir/axfr\_results.txt" 2>&1
> echo -e "\n---\n" >> "\$output\_dir/axfr\_results.txt"
> done

```
if grep -q "Transfer failed" "$output_dir/axfr_results.txt" || ! grep -q "IN" "$output_dir/axfr_results.txt"; then
    echo -e "  ${YELLOW}[!] No successful zone transfers${NC}"
else
    echo -e "  ${GREEN}[✓] SUCCESS: Zone transfer completed!${NC}"
fi
```

fi

# Step 6: crt.sh passive enum

echo -e "\n\${CYAN}\[*] Checking crt.sh for additional subdomains...\${NC}"
curl -s "[https://crt.sh/?q=%25.\$domain\&output=json](https://crt.sh/?q=%25.$domain&output=json)" | jq -r '.\[].name\_value' |&#x20;
sed 's/^\*.//;s/^.//' | sort -u | tee "\$output\_dir/crt.txt" | wc -l |&#x20;
awk -v CYAN="\$CYAN" -v GREEN="\$GREEN" -v NC="\$NC"&#x20;
'{printf CYAN"\[*] Found " GREEN"%d" CYAN" new subdomains from crt.sh" NC "\n", \$1}'

echo -e "\${CYAN}\[\*] Resolving crt.sh subdomains...\${NC}"
dnsx -l "\$output\_dir/crt.txt" -a -resp -silent -o "\$output\_dir/crt\_resolved.txt"
crt\_count=\$(grep -c . "\$output\_dir/crt\_resolved.txt" 2>/dev/null || echo 0)
echo -e "  \${GREEN}\[+]\${NC} Resolved \${GREEN}\$crt\_count\${NC} crt.sh subdomains"

# Step 8: Extract potential real IPs

echo -e "\n\${CYAN}\[\*] Filtering potential real IPs...\${NC}"
cat "\$output\_dir/resolved.txt" "\$output\_dir/crt\_resolved.txt" |&#x20;
grep -Eo '\[0-9]{1,3}.\[0-9]{1,3}.\[0-9]{1,3}.\[0-9]{1,3}' |&#x20;
sort -u > "\$output\_dir/all\_ips.txt"

> "\$output\_dir/cf\_ips.txt"
> "\$output\_dir/real\_ips.txt"

for ip in \$(cat "\$output\_dir/all\_ips.txt"); do
is\_cf=false
for range in "\${cf\_ips\[@]}"; do
if ipcalc -n "\$ip" "\$range" 2>/dev/null | grep -q "Network:"; then
echo "\$ip" >> "\$output\_dir/cf\_ips.txt"
is\_cf=true
break
fi
done
if ! \$is\_cf; then
echo "\$ip" >> "\$output\_dir/real\_ips.txt"
fi

done

cf\_count=\$(wc -l < "\$output\_dir/cf\_ips.txt")
real\_count=\$(wc -l < "\$output\_dir/real\_ips.txt")
echo -e "  \${GREEN}\[+]\${NC} Cloudflare IPs: \${YELLOW}\$cf\_count\${NC}"
echo -e "  \${GREEN}\[+]\${NC} Potential real IPs: \${GREEN}\$real\_count\${NC}"

echo -e "\n\${CYAN}\[\*] Running reverse IP lookup on potential real IPs...\${NC}"

> "\$output\_dir/reverse\_lookup.txt"
> if \[ -s "\$output\_dir/real\_ips.txt" ]; then
> while read -r ip; do
> echo -e "\n\[>] Reverse lookup for \$ip" >> "\$output\_dir/reverse\_lookup.txt"
> echo "=== Local DNS ===" >> "\$output\_dir/reverse\_lookup.txt"
> host "\$ip" | awk '/pointer/ {print \$NF}' >> "\$output\_dir/reverse\_lookup.txt"
> echo -e "\n---" >> "\$output\_dir/reverse\_lookup.txt"
> done < "\$output\_dir/real\_ips.txt"
> domain\_count=\$(grep -c "pointer" "\$output\_dir/reverse\_lookup.txt")
> echo -e "  \${GREEN}\[+]\${NC} Found \${GREEN}\$domain\_count\${NC} domains on these IPs"
> else
> echo -e "  \${YELLOW}\[!] No real IPs found for reverse lookup\${NC}"
> fi

# Step 10: Summary Report

echo -e "\n\${GREEN}===================================================\${NC}"
echo -e "\${GREEN}                   SCAN SUMMARY                     \${NC}"
echo -e "\${GREEN}===================================================\${NC}"
echo -e "  Target Domain:       \${YELLOW}\$domain\${NC}"
echo -e "  Subdomains Found:    \${GREEN}\$(wc -l < "\$output\_dir/subs\_raw\.txt")\${NC}"
echo -e "  Live Hosts:          \${GREEN}\$httpx\_count\${NC}"
echo -e "  Cloudflare IPs:      \${YELLOW}\$cf\_count\${NC}"
echo -e "  Potential Real IPs:  \${GREEN}\$real\_count\${NC}"
echo -e "  Reverse Lookup:      \${GREEN}\$domain\_count domains discovered\${NC}"
echo -e "\${GREEN}===================================================\${NC}"

echo -e "\n\${CYAN}\[\*] Output Files:\${NC}"
echo -e "  - Full subdomains:     \$output\_dir/subs\_raw\.txt"
echo -e "  - Resolved IPs:        \$output\_dir/resolved.txt"
echo -e "  - Live hosts (TXT):    \$output\_dir/httpx\_results.txt"
echo -e "  - Live hosts (CSV):    \$output\_dir/httpx\_results.csv"
echo -e "  - All IPs:             \$output\_dir/all\_ips.txt"
echo -e "  - Cloudflare IPs:      \$output\_dir/cf\_ips.txt"
echo -e "  - Potential Real IPs:  \$output\_dir/real\_ips.txt"
echo -e "  - DNS Records:         \$output\_dir/dns\_records.txt"
echo -e "  - AXFR Results:        \$output\_dir/axfr\_results.txt"
echo -e "  - crt.sh Subdomains:   \$output\_dir/crt.txt"
echo -e "  - crt.sh Resolved IPs: \$output\_dir/crt\_resolved.txt"
echo -e "  - Reverse Lookup:      \$output\_dir/reverse\_lookup.txt"
echo -e "  - Execution Log:       \$output\_dir/execution.log"

echo -e "\n\${GREEN}\[✓] Scan completed successfully!\${NC}"
exit 0
