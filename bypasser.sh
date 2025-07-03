\#!/bin/bash

# ==========================

# 🔍 Bypasser v1.1

# Author: 0xAbhi

# ==========================

RED='\033\[0;31m'
GREEN='\033\[0;32m'
CYAN='\033\[0;36m'
NC='\033\[0m'

# Banner

echo -e "\$CYAN"
cat << "EOF"
██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗███████╗██████╗
██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗█████╗  ██████╔╝
██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██╔══██╗
██████╔╝   ██║   ██║     ██║  ██║███████║███████║███████╗██║  ██║
╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝

```
             ⚡ Real IP Discovery Tool by 0xR4bbit/Abhi
```

EOF
echo -e "\$NC"

domain=\$1
if \[\[ -z "\$domain" ]]; then
echo -e "\${RED}\[!] Usage: \$0 target.com\${NC}"
exit 1
fi

cf\_ips='104.|172.|198.41.|199.27.|188.114.|141.101.|103.|162.|185.93.|190.93.|197.234.'

# Step 1: Subdomain Enum

echo -e "\${CYAN}\[\*] Enumerating subdomains for: \$domain\${NC}"
subfinder -d "\$domain" -silent > subs.txt

# Step 2: Resolve with dnsx

echo -e "\${CYAN}\[\*] Resolving IPs with dnsx...\${NC}"
dnsx -l subs.txt -a -resp -cname -silent > resolved.txt

# Step 3: HTTP probing

echo -e "\${CYAN}\[\*] Scanning subdomains with httpx...\${NC}"
httpx -l subs.txt -ip -title -web-server -tech-detect -status-code -silent > httpx\_results.txt

# Step 4: MX Records

echo -e "\${CYAN}\[\*] Checking MX records (possible IP leak)...\${NC}"

# Clear previous output

> mx\_records.txt

mx\_hosts=\$(dig MX "\$domain" +short | awk '{print \$2}' | sed 's/.\$//')

if \[\[ -z "\$mx\_hosts" ]]; then
echo "No MX records found for \$domain" | tee -a mx\_records.txt
else
echo "\$mx\_hosts" | while read mx; do
ip=\$(dig +short "\$mx" | head -n 1)
if \[\[ -n "\$ip" ]]; then
echo "\$mx -> \$ip" | tee -a mx\_records.txt
else
echo "\$mx -> No IP found" | tee -a mx\_records.txt
fi
done
fi

# Step 5: Zone Transfer attempt

echo -e "\${CYAN}\[\*] Trying DNS zone transfer (if misconfigured)...\${NC}"

# Clear previous output

> axfr\_results.txt

# Get authoritative name servers

ns\_servers=\$(dig NS "\$domain" +short)

if \[\[ -z "\$ns\_servers" ]]; then
echo "No name servers found for \$domain" | tee -a axfr\_results.txt
else
for ns in \$ns\_servers; do
echo -e "\${YELLOW}\[?] Trying AXFR on \$ns\${NC}" | tee -a axfr\_results.txt
dig axfr "\$domain" @"\$ns" >> axfr\_results.txt 2>&1
echo -e "\n---\n" >> axfr\_results.txt
done
fi

# Step 6: crt.sh passive enum

echo -e "\${CYAN}\[\*] Checking crt.sh for additional subdomains...\${NC}"
crt\_resp=\$(curl -s -A "Mozilla/5.0" "[https://crt.sh/?q=%25.\$domain\&output=json](https://crt.sh/?q=%25.$domain&output=json)")

if echo "\$crt\_resp" | jq empty 2>/dev/null; then
echo "\$crt\_resp" | jq -r '.\[].name\_value' | sort -u > crt.txt
else
echo -e "\${RED}\[!] crt.sh returned invalid JSON. Skipping...\${NC}"
echo "" > crt.txt
fi

# Step 7: Resolving crt.sh subdomains

echo -e "\${CYAN}\[\*] Resolving crt.sh subdomains...\${NC}"
dnsx -l crt.txt -a -resp -silent > crt\_resolved.txt

# Step 8: Extract potential real IPs

echo -e "\${CYAN}\[\*] Filtering potential real IPs (non-Cloudflare)...\${NC}"
grep -vE "\$cf\_ips" resolved.txt > real\_ips.txt
grep -vE "\$cf\_ips" crt\_resolved.txt >> real\_ips.txt
sort -u real\_ips.txt -o real\_ips.txt

# Step 9: Reverse IP Lookup (Hackertarget API)

echo -e "\${CYAN}\[\*] Running reverse IP lookup on filtered IPs...\${NC}"

> reverse\_lookup.txt

if \[ -s real\_ips.txt ]; then
while read ip; do
if \[\[ -n "\$ip" ]]; then
echo "\[>] \[\$ip]" >> reverse\_lookup.txt
resp=\$(curl -s "[https://api.hackertarget.com/reverseiplookup/?q=\$ip](https://api.hackertarget.com/reverseiplookup/?q=$ip)")
if echo "\$resp" | grep -q "No records found" || echo "\$resp" | grep -q "error"; then
echo "No domains found." >> reverse\_lookup.txt
else
echo "\$resp" >> reverse\_lookup.txt
fi
echo -e "\n---\n" >> reverse\_lookup.txt
fi
done < real\_ips.txt
else
echo "\[!] No real IPs found. Skipping reverse lookup." >> reverse\_lookup.txt
fi

# Done

echo -e "\${GREEN}\[+] Done. Check the following files for output:\${NC}"
echo -e " - subs.txt            → from subfinder"
echo -e " - resolved.txt        → resolved subdomain IPs"
echo -e " - httpx\_results.txt   → headers, tech info"
echo -e " - mx\_records.txt      → email MX records"
echo -e " - axfr\_results.txt    → AXFR results (if any)"
echo -e " - crt.txt             → crt.sh subdomains"
echo -e " - crt\_resolved.txt    → resolved crt.sh IPs"
echo -e " - real\_ips.txt        → filtered non-CF IPs (likely real)"
echo -e " - reverse\_lookup.txt  → domains hosted on real IPs"

exit 0
