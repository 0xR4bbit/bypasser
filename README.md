# 🔍 Bypasser v2.3 - Real IP Discovery & CDN Bypass Toolkit

A comprehensive and automated reconnaissance toolkit to **discover real IP addresses behind Cloudflare or other CDN/WAF-protected domains** using both passive and active techniques. Built for penetration testers, bug bounty hunters, and red teamers.

---

## 📌 Overview

Web applications often use **CDNs (Content Delivery Networks)** like **Cloudflare** to mask their real IPs and mitigate attacks. `Bypasser` attempts to uncover these real IPs using:

* Subdomain enumeration (active/passive)
* DNS resolution and zone transfer
* Cloudflare IP filtering
* Reverse IP lookups
* Web probing and metadata analysis

---

## ✨ Features

| Feature                      | Description                                           |
| ---------------------------- | ----------------------------------------------------- |
| 🔎 Subdomain Enumeration     | Uses `subfinder` and `crt.sh` to identify subdomains  |
| 🌐 DNS Resolution            | Resolves A records using `dnsx`                       |
| 🚀 HTTP Probing              | Identifies live hosts and technologies using `httpx`  |
| 📅 DNS Records Extraction    | Fetches MX, TXT, and NS records via `dig`             |
| 🔓 Zone Transfer Detection   | Tries AXFR on nameservers (TCP only)                  |
| 🔥 Cloudflare IP Filtering   | Detects and excludes IPs matching Cloudflare's ranges |
| 🧑‍🧐 Real IP Identification | Filters only the potential real backend IPs           |
| 🕵️‍♂️ Reverse IP Lookup     | Enumerates domains hosted on discovered real IPs      |
| 📁 Output Management         | Structured per-run output folder with all data        |
| ✅ Log File & Summary         | Provides detailed execution log and scan summary      |

---

## 📂 Output Structure

Each scan is stored in a timestamped directory like:

```
bypasser_example.com_20250703-225837/
├── subs_raw.txt            # Subdomains from Subfinder
├── resolved.txt            # IPs resolved with dnsx
├── httpx_results.txt       # Raw HTTPx probing output
├── httpx_results.csv       # HTTPx CSV output
├── crt.txt                 # Subdomains from crt.sh
├── crt_resolved.txt        # Resolved crt.sh subdomains
├── all_ips.txt             # Combined IP list
├── cf_ips.txt              # Cloudflare IPs detected
├── real_ips.txt            # Potential real IPs
├── dns_records.txt         # MX, TXT, NS records
├── axfr_results.txt        # AXFR zone transfer logs
├── reverse_lookup.txt      # Reverse DNS/API results
└── execution.log           # Full scan log
```

---

## 🚀 Installation

### ⚙️ Dependencies

Install the required tools using the following commands:

```bash
# Go-based tools (you must have Go installed)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# APT-based tools (for Debian/Kali/Ubuntu)
sudo apt install -y jq curl dnsutils parallel ipcalc
```

Make sure all tools are in your `$PATH`.

---

## 📆 Usage

```bash
chmod +x bypasser.sh
./bypasser.sh <domain.com>
```

### Example:

```bash
./bypasser.sh zonetransfer.me
```

This will:

* Enumerate subdomains
* Resolve IPs and scan web services
* Extract DNS records
* Attempt DNS zone transfers
* Filter Cloudflare IPs
* Identify real IPs and perform reverse lookup
* Save all output in a timestamped folder

---

## 🧠 Techniques Used

* **Passive Recon**: subfinder, crt.sh
* **Active Recon**: DNS resolution, zone transfer (AXFR), httpx probing
* **Cloudflare Filtering**: IP ranges hardcoded for validation
* **Reverse IP Lookup**: HackerTarget, ViewDNS, and local DNS

---

## 🐳 Docker Support *(Coming Soon)*

We are working on a lightweight Docker image so you can run this with:

```bash
docker run --rm -v $(pwd):/data bypasser <target.com>
```

✅ Stay tuned for `.deb` packaging support for easy APT installs.

---

## 📜 Example Output

```
[*] Enumerating subdomains for: example.com
[*] Found 64 subdomains
[*] Resolving IPs with dnsx...
[+] Resolved 52 subdomains
[*] Scanning subdomains with httpx...
[+] Found 20 live hosts
[*] Trying DNS zone transfer...
[✓] SUCCESS: Zone transfer completed!
[*] Filtering potential real IPs...
[+] Cloudflare IPs: 8
[+] Potential real IPs: 3
[*] Running reverse IP lookup...
[+] Found 12 domains on real IPs

Scan completed successfully! ✅
```

---

## 🧑‍💻 Author

**Bypasser v2.3**
Built by **0xR4bbit / Abhi**
🔗 Ethical Hacker | Security Researcher | Bug Bounty Hunter

> GitHub: [github.com/0xR4bbit](https://github.com/0xR4bbit)

---

## ⚠️ Disclaimer

> This tool is intended **only for educational, research, and authorized penetration testing purposes**.
> **Do not** use against targets you do not own or have explicit written permission to test.
> Misuse of this tool may violate laws and terms of service. The author is **not responsible** for any misuse or damages.

---

## 📬 Feedback & Contributions

Found a bug or have suggestions?
Feel free to open an [Issue](https://github.com/0xR4bbit/bypasser/issues) or submit a PR.
Pull requests for new features, bug fixes, and enhancements are welcome!

---

## 📖 License

MIT License — Free for personal and commercial use.
Please give credit if you reuse or modify this in your own projects.

---

## 🔄 Changelog (v2.3)

- Fixed output file discrepancies
- Enhanced Cloudflare IP filtering
- Improved error handling
- Added CSV output for httpx results
- Optimized reverse IP lookup
- Updated documentation and examples

---
```

### Key Updates:

1. **Version Update**: Changed from v2.2 to v2.3 to reflect the latest improvements
2. **Output Structure**: Updated to match actual file outputs (added `all_ips.txt`, fixed httpx outputs)
3. **Changelog**: Added v2.3 changelog section highlighting the recent fixes
4. **Feature Clarification**: Enhanced descriptions of CDN bypass techniques
5. **Example Output**: Improved formatting for better readability
6. **Installation**: Added missing `ipcalc` to dependencies
7. **Bug Fixes**: Noted the resolution of output file discrepancies

This updated README accurately reflects the current capabilities and output structure of the tool, making it easier for users to understand what to expect from each scan. The changelog section also helps track improvements across versions.
