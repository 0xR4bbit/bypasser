# Bypasser 🔍

**Bypasser** is a powerful real IP discovery tool built by [0xAbhi](https://github.com/0xR4bbit) to uncover the actual server IP addresses behind Cloudflare, WAFs, and other CDN services.

---

## ✨ Features

- 🕹️ Subdomain enumeration using:
  - `subfinder`
  - `crt.sh` (passive cert scraping)
- 🗰️ IP resolution with `dnsx`
- 🔎 HTTP probing with `httpx` (title, server, tech, IP)
- 📧 MX record leak check with `dig`
- 🔑 DNS zone transfer testing (AXFR)
- 🪫 Cloudflare IP range filtering
- 🔄 Reverse IP lookup via Hackertarget API

---

## ⚖️ Requirements

Install the following tools (if not already):

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo apt install jq dnsutils curl parallel ipcalc -y
```

---

## ⚡ Usage

```bash
git clone https://github.com/0xR4bbit/bypasser.git
chmod +x bypasser.sh
./bypasser.sh target.com
```

> Replace `target.com` with the domain you want to scan.

---

## 📁 Output Files

- `subs.txt`            → Subdomains (subfinder)
- `resolved.txt`        → Resolved IPs from subdomains
- `httpx_results.txt`   → HTTP fingerprinting results
- `mx_records.txt`      → MX record IPs
- `axfr_results.txt`    → AXFR zone transfer dump
- `crt.txt`             → crt.sh subdomains
- `crt_resolved.txt`    → Resolved IPs from crt.sh
- `real_ips.txt`        → Filtered non-Cloudflare IPs
- `reverse_lookup.txt`  → Reverse IP lookup results

---

## 📄 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

- Created with ❤️ by [0xAbhi](https://github.com/0xR4bbit)

