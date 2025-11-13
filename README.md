# t-recon-t

**Termux-Recon-Tool**

## Overview

`recon.sh` is a comprehensive reconnaissance script designed for Termux environments. It automates passive and active scanning tasks to gather intelligence on target domains or IPs, including DNS enumeration, subdomain discovery, HTTP probing, and vulnerability scanning.

> **Warning:** Use only on targets you own or have explicit permission to test.

---

## Features

- Passive DNS queries and WHOIS lookups  
- Subdomain discovery using `subfinder` and `amass`  
- URL harvesting via `gau` or `waybackurls` (optional)  
- HTTP probing with `httprobe` or `curl` fallback  
- Active scanning with `nmap` and `masscan` (enabled with `--active`)  
- Vulnerability scanning using `nuclei` (optional, requires active mode)  
- JSON report summary generation  
- Configurable concurrency and output management  
- Temporary file handling with auto-cleanup or retention option  

---

## Requirements

- Termux with Bash shell  
- Installed tools (conditionally checked): `whois`, `dig`, `nslookup`, `subfinder`, `amass`, `gau`, `waybackurls`, `httprobe`, `nmap`, `masscan`, `nuclei`  
- Go environment recommended to install Go-based tools  
- Permissions and network access to scan target  

---

## Installation

Download or clone the script to your Termux device and make it executable:

chmod +x recon.sh

text

Dependencies will be suggested by the script if missing.

---

## Usage

./recon.sh -t <target> [--active] [--out DIR] [--keep-temp] [--subdomains y|n] [--concurrency N]

text

### Options

- `-t, --target` — Target domain or IP address (**required**)  
- `--active` — Enable active scanning tools (prompts for confirmation)  
- `--out DIR` — Directory to save all output files  
- `--keep-temp` — Retain temporary files after execution  
- `--subdomains y|n` — Enable (y) or disable (n) passive subdomain discovery (default: y)  
- `--concurrency N` — Number of concurrent workers for probes (default: 10)  
- `--help, -h` — Display usage instructions  

### Examples

Passive scan of example.com, save output to a folder:

./recon.sh -t example.com --out ./recon_results

text

Active scan with nmap and nuclei enabled:

./recon.sh -t example.com --active

text

---

## Output

- Temporary data stored in a dedicated temp directory (cleaned up by default)  
- JSON summary report including subdomains, DNS records, responders, and scan metadata  
- If `--out` specified, all raw data files are saved to that directory  

---

## Notes

- Active scans require explicit permission from the target owner.  
- The script prepends `$HOME/go/bin` to PATH automatically if Go is installed, to help locate Go tools.  
- Use moderate concurrency values on mobile devices to avoid performance issues.  

---

## See MIT License

Provided as-is without warranty. Use responsibly against authorized targets only.

---
