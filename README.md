# pd_recon

![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![ProjectDiscovery](https://img.shields.io/badge/powered%20by-projectdiscovery-blue)

**pd_recon.py** is a comprehensive automated reconnaissance tool built exclusively using **ProjectDiscovery** tools.

## Installation

```bash
git clone https://github.com/alterpix/pd_recon.git
cd pd_recon
# Ensure Python 3 and Go are installed
```

### Usage
Run the tool from the project directory:

```bash
# Basic Usage (Low Mode - Passive)
python3 pd_recon.py -d target.com

# Medium Mode (Active Port Scan & Crawling, Nuclei disabled by default)
python3 pd_recon.py -d target.com -m medium

# Medium Mode WITH Nuclei Scanning
python3 pd_recon.py -d target.com -m medium --nuclei

# Aggressive Mode (Full Port Scan, Deep Crawl, DNS Bruteforce)
# Nuclei disabled by default, add --nuclei to enable
python3 pd_recon.py -d target.com -m aggressive --nuclei

# Aggressive Mode with Custom Wordlist for DNS Bruteforce
python3 pd_recon.py -d target.com -m aggressive --wordlist /path/to/wordlist.txt
```

### Modes
1.  **Low (Default)**:
    *   Passive Subdomain Discovery (`subfinder`)
    *   DNS Resolution (`dnsx`)
    *   Tech Detection (`httpx`)
    *   *Stealthy, good for initial recon.*

2.  **Medium**:
    *   **Active** Port Scanning (`naabu`, top 100 ports)
    *   **Active** Crawling (`katana`, depth 2)
    *   *Optional*: Vulnerability Scanning (`nuclei`) with `--nuclei` flag.

3.  **Aggressive**:
    *   **Full** Port Scanning (`naabu`, top 1000 ports)
    *   **Deep** Crawling (`katana`, depth 5, JS crawl)
    *   **DNS Bruteforce** (`dnsx` with wordlist)
    *   *Optional*: Vulnerability Scanning (`nuclei`) with `--nuclei` flag.

### Features
*   **Auto-Installation**: Automatically downloads missing tools to `project/bin`.
*   **Wordlist Integration**: Uses SecLists (`shubs-subdomains.txt`) by default for DNS bruteforcing if available in `project/wordlists`.
*   **Anti-Hang Mechanisms**: Uses stdin piping for `dnsx` and `httpx` to prevent freezing on large inputs.
*   **Comprehensive Reports**: Generates `REPORT.md` with active subdomain counts, open ports, technologies, and vulnerabilities.
*   **Structured Artifacts**: Saves results in `output/<target>_<timestamp>/`:
    -   `subdomains.txt`
    -   `active_subdomains.txt`
    -   `open_ports.txt`
    -   `technologies.txt`
    -   `crawled.txt`
    -   `vulns.txt`
    -   `REPORT.md`


