import argparse
import subprocess
import shutil
import os
import sys
import json
from datetime import datetime

# Configuration
TOOLS = ["subfinder", "dnsx", "naabu", "httpx", "katana", "nuclei"]
# Get script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR_BASE = os.path.join(SCRIPT_DIR, "output")
BIN_DIR = os.path.join(SCRIPT_DIR, "bin")
WORDLIST_DIR = os.path.join(SCRIPT_DIR, "wordlists")

# Add project bin to PATH
os.environ["PATH"] += os.pathsep + BIN_DIR + os.pathsep + os.path.expanduser("~/go/bin")

class PDRecon:
    def __init__(self, target, mode, nuclei_enabled, custom_wordlist=None):
        self.target = target
        self.mode = mode.lower()
        self.nuclei_enabled = nuclei_enabled
        self.custom_wordlist = custom_wordlist
        self.workspace = self.create_workspace()
        self.commands_executed = []
        self.findings = {}

    def log_command(self, command):
        cmd_str = ' '.join(command)
        print(f"[+] Executing: {cmd_str}")
        self.commands_executed.append(cmd_str)

    def check_and_install_tools(self):
        print("[*] Checking tools...")
        os.makedirs(BIN_DIR, exist_ok=True)
        
        for tool in TOOLS:
            if shutil.which(tool):
                print(f"[+] {tool} found.")
                continue
            
            # Check project/bin explicitly if not in PATH (though PATH should cover it)
            tool_path = os.path.join(BIN_DIR, tool)
            if os.path.exists(tool_path):
                 print(f"[+] {tool} found in project/bin.")
                 continue

            print(f"[-] {tool} not found. Installing to {BIN_DIR}...")
            # Map tool names to repo paths if needed (most are straightforward)
            repo = f"github.com/projectdiscovery/{tool}/v2/cmd/{tool}@latest"
            if tool == "dnsx": repo = f"github.com/projectdiscovery/{tool}/cmd/{tool}@latest"
            if tool == "httpx": repo = f"github.com/projectdiscovery/{tool}/cmd/{tool}@latest"
            if tool == "katana": repo = f"github.com/projectdiscovery/{tool}/cmd/{tool}@latest"
            if tool == "nuclei": repo = f"github.com/projectdiscovery/{tool}/v3/cmd/{tool}@latest"
            
            env = os.environ.copy()
            env["GOBIN"] = BIN_DIR
            try:
                subprocess.run(["go", "install", "-v", repo], check=True, env=env)
                print(f"[+] {tool} installed successfully.")
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to install {tool}: {e}")
                sys.exit(1)

    def create_workspace(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ws = os.path.join(OUTPUT_DIR_BASE, f"{self.target}_{timestamp}")
        os.makedirs(ws, exist_ok=True)
        print(f"[+] Workspace created: {ws}")
        return ws

    def run_cmd(self, command, output_file=None, input_data=None):
        self.log_command(command)
        try:
            process = subprocess.run(command, input=input_data, capture_output=True, text=True, check=True, timeout=600)
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(process.stdout)
            return process.stdout
        except subprocess.CalledProcessError as e:
            print(f"[-] Command failed: {e}")
            return None
        except subprocess.TimeoutExpired:
            print(f"[-] Command timed out: {' '.join(command)}")
            return None

    def run(self):
        print(f"[*] Starting {self.mode.upper()} scan on {self.target}")
        
        # 1. Subdomain Discovery
        subdomains_file = os.path.join(self.workspace, "subdomains.txt")
        cmd_sub = ["subfinder", "-d", self.target, "-silent", "-o", subdomains_file]
        self.run_cmd(cmd_sub)
        
        if not os.path.exists(subdomains_file) or os.path.getsize(subdomains_file) == 0:
            print("[-] No subdomains found. Using target as single domain.")
            with open(subdomains_file, 'w') as f:
                f.write(self.target + "\n")

        # 2. DNS Resolution (Active Subdomains)
        active_subs_file = os.path.join(self.workspace, "active_subdomains.txt")
        # Read subdomains to pass as input
        with open(subdomains_file, 'r') as f:
            subdomains_data = f.read()

        # dnsx needs input via stdin if not using -l. Pass input_data.
        cmd_dns = ["dnsx", "-silent", "-r", "8.8.8.8,1.1.1.1", "-o", active_subs_file]
        
        if self.mode == "aggressive":
             # Bruteforce
            wordlist = self.custom_wordlist
            if not wordlist:
                # Fallback to default wordlist in project/wordlists
                default_wl = os.path.join(WORDLIST_DIR, "subdomains.txt")
                if os.path.exists(default_wl):
                    wordlist = default_wl
            
            if wordlist:
                print(f"[*] Aggressive Mode: Running DNS Bruteforce with {wordlist}")
                cmd_dns.extend(["-w", wordlist])
            else:
                print("[!] Aggressive Mode: No wordlist found for DNS bruteforce. Skipping.")

        self.run_cmd(cmd_dns, input_data=subdomains_data)

        # 3. Port Scanning (Naabu) - ONLY Medium/Aggressive
        ports_file = os.path.join(self.workspace, "open_ports.txt")
        if self.mode in ["medium", "aggressive"]:
            # naabu -list active_subdomains.txt ...
            cmd_naabu = ["naabu", "-list", active_subs_file, "-silent", "-o", ports_file]
            if self.mode == "medium":
                cmd_naabu.extend(["-top-ports", "100"])
            elif self.mode == "aggressive":
                cmd_naabu.extend(["-top-ports", "1000"]) # or -p -
            
            self.run_cmd(cmd_naabu)
            if os.path.exists(ports_file) and os.path.getsize(ports_file) > 0:
                target_list_for_httpx = ports_file
            else:
                print("[-] Port scan failed or no ports found. Falling back to subdomains for HTTP probing.")
                target_list_for_httpx = active_subs_file
        else:
            target_list_for_httpx = active_subs_file # Use subdomains for Low mode

        # 4. HTTP Probing & Tech Detect (HTTPX)
        technologies_file = os.path.join(self.workspace, "technologies.txt")
        # Read targets to pass as input
        httpx_data = ""
        if os.path.exists(target_list_for_httpx):
            with open(target_list_for_httpx, 'r') as f:
                httpx_data = f.read()
        
        # httpx needs to read from stdin if no -l. Pass input_data.
        cmd_httpx = ["httpx", "-silent", "-o", technologies_file]
        # Common flags
        cmd_httpx.extend(["-title", "-tech-detect", "-status-code", "-ip"])
        
        if self.mode == "low":
            pass # default is fine, fast
        elif self.mode == "aggressive":
            cmd_httpx.extend(["-follow-redirects"]) 
        
        self.run_cmd(cmd_httpx, input_data=httpx_data)

        # Extract URLs for Crawling/Scanning
        live_urls_file = os.path.join(self.workspace, "live_urls.txt")
        live_urls = []
        if os.path.exists(technologies_file):
            with open(technologies_file, 'r') as f:
                for line in f:
                    # simplistic extraction: first part of line
                    parts = line.split()
                    if parts:
                        live_urls.append(parts[0])
            with open(live_urls_file, 'w') as f:
                f.write('\n'.join(live_urls))

        # 5. Crawling (Katana)
        crawled_file = os.path.join(self.workspace, "crawled.txt")
        if live_urls:
            cmd_katana = ["katana", "-list", live_urls_file, "-silent", "-o", crawled_file]
            
            if self.mode == "low":
                print("[*] Low mode: Skipping active crawling.")
                cmd_katana = None
            elif self.mode == "medium":
                cmd_katana.extend(["-d", "2", "-jc"])
            elif self.mode == "aggressive":
                cmd_katana.extend(["-d", "5", "-jc", "-js-crawl"])
            
            if cmd_katana:
                self.run_cmd(cmd_katana)

        # 6. Vulnerability Scanning (Nuclei)
        vulns_file = os.path.join(self.workspace, "vulns.txt")
        
        if not self.nuclei_enabled:
            print("[*] Nuclei scanning disabled (use --nuclei to enable).")
        else:
            # Determine target list for nuclei. Usually scanned URLs + crawled URLs.
            nuclei_targets_file = os.path.join(self.workspace, "nuclei_targets.txt")
            concat_files = [live_urls_file]
            if os.path.exists(crawled_file):
                concat_files.append(crawled_file)
            
            # Merge files
            with open(nuclei_targets_file, 'w') as outfile:
                for fname in concat_files:
                    if os.path.exists(fname):
                        with open(fname) as infile:
                            outfile.write(infile.read())
                            outfile.write("\n")

            cmd_nuclei = ["nuclei", "-l", nuclei_targets_file, "-silent", "-o", vulns_file]
            
            if self.mode == "medium":
                cmd_nuclei.extend(["-t", "technologies", "-t", "misconfiguration", "-severity", "low,medium"])
            elif self.mode == "aggressive":
                # Default templates (all) + criticals?
                # or just don't filter.
                cmd_nuclei.extend(["-severity", "low,medium,high,critical"])
            
            self.run_cmd(cmd_nuclei)

        self.generate_report()

    def generate_report(self):
        report_path = os.path.join(self.workspace, "REPORT.md")
        with open(report_path, 'w') as f:
            f.write(f"# Penetration Testing Report: {self.target}\n")
            f.write(f"**Date**: {datetime.now()}\n")
            f.write(f"**Mode**: {self.mode}\n")
            f.write(f"**Nuclei Enabled**: {self.nuclei_enabled}\n\n")

            f.write("## 1. Executive command Log\n")
            f.write("```bash\n")
            for cmd in self.commands_executed:
                f.write(f"{cmd}\n")
            f.write("```\n\n")

            f.write("## 2. Artifacts Summary\n")
            
            # Subdomains
            sub_file = os.path.join(self.workspace, "active_subdomains.txt")
            if os.path.exists(sub_file):
                count = sum(1 for line in open(sub_file))
                f.write(f"- **Active Subdomains**: {count}\n")
            
            # Ports
            ports_file = os.path.join(self.workspace, "open_ports.txt")
            if os.path.exists(ports_file):
                count = sum(1 for line in open(ports_file))
                f.write(f"- **Open Ports**: {count}\n")

            # Tech
            tech_file = os.path.join(self.workspace, "technologies.txt")
            if os.path.exists(tech_file):
                count = sum(1 for line in open(tech_file))
                f.write(f"- **Live Hosts / Tech Detected**: {count}\n")

            # Vulns
            vuln_file = os.path.join(self.workspace, "vulns.txt")
            if os.path.exists(vuln_file):
                count = sum(1 for line in open(vuln_file))
                f.write(f"- **Vulnerabilities Found**: {count}\n")
            
            f.write("\n## 3. Findings Detail\n")
            
            # List technologies
            if os.path.exists(tech_file):
                f.write("### Technologies Detected\n")
                f.write("```\n")
                with open(tech_file) as tf:
                    f.write(tf.read())
                f.write("```\n\n")
            
            # List Vulns
            if os.path.exists(vuln_file) and os.path.getsize(vuln_file) > 0:
                f.write("### Vulnerabilities\n")
                f.write("```\n")
                with open(vuln_file) as vf:
                    f.write(vf.read())
                f.write("```\n")
            elif self.nuclei_enabled:
                f.write("### Vulnerabilities\nNo vulnerabilities found.\n")
            else:
                f.write("### Vulnerabilities\nSkipped (Nuclei disabled).\n")

        print(f"[+] Report generated: {report_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PD Comprehensive Recon Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-m", "--mode", choices=["low", "medium", "aggressive"], default="low", help="Scan mode")
    parser.add_argument("--nuclei", action="store_true", help="Enable Nuclei vulnerability scanning")
    parser.add_argument("--wordlist", help="Custom wordlist for DNS bruteforce (Aggressive mode)")
    args = parser.parse_args()

    recon = PDRecon(args.domain, args.mode, args.nuclei, args.wordlist)
    recon.check_and_install_tools()
    recon.run()
