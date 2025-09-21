import re
import subprocess
from discovery_scanners import *
from colorama import Fore, Style
from processors import *
from pathlib import Path
from helpers import *

class NxcScanner(DiscoveryScanner):

    def __init__(self, name: str, banner: str, subnet: str, outdir: Path):
        super().__init__(name, banner, subnet, outdir)  # Initialize superclass attributes
        self.ips: str | None = ""                      # New attribute for extracted IPs
        self.eternalblue_hosts = []             # New attribute for EternalBlue hosts (dicts)
        self.eternalblue_ips: str = ""               # New attribute for EternalBlue IPs only

    def run_discovery_scan(self) -> str | None:
        command = ["nxc", "smb", "--no-progress", self.subnet]
        raw_output = super().run(command)

        # if re.fullmatch(r"Running nxc against \d+ targets ━+ 100% \d+:\d+:\d+", raw_output):
        #     print(f"{Fore.YELLOW}[!]{self.banner} Did not return any hosts alive (subnet empty?)")
        #     self.results = None
        #     return
        if not raw_output:
            print(f"{Fore.YELLOW}[!]{self.banner} No hosts alive in {self.subnet}, skipping.{Style.RESET_ALL}")
            self.results = None
            return
        
        self.results = raw_output
        self.print_raw_output()
        return

    def run_discovery_scan_chunked(self, output_file: Path):
        """
        Run fping discovery on /24 subnets and append results incrementally.
        
        Args:
            output_file (Path): File to append results for each processed chunk.
        """
        all_results = []  # Optional: keep accumulated results in memory
        
        for chunk in IPUtils._chunk_subnet(self.subnet):  # generator yielding /24 subnets
            print(f"{Fore.CYAN}[*]{self.banner} Scanning chunk {chunk}...{Style.RESET_ALL}")
            
            command = ["nxc", "smb", "--no-progress", str(chunk)]
            process = subprocess.run(command, capture_output=True, text=True)
            raw_output = process.stdout.strip()

            
            # if re.fullmatch(r"Running nxc against \d+ targets ━+ 100% \d+:\d+:\d+", raw_output):
            if not raw_output:
                print(f"{Fore.YELLOW}[!]{self.banner} No hosts alive in {chunk}, skipping.{Style.RESET_ALL}")
                continue
                
            print(f"{Fore.GREEN}[+]{self.banner} Raw output from {chunk}:{Style.RESET_ALL}")
            print(raw_output)

            # Store in object
            if self.results:
                self.results += "\n" + raw_output
            else:
                self.results = raw_output
            
            
            # Append results incrementally to the file
            self.append(raw_output, output_file, str(chunk))


    def filter_eternalblue(self):
        if self.results:
            filtered_hosts = EternalBlueFilter(self.results).find_vulnerable_hosts()
            self.eternalblue_hosts = filtered_hosts
            self.eternalblue_ips = "\n".join(host["ip"] for host in filtered_hosts)
            return
    

    def save_eternalblue(self, output: str | list[dict[str, str]], output_file: Path):
        """Custom save method for NXCScanner"""
        
        if output:
            if isinstance(output, str):
                print(f"{Fore.GREEN}[+]{self.banner} Saving Potential EternalBlue IPs to {output_file}")
                output_file.write_text(output)

            elif isinstance(output, list):
                print(f"{Fore.GREEN}[+]{self.banner} Saving Potential EternalBlue hosts to {output_file}")
                with output_file.open("w") as f:
                    for host in output:
                        ip = host.get("ip", "Unknown IP")
                        reason = host.get("reason", "Unknown reason")
                        f.write(f"Host: {ip} - Reason: {reason}\n")
            else:
                print(f"{Fore.RED}[-][NXCScanner] Unsupported output type: {type(output)}")
                return None
    

    def extract_unique_domains_from_text(self, output: str) -> str:
        """
        Extract unique domain values from nxc output text.

        Args:
            content: Full text of an nxc output.

        Returns:
            A list of unique domain strings (in first-seen order). Empty list if none found.
        """
        domain_pattern = re.compile(r"\(domain:([^)]+)\)")
        domains = set()

        for line in output.splitlines():
            match = domain_pattern.search(line)
            if match:
                domain = match.group(1).strip()
                domains.add(domain)

        print(f"{Fore.GREEN}[+]{self.banner} Extracted {len(domains)} unique domains from nxc output.{Style.RESET_ALL}")

        return "\n".join(sorted(domains))


    def extract_unique_domains_from_file(self, input_file: Path) -> str:
        """
        Read an nxc output file and extract unique domains.

        Args:
            path: Path to the nxc output file.

        Returns:
            A list of unique domains.
        """
        text = input_file.read_text()
        return self.extract_unique_domains_from_text(text)
    
    def extract_smb_relay_targets(self, nxc_output: str):
        
        smb_relay_targets =[]

        nxc_output = nxc_output.strip()
        signing_false_pattern = re.compile(
            r"(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b).*?\(signing:False\)",
            re.IGNORECASE
        )

        for line in nxc_output.splitlines():
            match = signing_false_pattern.search(line)
            if match:
                host = match.group("ip")
                smb_relay_targets.append(host)
        
        return "\n".join(smb_relay_targets)
