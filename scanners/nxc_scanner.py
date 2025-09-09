import re
from scanners import *
from colorama import Fore, Style
from processors import *
from pathlib import Path

class NxcScanner(DiscoveryScanner):

    def __init__(self, name: str, banner: str, subnet: str, outdir: Path):
        super().__init__(name, banner, subnet, outdir)  # Initialize superclass attributes
        self.ips: str | None = ""                      # New attribute for extracted IPs
        self.eternalblue_hosts = []             # New attribute for EternalBlue hosts (dicts)
        self.eternalblue_ips: str = ""               # New attribute for EternalBlue IPs only

    def run_discovery_scan(self) -> str | None:
        command = ["nxc", "smb", self.subnet]
        raw_output = super().run(command)

        if re.fullmatch(r"Running nxc against \d+ targets ━+ 100% \d+:\d+:\d+", raw_output):
            print(f"{Fore.YELLOW}[!]{self.banner} Did not return any hosts alive (subnet empty?)")
            self.results = None
            return
        
        self.results = raw_output
        self.print_raw_output()
        return

    
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
