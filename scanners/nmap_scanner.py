import subprocess
from pathlib import Path
from colorama import Fore, Style
from scanners import *
import re

class NmapScanner(DiscoveryScanner):
#     def __init__(self, banner: str, subnet: str, outdir: Path):
#         super().__init__("nmap_scanner", "NmapScanner", subnet, outdir)

    def run_discovery_scan(self) -> str | None:
        """Run Nmap host discovery scan (-sn)"""

        command = ["sudo", "nmap", "-sn", "-n", self.subnet]  # -n = no DNS resolution
        raw_output = super().run(command)
        self.results = raw_output.strip()
            
        if re.search(r"(0 hosts up)", self.results):
            print(f"{Fore.YELLOW}[!]{self.banner} Did not return any hosts alive (subnet empty?){Style.RESET_ALL}")
            self.results = None
            return 
        
        self.results = raw_output
        self.print_raw_output()
        return


    # def save(self, filename: str = "nmap_results.txt") -> Path | None:
    #     """Save Nmap output to file"""
    #     if not self.results:
    #         print(f"{Fore.YELLOW}[!] {self.name} did not return any results to save{Style.RESET_ALL}")
    #         return None

    #     outfile = self.outdir / filename
    #     outfile.write_text(self.results)
    #     print(f"{Fore.GREEN}[+] {self.name} results saved to {outfile}{Style.RESET_ALL}")
    #     return outfile
