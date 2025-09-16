from pathlib import Path
import subprocess
from discovery_scanners import *
from colorama import Fore, Style
from helpers import *

class FpingScanner(DiscoveryScanner):

    def run_discovery_scan(self) -> str | None:
        command = ["fping", "-a", "-s", "-g", "-q", self.subnet]
        
        raw_output = super().run(command)
        if not raw_output:
            print(f"{Fore.YELLOW}[!]{self.banner} Did not return any hosts alive (subnet empty?)")
            self.results = None
            return
        
        ips_sorted = IPUtils.sort_ips_in_ascending(raw_output)

        self.results = ips_sorted
        self.ips = ips_sorted
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
            
            command = ["fping", "-a", "-s", "-g", "-q", str(chunk)]
            process = subprocess.run(command, capture_output=True, text=True)
            raw_output = process.stdout.strip()
            
            if not raw_output:
                print(f"{Fore.YELLOW}[!]{self.banner} No hosts alive in {chunk}, skipping.{Style.RESET_ALL}")
                continue
            
            ips_sorted = IPUtils.sort_ips_in_ascending(raw_output)
            
            print(f"{Fore.GREEN}[+]{self.banner} Raw output from {chunk}:{Style.RESET_ALL}")
            print(raw_output)
            # Store in object
            if self.results:
                self.results += "\n" + ips_sorted
            else:
                self.results = ips_sorted
            
            self.ips = self.results
            
            # Append results incrementally to the file
            self.append(self.results, output_file, str(chunk))
