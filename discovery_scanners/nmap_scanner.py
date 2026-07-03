import subprocess
from pathlib import Path
from colorama import Fore, Style
from helpers import *
from discovery_scanners import *
import re

class NmapScanner(DiscoveryScanner):
#     def __init__(self, banner: str, subnet: str, outdir: Path):
#         super().__init__("nmap_scanner", "NmapScanner", subnet, outdir)

    def run_discovery_scan(self) -> str | None:
        """Run Nmap host discovery scan (-sn)"""

        command = ["sudo", "nmap", "-sn", "-n", self.subnet]
        raw_output = super().run(command)
        self.results = raw_output.strip()
            
        if re.search(r"(0 hosts up)", self.results):
            print(f"{Fore.YELLOW}[!]{self.banner} Did not return any hosts alive (subnet empty?){Style.RESET_ALL}")
            self.results = None
            return 
        
        self.results = raw_output
        self.print_raw_output()
        return
    
    
    def run_discovery_scan_chunked(self, output_file: Path):
        """
        Run nmap discovery on /24 subnets and append results incrementally.

        Args:
            output_file (Path): File to append results for each processed chunk.
        """
        checkpoint_file = output_file.parent / f"{self.name}_chunk_checkpoint.txt"
        start_index = 0
        if checkpoint_file.exists():
            try:
                start_index = int(checkpoint_file.read_text().strip()) + 1
                print(f"{Fore.YELLOW}[*]{self.banner} Resuming from chunk {start_index}{Style.RESET_ALL}")
            except ValueError:
                start_index = 0

        all_results = []

        for idx, chunk in enumerate(IPUtils._chunk_subnet(self.subnet)):
            if idx < start_index:
                continue

            print(f"{Fore.CYAN}[*]{self.banner} Scanning chunk {chunk}...{Style.RESET_ALL}")

            command = ["sudo", "nmap", "-sn", "-n", str(chunk)]
            process = subprocess.run(command, capture_output=True, text=True)
            raw_output = process.stdout.strip()

            if re.search(r"(0 hosts up)", raw_output):
                print(f"{Fore.YELLOW}[!]{self.banner} No hosts alive in {chunk}, skipping.{Style.RESET_ALL}")
                checkpoint_file.write_text(str(idx))
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
            checkpoint_file.write_text(str(idx))
