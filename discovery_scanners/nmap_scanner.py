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
        all_results = []  # Optional: keep accumulated results in memory
        
        for chunk in IPUtils._chunk_subnet(self.subnet):  # generator yielding /24 subnets
            print(f"{Fore.CYAN}[*]{self.banner} Scanning chunk {chunk}...{Style.RESET_ALL}")
            
            command = ["sudo", "nmap", "-sn", "-n", str(chunk)]
            process = subprocess.run(command, capture_output=True, text=True)
            raw_output = process.stdout.strip()
            
            if re.search(r"(0 hosts up)", raw_output):
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
            self.append(self.results, output_file, str(chunk))

    @staticmethod
    def natural_sort_key(path: Path):
        """Sort paths with numbers in natural numeric order."""
        return [int(text) if text.isdigit() else text.lower() for text in re.split(r"(\d+)", str(path))]

    def run_nmap_on_file(self, ip_file: Path, result_file: Path):
        """Run nmap on a single IP file and save output to result_file."""
        print(f"[+] Processing file {ip_file} ...")
        cmd = ["sudo", "nmap", "-iL", str(ip_file), "--open", "-Pn", "-oX", "-", "-oN", str(result_file)]
        process = subprocess.run(cmd, capture_output=True, text=True)

        raw_output = process.stdout.strip()
        
        if not re.search(r"(0 hosts up)", raw_output):
            # if scan is positive append results to an xml file
            # PROCESS THE XML OUTPUT EXTRACT HOSTS AND PORTS
            # APPEND THE PROCESSED output to a file
            pass

        print(f"[+] Saved results to {result_file}")

    def scan_all_chunks(self, ip_files_dir: Path, prefix="nmap_chunk_result_"):
        """Scan all 64-IP chunk files in numeric order."""
        ip_files = sorted(ip_files_dir.glob("*.txt"), key=self.natural_sort_key)
        self.outdir.mkdir(parents=True, exist_ok=True)

        for idx, ip_file in enumerate(ip_files, start=1):
            result_file = self.outdir / f"{prefix}{idx}.txt"
            print(f"{Fore.GREEN}Processing file {result_file}")
            self.run_nmap_on_file(ip_file, result_file)

