import subprocess
from pathlib import Path
from colorama import Fore, Style
from helpers import *
from processing_scanners import *
import re

class NmapProcessingScanner(ProcessingScanner):

    def __init__(self, banner: str, name: str, outdir: Path):
        # Initialize parent class attributes
        super().__init__(banner, name, outdir)

        # Add new attributes in the child class
        self.xml_output: str = ""
        

    @staticmethod
    def natural_sort_key(path: Path):
        """Sort paths with numbers in natural numeric order."""
        return [int(text) if text.isdigit() else text.lower() for text in re.split(r"(\d+)", str(path))]

    def run_nmap_on_file(self, ip_file: Path, result_file: Path):
        """Run nmap on a single IP file and save output to result_file."""

        print(f"{Fore.GREEN}[+]{self.banner} Processing file {ip_file} ...")
        cmd = ["sudo", "nmap", "-iL", str(ip_file), "--open", "-Pn", "-oX", "-", "-oN", str(result_file)] # , "-oN", str(result_file)
        process = subprocess.run(cmd, capture_output=True, text=True)

        raw_output = process.stdout.strip()
        
        if not re.search(r"(0 hosts up)", raw_output):
            print(raw_output)
            pass

        print(f"{Fore.GREEN}[+]{self.banner} Saved results to {result_file}")

    def scan_all_chunks(self, ip_files_dir: Path, prefix="nmap_chunk_result_"):
        """Scan all 64-IP chunk files in numeric order."""
        ip_files = sorted(ip_files_dir.glob("*.txt"), key=self.natural_sort_key)
        chunked_scans_outdir = self.outdir / f"chunked_scans"
        chunked_scans_outdir.mkdir(parents=True, exist_ok=True)

        for idx, ip_file in enumerate(ip_files, start=1):
            result_file = chunked_scans_outdir/ f"{prefix}{idx}.txt"
            self.run_nmap_on_file(ip_file, result_file)

