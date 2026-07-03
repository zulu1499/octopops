import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from colorama import Fore, Style
from helpers import *
from processing_scanners import *
import re
from processors import *

class NmapProcessingScanner(ProcessingScanner):

    def __init__(self, banner: str, name: str, outdir: Path, db_path: Path):
        # Initialize parent class attributes
        super().__init__(banner, name, outdir)
        self.db_path: Path = db_path
        # Add new attributes in the child class
        self.xml_output: str = ""
        

    @staticmethod
    def natural_sort_key(path: Path):
        """Sort paths with numbers in natural numeric order."""
        return [int(text) if text.isdigit() else text.lower() for text in re.split(r"(\d+)", str(path))]

    def run_nmap_on_file(self, ip_file: Path, result_file: Path):
        """Run nmap on a single IP file and save output to result_file."""

        print(f"{Fore.GREEN}[+]{self.banner} Processing file {ip_file} ...")
        cmd = ["nmap", "-iL", str(ip_file), "--open", "-Pn", "-sV", "-oX", "-", "-oN", str(result_file)]
        process = subprocess.run(cmd, capture_output=True, text=True)

        raw_xml_output = process.stdout.strip()

        if not raw_xml_output:
            print(f"{Fore.YELLOW}[!]{self.banner} nmap returned no output for {ip_file}.{Style.RESET_ALL}")
            return

        try:
            json_output = XMLToJson.nmap_xml_to_json(raw_xml_output)
        except ET.ParseError:
            print(f"{Fore.RED}[-]{self.banner} Failed to parse nmap XML for {ip_file}.{Style.RESET_ALL}")
            return

        DB.insert_nmap_scan_results(self.db_path, json_output, "hosts_ports")
        print(f"{Fore.GREEN}[+]{self.banner} Saved results to {result_file} and inserted into {self.db_path}")

    def scan_all_chunks(self, ip_files_dir: Path, prefix="nmap_chunk_result_"):
        """Scan all 64-IP chunk files in numeric order."""
        ip_files = sorted(ip_files_dir.glob("*.txt"), key=self.natural_sort_key)
        chunked_scans_outdir = self.outdir / f"chunked_scans_result"
        chunked_scans_outdir.mkdir(parents=True, exist_ok=True)

        for idx, ip_file in enumerate(ip_files, start=1):
            result_file = chunked_scans_outdir/ f"{prefix}{idx}.txt"
            self.run_nmap_on_file(ip_file, result_file)