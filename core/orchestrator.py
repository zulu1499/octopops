import threading
from pathlib import Path
from colorama import Fore, Style

from scanners.fping_scanner import FpingScanner
from scanners.nxc_scanner import NxcScanner
from processors.ip_extractor import IPExtractor
from processors.eternalblue import EternalBlueFilter
from helpers import *

class Octopops:
    def __init__(self, subnet: str, outdir: str):
        self.subnet = subnet
        self.outdir = Path.cwd() / outdir
        self.outdir.mkdir(exist_ok=True)
        self.banner = "[Orchestrator]"

    def run(self):
        # --------------------------- Scanning ---------------------------
        fping = FpingScanner("fping_scanner","[FpingScanner]", self.subnet, self.outdir)
        nxc = NxcScanner("nxc_scanner", "[NXCScanner]", self.subnet, self.outdir)

        # t1 = threading.Thread(target=fping.run_scan)
        # t2 = threading.Thread(target=nxc.run_scan)
        # t1.start()
        # t2.start()
        # t1.join()
        # t2.join()

        # fping.save(fping.results, self.outdir / "fping_results.txt")
        # nxc.save(nxc.results, self.outdir / "nxc_results.txt")

        # --------------------------- For testing purposes ---------------------------
        nxc.results = Path("test_data/nxc_sample_output.txt").read_text()
        fping.results = Path("test_data/fping_sample_output.txt").read_text()
        fping.save(fping.results, self.outdir / "fping_results.txt")
        nxc.save(nxc.results, self.outdir / "nxc_results.txt")
        # --------------------------- Processing ---------------------------
        
        if nxc.results:
            # Extract IPs from NXC results and save to file
            nxc.extract_ips()
            nxc.save(nxc.ips, self.outdir / "nxc_extracted_ips.txt")
        
            # Filter EternalBlue vulnerable hosts and save to files
            nxc.filter_eternalblue()    
            eternalblue_subdir = self.outdir / "eternal_blue_hosts"
            eternalblue_subdir.mkdir(exist_ok=True)
            nxc.save_eternalblue(nxc.eternalblue_ips, eternalblue_subdir / "nxc_eternalblue_ips.txt")
            nxc.save_eternalblue(nxc.eternalblue_hosts, eternalblue_subdir / "nxc_eternalblue_hosts.txt")

            # Merge and sort IPs from both scanners and save to file
            if fping.results and nxc.ips:
                
                merged_sorted_ips = misc.merge_sort_ips(fping.results, nxc.ips)
                if merged_sorted_ips:
                    merged_file = self.outdir / "merged_all_scanners_ips.txt"
                    merged_file.write_text(merged_sorted_ips)
                    print(f"{Fore.GREEN}[+]{self.banner} Merged and sorted IPs from all scanners saved to {merged_file}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!]{self.banner} No valid IPs found to merge and sort.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!]{self.banner} Skipping merge and sort due to missing fping or nxc IPs.{Style.RESET_ALL}")

    # --------------------------- Splitting all discovered ips into 64 hosts chuncks for nmap ---------------------------
        split_subdir = self.outdir / "split_ips_for_nmap"
        split_subdir.mkdir(exist_ok=True)
        if (self.outdir / "merged_all_scanners_ips.txt").exists():
            misc.split_file_by_hosts(self.outdir / "merged_all_scanners_ips.txt", split_subdir, hosts_per_file=64, prefix="subnet_chunk")