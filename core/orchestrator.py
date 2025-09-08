import threading
from pathlib import Path
from colorama import Fore, Style
from typing import cast
from scanners import *
from processors.ip_extractor import IPExtractor
from processors.eternalblue import EternalBlueFilter
from helpers import *

class Octopops:
    def __init__(self, subnet: str, outdir: Path, scanners: list[str]):
        self.subnet = subnet
        self.outdir = Path.cwd() / outdir
        self.outdir.mkdir(exist_ok=True)
        self.scanners = scanners
        self.banner = "[Octopops]"

        # Store scanner objects keyed by their name
        self.scanner_objects: dict[str, Scanner] = {}
        self.threads: list[threading.Thread] = []


# --------------------------- NXC OUTPUT PROCESSING ---------------------------
    def output_processing_nxc(self, nxc: NxcScanner):
        print(f"{Fore.CYAN}[*]{self.banner} Processing {nxc.banner} output...{Style.RESET_ALL}")
        # Extract IPs from NXC results and save to file
        nxc.extract_ips()
        nxc.save(nxc.ips, self.outdir / "nxc_extracted_ips.txt")
            
        # Filter EternalBlue vulnerable hosts and save to files
        nxc.filter_eternalblue()    
        eternalblue_subdir = self.outdir / "eternal_blue_hosts"
        eternalblue_subdir.mkdir(exist_ok=True)
        nxc.save_eternalblue(nxc.eternalblue_ips, eternalblue_subdir / "nxc_eternalblue_ips.txt")
        nxc.save_eternalblue(nxc.eternalblue_hosts, eternalblue_subdir / "nxc_eternalblue_hosts.txt")


# --------------------------- MERGE AND SORT IPS FROM ALL DISCOVERY SCANNERS ---------------------------
    def merge_discovery_scanners_ips(self, *positive_scanners: Scanner):
        all_ips = []

        # Collect ips from all scanners
        for scanner in positive_scanners:
            if scanner.ips:  # Only add non-empty results
                all_ips.append(scanner.ips)

        if all_ips:
            merged_sorted_ips = misc.merge_sort_ips(*all_ips)
            if merged_sorted_ips:
                merged_file = self.outdir / "merged_all_scanners_ips.txt"
                merged_file.write_text(merged_sorted_ips)
                # print(f"{Fore.GREEN}[+]{self.banner} Merged and sorted IPs from all scanners saved to {merged_file}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+]{self.banner} Merged and sorted {len(merged_sorted_ips.splitlines())} IPs from {len(positive_scanners)} scanners saved to {merged_file}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!]{self.banner} No valid IPs found to merge and sort.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!]{self.banner} No scanner produced valid IPs, skipping merge.{Style.RESET_ALL}")


# --------------------------- RUN DISCOVERY SCANNERS ---------------------------
    def run_discovery_scanners(self):
        # Map scanner names to their classes
        scanner_classes = {
            "fping": FpingScanner,
            "nxc": NxcScanner,
            # "nmap": NmapScanner,
        }

        # Create scanner objects and start threads
        for scanner_name in self.scanners:
            ScannerClass = scanner_classes.get(scanner_name)
            if ScannerClass:
                scanner = ScannerClass(
                    f"{scanner_name}_scanner",
                    f"[{scanner_name.capitalize()}Scanner]",
                    self.subnet,
                    self.outdir
                )
                t = threading.Thread(target=scanner.run_discovery_scan)
                t.start()

                # Save references
                self.scanner_objects[scanner_name] = scanner
                self.threads.append(t)

        # Wait for all threads to complete
        for t in self.threads:
            t.join()


        # Example of saving results after all scanners finished
        for name, scanner in self.scanner_objects.items():
            output_file = self.outdir / f"{name}_results.txt"
            scanner.save(scanner.results, output_file)

        # --------------------------- For testing purposes ---------------------------
        # nxc_scanner.results = Path("test_data/nxc_sample_output.txt").read_text()
        # fping.results = Path("test_data/fping_sample_output.txt").read_text()
        # fping.save(fping.results, self.outdir / "fping_results.txt")
        # nxc.save(nxc.results, self.outdir / "nxc_results.txt")

        # --------------------------- Processing ---------------------------
        
        if "nxc" in self.scanners:
            nxc = self.scanner_objects.get("nxc")
            if isinstance(nxc, NxcScanner) and nxc.results:
                self.output_processing_nxc(nxc)

        
        # Filter only scanners that have non-empty extracted IPs or results
        positive_scanners = [
            scanner
            for scanner in self.scanner_objects.values()
            if getattr(scanner, "ips", None)
        ]

        if len(positive_scanners) > 1:
            # Merge and sort IPs from both scanners and save to file
            self.merge_discovery_scanners_ips(*positive_scanners)
        else:
            print(f"{Fore.YELLOW}[!]{self.banner} Skipping merge (not enough scanners returned results).{Style.RESET_ALL}")


    # --------------------------- Splitting all discovered ips into 64 hosts chuncks for nmap ---------------------------
        # split_subdir = self.outdir / "split_ips_for_nmap"
        # split_subdir.mkdir(exist_ok=True)
        # if (self.outdir / "merged_all_scanners_ips.txt").exists():
        #     misc.split_file_by_hosts(self.outdir / "merged_all_scanners_ips.txt", split_subdir, hosts_per_file=64, prefix="subnet_chunk")
