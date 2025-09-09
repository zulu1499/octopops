import threading
from pathlib import Path
from colorama import Fore, Style
from typing import cast
from scanners import *
from processors.ip_extractor import IPExtractor
from processors.eternalblue import EternalBlueFilter
from helpers import *

class Orchestrator:
    def __init__(self, subnet: str | None, outdir: Path, discovery_scanners: list[str]):

        self.subnet = subnet
        self.outdir = Path.cwd() / outdir
        self.outdir.mkdir(exist_ok=True)
        self.discovery_scanners = discovery_scanners
        self.banner = "[Orchestrator]"
        self.all_ips = ""  # To store merged IPs from all discovery scanners

        # Store scanner objects keyed by their name
        self.discovery_scanner_objects: dict[str, DiscoveryScanner] = {}
        self.threads: list[threading.Thread] = []


# --------------------------- NXC OUTPUT PROCESSING ---------------------------
    def output_processing_nxc(self, nxc: NxcScanner):
        print(f"{Fore.CYAN}[*]{self.banner} Processing {nxc.banner} output...{Style.RESET_ALL}")
        # Extract IPs from NXC results and save to file
        nxc.extract_ips()
        nxc.save(nxc.ips, self.outdir / f"{nxc.name}_extracted_ips.txt")
            
        # Filter EternalBlue vulnerable hosts and save to files
        nxc.filter_eternalblue()    
        eternalblue_subdir = self.outdir / "eternal_blue_hosts"
        eternalblue_subdir.mkdir(exist_ok=True)
        nxc.save_eternalblue(nxc.eternalblue_ips, eternalblue_subdir / "nxc_eternalblue_ips.txt")
        nxc.save_eternalblue(nxc.eternalblue_hosts, eternalblue_subdir / "nxc_eternalblue_hosts.txt")


# --------------------------- NMAP OUTPUT PROCESSING ---------------------------
    def output_processing_nmap(self, nmap: NmapScanner):
        print(f"{Fore.CYAN}[*]{self.banner} Processing {nmap.banner} output...{Style.RESET_ALL}")
        # Extract IPs from NXC results and save to file
        nmap.extract_ips()
        nmap.save(nmap.ips, self.outdir / f"{nmap.name}_extracted_ips.txt")


# --------------------------- MERGE AND SORT IPS FROM ALL DISCOVERY SCANNERS ---------------------------
    def merge_discovery_scanners_ips(self, *positive_scanners: DiscoveryScanner):
        all_ips = []

        # Collect ips from all scanners
        for scanner in positive_scanners:
            if scanner.ips:  # Only add non-empty results
                all_ips.append(scanner.ips)

        if all_ips:
            merged_sorted_ips = misc.merge_sort_ips(*all_ips)
            if merged_sorted_ips:
                merged_file = self.outdir / "merged_all_discovery_scanners_ips.txt"
                merged_file.write_text(merged_sorted_ips)
                # print(f"{Fore.GREEN}[+]{self.banner} Merged and sorted IPs from all scanners saved to {merged_file}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+]{self.banner} Merged and sorted {len(merged_sorted_ips.splitlines())} IPs from {len(positive_scanners)} scanners saved to {merged_file}{Style.RESET_ALL}")
                
                # Update ip_file to point to merged file for processing scanners
                self.ip_file = merged_file  
            else:
                print(f"{Fore.YELLOW}[!]{self.banner} No valid IPs found to merge and sort.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!]{self.banner} No scanner produced valid IPs, skipping merge.{Style.RESET_ALL}")


# --------------------------- RUN DISCOVERY SCANNERS ---------------------------
    def run_discovery_scanners(self):
        # Map scanner names to their classes
        discovery_scanner_classes = {
            "fping": FpingScanner,
            "nxc": NxcScanner,
            "nmap": NmapScanner,
        }
        


        # If no scanners specified or "all" is specified, use all available scanners
        if not self.discovery_scanners or "all" in self.discovery_scanners:
            self.discovery_scanners = list(discovery_scanner_classes.keys())  # all scanners


        # Create discovery scanner objects and start threads
        for scanner_name in self.discovery_scanners:
            ScannerClass = discovery_scanner_classes.get(scanner_name)
            if ScannerClass:
                scanner = ScannerClass(
                    f"{scanner_name}_discovery_scanner",
                    f"[{scanner_name.capitalize()}Scanner]",
                    self.subnet,
                    self.outdir
                )
                t = threading.Thread(target=scanner.run_discovery_scan)
                t.start()

                # Save references
                self.discovery_scanner_objects[scanner_name] = scanner
                self.threads.append(t)

        # Wait for all threads to complete
        for t in self.threads:
            t.join()


        # Saving results after all scanners finished
        for name, scanner in self.discovery_scanner_objects.items():
            output_file = self.outdir / f"{name}_raw_results.txt"
            scanner.save(scanner.results, output_file)

        # --------------------------- For testing purposes ---------------------------
        # nxc_scanner.results = Path("test_data/nxc_sample_output.txt").read_text()
        # fping.results = Path("test_data/fping_sample_output.txt").read_text()
        # fping.save(fping.results, self.outdir / "fping_results.txt")
        # nxc.save(nxc.results, self.outdir / "nxc_results.txt")

        # --------------------------- Processing ---------------------------
        
        if "nxc" in self.discovery_scanners:
            nxc = self.discovery_scanner_objects.get("nxc")
            if isinstance(nxc, NxcScanner) and nxc.results:
                self.output_processing_nxc(nxc)
        
        if "nmap" in self.discovery_scanners:
            nmap = self.discovery_scanner_objects.get("nmap")
            if isinstance(nmap, NmapScanner) and nmap.results:
                self.output_processing_nmap(nmap)


        
        # Filter only scanners that have non-empty extracted IPs or results
        positive_scanners = [
            scanner
            for scanner in self.discovery_scanner_objects.values()
            if getattr(scanner, "ips", None)
        ]

        if len(positive_scanners) > 1:
            # Merge and sort IPs from both scanners and save to file
            self.merge_discovery_scanners_ips(*positive_scanners)
        else:
            print(f"{Fore.YELLOW}[!]{self.banner} Skipping merge (not enough scanners returned results).{Style.RESET_ALL}")

        # Run processing scanners
        if self.all_ips:
            self.run_processing_scanners()


# --------------------------- Run processing scanners on merged IPs ---------------------------
    
    def run_processing_scanners(self, ip_file_arg: Path | None = None) -> None:
        
        # If an IP file is provided as an argument, use it else self.all_ips is already set (from discovery scanners)
        if ip_file_arg:
            print(f"{Fore.CYAN}[*]{self.banner} Using IPs from {ip_file_arg} for processing scanners...{Style.RESET_ALL}")
            
            file_content = ip_file_arg.read_text().strip()  # Read file content
            extracted_ips = IPExtractor.extract(file_content)  # Validate and extract IPs

            if not extracted_ips:
                print(f"{Fore.RED}[-]{self.banner} No valid IPs found in {ip_file_arg}, skipping processing scanners.{Style.RESET_ALL}")
                return
            
            self.all_ips = ip_utils.sort_ips_in_ascending(extracted_ips)  # Sort IPs and Store them in attribute
            print(f"{Fore.GREEN}[+]{self.banner} Loaded {len(self.all_ips.splitlines())} valid IPs from {ip_file_arg}{Style.RESET_ALL}")
            
            # Save the extracted and sorted IPs to a file
            output_file = self.outdir / "provided_ip_file_extracted_sorted_ips.txt"
            output_file.write_text(self.all_ips)
            print(f"{Fore.GREEN}[+]{self.banner} Saving results to {output_file}{Style.RESET_ALL}")


    # Split all discovered ips into 64 hosts chuncks for nmap ---------------------------
        if len(self.all_ips.splitlines()) > 64:
            split_subdir = self.outdir / "64_ip_per_file_for_nmap"
            split_subdir.mkdir(exist_ok=True)
            print(f"{Fore.CYAN}[*]{self.banner} Splitting IPs into chunks of 64 for nmap processing...{Style.RESET_ALL}")
            misc.split_ips_by_file(self.all_ips, split_subdir, ips_per_file=64, prefix="subnet_chunk")