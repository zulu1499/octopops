import threading
from pathlib import Path
from colorama import Fore, Style

from scanners.fping_scanner import FpingScanner
from scanners.nxc_scanner import NxcScanner
from processors.ip_extractor import IPExtractor
from processors.eternalblue import EternalBlueFilter


class Octopops:
    def __init__(self, subnet: str, outdir: str):
        self.subnet = subnet
        self.outdir = Path.cwd() / outdir
        self.outdir.mkdir(exist_ok=True)

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

