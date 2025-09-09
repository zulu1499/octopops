import re
import ipaddress
from scanners import *
from colorama import Fore, Style
from helpers import sort_ips_in_ascending

class FpingScanner(DiscoveryScanner):

    def run_discovery_scan(self) -> str | None:
        command = ["fping", "-a", "-s", "-g", "-q", self.subnet]
        
        raw_output = super().run(command)
        if not raw_output:
            print(f"{Fore.YELLOW}[!]{self.banner} Did not return any hosts alive (subnet empty?)")
            self.results = None
            return
        
        ips_sorted = sort_ips_in_ascending(raw_output)

        self.results = ips_sorted
        self.ips = ips_sorted
        self.print_raw_output()
        return 
