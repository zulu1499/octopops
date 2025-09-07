import re
import ipaddress
from .base_scanner import Scanner
from colorama import Fore, Style
from helpers import sort_ips_in_ascending

class FpingScanner(Scanner):

    def run_scan(self) -> str | None:
        command = ["fping", "-a", "-s", "-g", "-q", self.subnet]
        raw_output = super().run(command)
        if not raw_output:
            print(f"{Fore.YELLOW}[!]{self.banner} Did not return any hosts alive (subnet empty?)")
            self.results = None
            return
        
        ips_sorted = sort_ips_in_ascending(raw_output)
        print(f"{Fore.GREEN}[+][FpingScanner] Raw output:\n{ips_sorted}{Style.RESET_ALL}")
        self.results = ips_sorted
        return 
