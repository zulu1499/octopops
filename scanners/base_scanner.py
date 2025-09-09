import subprocess
from pathlib import Path
from colorama import Fore, Style
from helpers import *
from processors import *

class DiscoveryScanner:
    """
    DiscoveryScanner is a base class for network discovery scanners.
    Attributes:
        name (str): The name of the scanner.
        banner (str): A banner or label for the scanner, used in output messages.
        subnet (str): The target subnet to scan.
        outdir (Path): The output directory for saving results.
        results (str | None): The raw results from the scan command.
        ips (str | None): The extracted IP addresses from the scan results.
    Methods:
        __init__(name: str, banner: str, subnet: str, outdir: Path):
            Initializes the DiscoveryScanner with the given parameters.
        run(command: list[str]) -> str:
            Executes a shell command for scanning, handles root requirements, and returns the command output.
        save(output, output_file: Path):
            Saves the scan results to a specified file.
        extract_ips():
            Extracts IP addresses from the scan results using IPExtractor.
    """
    
    def __init__(self, name: str, banner: str, subnet: str, outdir: Path):
        self.banner = banner
        self.name = name
        self.subnet = subnet
        self.outdir = outdir
        self.results: str | None = None
        self.ips: str | None = None  # To store extracted IPs

    def run(self, command: list[str]) -> str:
        """Run a shell command and return stdout"""

        print(f"{Fore.CYAN}[*]{self.banner} Running {self.name} on {self.subnet}...{Style.RESET_ALL}")

        need_root = misc.check_for_root_requirement(command)
        if need_root and not misc.is_root():
            print(f"{Fore.RED}[-]{self.banner} requires root privileges. Run octopops with a user that has sudo{Style.RESET_ALL}")
            return ""
                        
        result = subprocess.run(command, capture_output=True, text=True)
        # if result.returncode != 0:
        #     print(f"{Fore.RED}[!]{self.banner} command *{command}* failed: {result.stderr.strip()}{Style.RESET_ALL}")
        #     return ""

        self.results = result.stdout.strip()
        return self.results

    def print_raw_output(self):
        print(f"{Fore.GREEN}[+]{self.banner} Raw discovery scanner output:{Style.RESET_ALL}")
        print(self.results)

    def save(self, output, output_file: Path):
        """Save results to a file"""
        if not self.results:
            print(f"{Fore.YELLOW}[!]{self.banner} did not return any results to save {Style.RESET_ALL}")
            return

        output_file.write_text(output)
        print(f"{Fore.GREEN}[+]{self.banner} Saving results to {output_file}{Style.RESET_ALL}")
        return output_file

    def extract_ips(self):
        if self.results:
            extracted_ips = IPExtractor.extract(self.results)
            self.ips = extracted_ips
            return 