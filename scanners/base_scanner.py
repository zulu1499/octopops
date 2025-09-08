import subprocess
from pathlib import Path
from colorama import Fore, Style
from helpers import *


class Scanner:
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
            print(f"{Fore.YELLOW}[!]{self.banner} requires root privileges. Run octopops with a user that has sudo{Style.RESET_ALL}")
            return ""
                        
        result = subprocess.run(command, capture_output=True, text=True)
        # if result.returncode != 0:
        #     print(f"{Fore.RED}[!]{self.banner} command *{command}* failed: {result.stderr.strip()}{Style.RESET_ALL}")
        #     return ""

        self.results = result.stdout.strip()
        return self.results

    def save(self, output, output_file: Path):
        """Save results to a file"""
        if not self.results:
            print(f"{Fore.YELLOW}[!]{self.banner} did not return any results to save {Style.RESET_ALL}")
            return

        output_file.write_text(output)
        print(f"{Fore.GREEN}[+]{self.banner} Saving results saved to {output_file}{Style.RESET_ALL}")
        return output_file
