import subprocess
from pathlib import Path
from colorama import Fore, Style


class Scanner:
    def __init__(self, name: str, banner: str, subnet: str, outdir: Path):
        self.banner = banner
        self.name = name
        self.subnet = subnet
        self.outdir = outdir
        self.results: str | None = None

    def run(self, command: list[str]) -> str:
        """Run a shell command and return stdout"""
        try:
            print(f"{Fore.CYAN}[*]{self.banner} Running {self.name} on {self.subnet}...{Style.RESET_ALL}")
            result = subprocess.run(command, capture_output=True, text=True)
            self.results = result.stdout.strip()
            return self.results
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[!]{self.banner} failed: {e.stderr.strip()}{Style.RESET_ALL}")
            return ""

    def save(self, output, output_file: Path):
        """Save results to a file"""
        if not self.results:
            print(f"{Fore.YELLOW}[!]{self.banner} did not return any results to save {Style.RESET_ALL}")
            return

        output_file.write_text(self.results)
        print(f"{Fore.GREEN}[+]{self.banner} Saving results saved to {output_file}{Style.RESET_ALL}")
        return output_file
