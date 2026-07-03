import subprocess
from pathlib import Path
from colorama import Fore, Style
from helpers import *
from processors import *

class ProcessingScanner:
    """
    ProcessingScanner is a base class for running and managing network scanning commands.
    Attributes:
        name (str): The name of the scanner.
        banner (str): A banner or label for the scanner.
        subnet (str): The subnet to scan.
        outdir (Path): The output directory for saving results.
        results (str | None): The results of the last scan, if any.
    Methods:
        __init__(name: str, banner: str, subnet: str, outdir: Path):
            Initializes the ProcessingScanner with the given parameters.
        run(command: list[str]) -> str:
            Executes a shell command for scanning, handles root requirements, and returns the command output.
        save(output, output_file: Path):
            Saves the provided output to the specified file if results are available.
        append(output, output_file: Path, chunk: str | None = None):
            Appends the provided output to the specified file, optionally annotating with a subnet chunk."
  
    """
    
    def __init__(self, name: str, banner: str, outdir: Path):
        self.banner = banner
        self.name = name
        self.outdir = outdir
        self.results: str | None = None
    

    def save(self, output, output_file: Path):
        """Save results to a file"""
        if not output:
            print(f"{Fore.YELLOW}[!]{self.banner} did not return any results to save {Style.RESET_ALL}")
            return

        output_file.write_text(output)
        print(f"{Fore.GREEN}[+]{self.banner} Saving results to {output_file}{Style.RESET_ALL}")
        return output_file
    
    def append(self, output, output_file: Path, chunk: str | None = None):
        """Append results to a file"""
        if output:
            with output_file.open("a") as f:
                f.write(output + "\n")
            print(f"{Fore.GREEN}[+]{self.banner} Appending results of subnet {chunk} to {output_file}{Style.RESET_ALL}")
            return output_file

