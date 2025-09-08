from helpers.ip_utils import sort_ips_in_ascending
from colorama import Fore, Style
import os

banner_misc = "[HELPER MISC]"
def merge_sort_ips(*strings: str) -> str:
    """
    Merge multiple strings, remove duplicate lines, and sort IPs in ascending order.

    Args:
        *strings (str): Two or more multi-line strings containing IPs.

    Returns:
        str: Merged content with unique IPs, sorted numerically.
    """
    seen = set()
    merged_lines = []

    # Merge and deduplicate lines
    for s in strings:
        for line in s.splitlines():
            line = line.strip()
            if line and line not in seen:
                seen.add(line)
                merged_lines.append(line)

    # Sort the IPs using your existing helper
    merged_sorted_ips = sort_ips_in_ascending("\n".join(merged_lines))

    # Already a string, just return it
    return merged_sorted_ips


def split_file_by_hosts(file, outdir, hosts_per_file: int = 64, prefix: str = "subnet_chunk"):
    """
    Split a file containing IP addresses into multiple files, each containing a fixed number of hosts.

    Args:
        input_file (Path): Path to the input file containing IPs (one per line).
        outdir (Path): Directory where the output files will be saved.
        hosts_per_file (int, optional): Number of IPs per output file. Default is 64.
        prefix (str, optional): Prefix for output file names. Default is "chunk".
    """
    outdir.mkdir(exist_ok=True)
    
    # Read all IPs from the input file
    with file.open("r") as f:
        ips = [line.strip() for line in f if line.strip()]
    
    # Split into chunks
    for i in range(0, len(ips), hosts_per_file):
        chunk_ips = ips[i:i+hosts_per_file]
        chunk_file = outdir / f"{prefix}_{i//hosts_per_file + 1}.txt"
        chunk_file.write_text("\n".join(chunk_ips))
        print(f"{Fore.GREEN}[+]{banner_misc} Created {chunk_file} with {len(chunk_ips)} IPs")

def check_for_root_requirement(command: list[str]) -> bool:
    """
    Check if a command requires root.

    Currently, only `nmap -sn` requires root in your setup.
    You can extend this for other scanners.

    Returns:
        bool: True if root is required, False otherwise.
    """
    # Example: check if command needs sudo privileges
    if command[0] == "sudo":
        return True
    return False

def is_root() -> bool:
    """Check if the current user is root."""
    return os.geteuid() == 0