#!/usr/bin/env python3
import subprocess
import argparse
import sys
from pathlib import Path
from colorama import Fore, Style, init
import re
import threading
import ipaddress

# Global files
files ={}

# Regex to match a valid IPv4 subnet in CIDR notation
subnet_regex = re.compile(
    r'^('
    r'(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'  # first octet
    r'(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'  # second octet
    r'(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'  # third octet
    r'(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'    # fourth octet
    r')/(3[0-2]|[12]?\d)$'                  # CIDR mask /0 - /32
)

def is_valid_subnet(subnet):
    return bool(subnet_regex.match(subnet))

def sort_ips_in_ascending(ips):
    """
    Sort a string of IP addresses in ascending numerical order.

    This function:
    1. Splits the input string into individual lines.
    2. Filters only valid IPv4 addresses.
    3. Sorts the IP addresses numerically.
    4. Joins them back into a multi-line string.

    Args:
        ips (str): Multi-line string containing IP addresses (and possibly other text).

    Returns:
        str: Multi-line string with valid IPs sorted in ascending order.
    """
    ips_list = [line.strip() for line in ips.splitlines() if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line)]
    ips_list.sort(key=lambda ip: ipaddress.IPv4Address(ip))
    ips_sorted = "\n".join(ips_list)
    return ips_sorted


# Function to run fping on a subnet and save valid ips to a file
def run_fping(subnet, outdir):
    """Run fping on a subnet and save responsive IPs to a file."""

    print(f"{Fore.YELLOW}[*] Running fping on {subnet} ...{Style.RESET_ALL}")

    try:
        command = ["fping", "-a", "-s", "-g", "-q", subnet]
        fping_output = subprocess.run(command, stdout=None, capture_output=True, text=True)
        fping_output = fping_output.stdout.strip()


        if not fping_output:
            print(f"{Fore.YELLOW}[!] fping did not return any output (subnet {subnet} empty maybe ?)")
            return

        # Sort IPs numberically in ascending order
        fping_output_sorted = sort_ips_in_ascending(fping_output)

        fping_output_file = outdir / "octo_scanner_fping_results.txt"
        fping_output_file.write_text(fping_output_sorted)
        print(f"{Fore.GREEN}[+] fping scan completed. Results saved to {fping_output_file}{Style.RESET_ALL}")
        print(fping_output_sorted)
        files["fping_output_file"] = fping_output_file

    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] fping failed: {e.stderr.strip()}{Style.RESET_ALL}")


def run_nxc(subnet, outdir):
    """Run nxc (NetExec) on a subnet and save results to a file."""
    print(f"{Fore.YELLOW}[*] Running nxc on {subnet} ...{Style.RESET_ALL}")
    
    try:
        command = ["nxc", "smb", subnet]
        nxc_output = subprocess.run(command, stdout=None, capture_output=True, text=True)

        # Path(output_file).write_text(nxc_output.stdout)
        nxc_output = nxc_output.stdout.strip()
        line_to_check = "Running nxc against 256 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00"

        if re.search(r"Running nxc against \d+ targets", nxc_output):
            print(f"{Fore.YELLOW}[!] nxc did not return any output (subnet {subnet} empty maybe ?)")
            return

        
        nxc_output_file = outdir / "octo_scanner_nxc_results.txt"
        nxc_output_file.write_text(nxc_output)
        print(f"{Fore.GREEN}[+] nxc scan completed. Results saved to {nxc_output_file}{Style.RESET_ALL}")
        print(nxc_output)
        files["nxc_output_file"] = nxc_output_file

        
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] nxc failed: {e.stderr.strip()}{Style.RESET_ALL}")


def split_file_by_hosts(input_file, outdir, hosts_per_file: int = 64, prefix: str = "chunk"):
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
    with input_file.open("r") as f:
        ips = [line.strip() for line in f if line.strip()]
    
    # Split into chunks
    for i in range(0, len(ips), hosts_per_file):
        chunk_ips = ips[i:i+hosts_per_file]
        chunk_file = outdir / f"{prefix}_{i//hosts_per_file + 1}.txt"
        chunk_file.write_text("\n".join(chunk_ips))
        print(f"[+] Created {chunk_file} with {len(chunk_ips)} IPs")


def main():
    parser = argparse.ArgumentParser(description="🐙 OctoScanner - simple subnet scanner using fping and nxc")
    parser.add_argument("-s", "--subnet", help="Subnet to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--outdir", default="octo_scanner_results", help="Directory to store results")


    # -------------------------- Argument Parsing ---------------------------------
    args = parser.parse_args()
    subnet = args.subnet
    
    if not is_valid_subnet(subnet):
        print(f"{Fore.RED}[-] Subnet should be in the format : x.x.x.x/x !")
        parser.print_help()
        exit(1)

    # Convert the outdir to a path object and create it it it doesn't exist
    outdir = Path(args.outdir)
    outdir.mkdir(exist_ok=True)
    

    # -------------------------------- Implemented threading -----------------------------------------
    thread_fping = threading.Thread(target=run_fping, args=(subnet,outdir))
    thread_nxc = threading.Thread(target=run_nxc, args=(subnet,outdir))

    thread_fping.start()
    thread_nxc.start()

    thread_fping.join()
    thread_nxc.join()

    # --------------------------------- Perform further actions on the discovered hosts from both tools ----------------------
    print(files)
    

if __name__ == "__main__":
    main()