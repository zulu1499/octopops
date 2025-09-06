#!/usr/bin/env python3
import subprocess
import argparse
import sys
from pathlib import Path
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def run_fping(subnet, output_file):
    """Run fping on a subnet and save responsive IPs to a file."""
    try:
        result = subprocess.run(
            ["fping", "-a", "-q", "-g", subnet],
            capture_output=True,
            text=True,
            check=True
        )
        alive_ips = result.stdout.strip().splitlines()
        Path(output_file).write_text("\n".join(alive_ips))

        print(f"{Fore.GREEN}[+] fping found {len(alive_ips)} live hosts. Results saved to {output_file}{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] fping failed: {e.stderr.strip()}{Style.RESET_ALL}")

def run_nxc(subnet, output_file):
    """Run nxc (NetExec) on a subnet and save results to a file."""
    try:
        result = subprocess.run(
            ["nxc", "smb", subnet],
            capture_output=True,
            text=True,
            check=True
        )

        Path(output_file).write_text(result.stdout)

        print(f"{Fore.GREEN}[+] nxc scan completed. Results saved to {output_file}{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] nxc failed: {e.stderr.strip()}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="🐙 OctoScanner - simple subnet scanner using fping and nxc")
    parser.add_argument("-s", "--subnet", help="Subnet to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--outdir", default="results", help="Directory to store results")

    args = parser.parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(exist_ok=True)

    # print(BANNER)

    fping_file = outdir / "octo_scanner_fping_results.txt"
    nxc_file = outdir / "octo_scanner_nxc_results.txt"

    print(f"{Fore.YELLOW}[*] Running fping on {args.subnet} ...{Style.RESET_ALL}")
    run_fping(args.subnet, fping_file)

    print(f"{Fore.YELLOW}[*] Running nxc on {args.subnet} ...{Style.RESET_ALL}")
    run_nxc(args.subnet, nxc_file)

if __name__ == "__main__":
    main()