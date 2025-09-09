import argparse
from pathlib import Path
from core.orchestrator import Orchestrator
from helpers import *
from colorama import Fore, Style
import traceback


# Global varibales
valid_scanners = {"nmap", "fping", "nxc", "all"}

def parse_args():
    parser = argparse.ArgumentParser(
        description="🐙 Octopops - Internal Pentest Subnet Dissector"
    )

    parser.add_argument(
        "-s", "--subnet",
        required=True,
        help="Subnet to scan (e.g., 192.168.1.0/24)"
    )

    parser.add_argument(
        "-o", "--outdir",
        type=Path,
        default="octopops_results",
        help="Directory to store results"
    )

    parser.add_argument(
        "-ds", "--discovery_scanners",
        type=str,
        default="all",
        help="Comma-separated list of scanners to run. Choices: fping, nmap, nxc, all"
    )
    
    parser.add_argument(
    "--ip-file",
    type=Path,
    help="Path to a file containing IPs to use instead of running discovery scans, this will skip discovery scans !"
)

    args = parser.parse_args()

    # Check if ip-file is provided, if so, override scanners to empty list
    if args.ip_file:
        if not args.ip_file.is_file():
            print(f"{Fore.RED}[-] IP file '{args.ip_file}' does not exist or is not a file.{Style.RESET_ALL}")
            exit(1)
        else: 
            args.discovery_scanners = ""  # No scanners to run if using IP file
            args.subnet = None  # No subnet needed if using IP file
            

    # Check if subnet is valid
    if args.subnet is not None and not ip_utils.is_valid_subnet(args.subnet):
        print(f"{Fore.RED}[!] Invalid subnet format: {args.subnet}{Style.RESET_ALL}")
        parser.print_help()
        exit(1)

    # Split comma-separated scanners into a list and validate
    if args.discovery_scanners:
        scanners = [s.strip().lower() for s in args.discovery_scanners.split(",")]
        args.discovery_scanners = scanners
        for s in scanners:
            if s not in valid_scanners:
                print(f"{Fore.RED}[!] Invalid scanner '{s}'. Choose from: fping, nmap, nxc, all")
                parser.print_help()
                exit(1)

    return args

def main():
    # banner.print_banner_slowly()
    args = parse_args()
    
    try:
        if args.ip_file:
            print(f"{Fore.YELLOW}[!] IP file provided, skipping discovery scans and using IPs from {args.ip_file}{Style.RESET_ALL}")
            orchestrator = Orchestrator(None, args.outdir, [])
            orchestrator.run_processing_scanners(args.ip_file)
        else:
            orchestrator = Orchestrator(args.subnet, args.outdir, args.discovery_scanners)
            orchestrator.run_discovery_scanners()
    except Exception as e:
        print(f"{Fore.RED}[FATAL ERROR] {e}{Style.RESET_ALL}")
        # Optional: print full traceback for debugging
        traceback.print_exc()

if __name__ == "__main__":
    main()
