import argparse
from core.orchestrator import Octopops
from helpers import *
from colorama import Fore, Style
import traceback

# def parse_args():
    # parser = argparse.ArgumentParser(description="🐙 Octopops - Internal Pentest Subnet Dissector")
    # parser.add_argument("-s", "--subnet", required=True, help="Subnet to scan (e.g., 192.168.1.0/24)")
    # parser.add_argument("-o", "--outdir", default="octopops_results", help="Directory to store results")
    # parser.add_argument("-ds",
    #     "--discovery_scanners",
    #     nargs="+",              # Accept one or more scanner names
    #     choices=["fping", "nmap", "nxc", "all"],
    #     default=["all"],
    #     help="List of scanners to run"
    # )

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
        default="octopops_results",
        help="Directory to store results"
    )

    parser.add_argument(
        "-ds", "--discovery_scanners",
        type=str,
        default="all",
        help="Comma-separated list of scanners to run. Choices: fping, nmap, nxc, all"
    )

    args = parser.parse_args()

    if not ip_utils.is_valid_subnet(args.subnet):
        print(f"{Fore.RED}[!] Invalid subnet format: {args.subnet}{Style.RESET_ALL}")
        parser.print_help()
        exit(1)

    # Split comma-separated scanners into a list and validate
    scanners = [s.strip().lower() for s in args.discovery_scanners.split(",")]

    # Add nmap scanners later
    valid_scanners = {"fping", "nxc", "all"}
    for s in scanners:
        if s not in valid_scanners:
            print(f"{Fore.RED}[!] Invalid scanner '{s}'. Choose from: fping, nmap, nxc, all")
            parser.print_help()
            exit(1)

    args.discovery_scanners = scanners
    return args

def main():
    # banner.print_banner_slowly()
    args = parse_args()
    
    orchestrator = Octopops(args.subnet, args.outdir, args.discovery_scanners)


    try:
        orchestrator.run_discovery_scanners()
    except Exception as e:
        print(f"{Fore.RED}[FATAL ERROR] {e}{Style.RESET_ALL}")
        # Optional: print full traceback for debugging
        traceback.print_exc()

if __name__ == "__main__":
    main()
