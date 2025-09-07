import argparse
from core.orchestrator import Octopops
from helpers import *
from colorama import Fore, Style

def parse_args():
    parser = argparse.ArgumentParser(description="🐙 Octopops - Internal Pentest Subnet Dissector")
    parser.add_argument("-s", "--subnet", required=True, help="Subnet to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--outdir", default="octopops_results", help="Directory to store results")

    args = parser.parse_args()
    if not ip_utils.is_valid_subnet(args.subnet):
        print(f"{Fore.RED}[!] Invalid subnet format: {args.subnet}{Style.RESET_ALL}")
        parser.print_help()
        exit(1)

    return args


def main():
    banner.print_banner_slowly()
    args = parse_args()
    
    scanner = Octopops(args.subnet, args.outdir)
    scanner.run()


if __name__ == "__main__":
    main()
