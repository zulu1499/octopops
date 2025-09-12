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
        required=False,
        default=None,
        type=str,
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
        default="fping,nxc",
        help="Comma-separated list of scanners to run. Choices: fping, nmap, nxc, all"
    )
    
    parser.add_argument(
    "--ip-file",
    type=Path,
    help="Path to a file containing IPs to use instead of running discovery scans, this will skip discovery scans !"
)
    parser.add_argument(
    "--nxc-file",
    type=Path,
    help="Path to a file containing raw output from an nxc scan, used only for nxc processing (extracts eternalblue and domains)," 
     "if you whish to run processing scanners on ips from nxc_file provide it as an --ip-file as well, this will skip discovery scans !"
)
    parser.add_argument(
        "-c",
        "--chunked",
        nargs="?",            # argument is optional
        const=24,             # if provided without a value → use 24
        type=int,             # if provided with a value → cast to int
        default=None,         # if not provided at all → None
        help="Run discovery scans in chunked mode. "
            "If specified without a value, defaults to /24 chunks. "
            "If a value is provided, it specifies the chunk size (e.g., 25 for /25). "
            "Valid range is /9 to /32."
    )
    
    args = parser.parse_args()

    # Validate input files
    for file_arg, name in [(args.ip_file, "IP"), (args.nxc_file, "NXC")]:
        if file_arg:
            if not file_arg.is_file():
                print(f"{Fore.RED}[-] {name} file '{file_arg}' does not exist or is not a file.{Style.RESET_ALL}")
                exit(1)
            elif args.subnet or args.chunked:
                # If an input file is provided, discovery scanners and subnet are ignored
                args.discovery_scanners = ""
                args.subnet = None
                args.chunked = None
                print(f"{Fore.YELLOW}[!] --chunked, --subnet and --discovery_scanner options are ignored when {name} file is provided.{Style.RESET_ALL}")

    # Validate subnet if provided
    if args.subnet and not IPUtils.is_valid_subnet(args.subnet):
        print(f"{Fore.RED}[!] Invalid subnet format: {args.subnet}{Style.RESET_ALL}")
        parser.print_help()
        exit(1)
    elif not args.subnet and not (args.ip_file or args.nxc_file):
        print(f"{Fore.RED}[!] Subnet is required unless --ip-file or --nxc-file is provided.{Style.RESET_ALL}")
        parser.print_help()
        exit(1)


    # Validate discovery scanners
    if args.discovery_scanners:
        scanners = [s.strip().lower() for s in args.discovery_scanners.split(",")]
        args.discovery_scanners = scanners
        for s in scanners:
            if s not in valid_scanners:
                print(f"{Fore.RED}[!] Invalid scanner '{s}'. Choose from: fping, nmap, nxc, all")
                parser.print_help()
                exit(1)

    # # Special handling for 'all' when input files are provided
    # if args.discovery_scanners == ["all"] and (args.ip_file or args.nxc_file):
    #     print(f"{Fore.YELLOW}[!] 'all' option for --discovery_scanners is ignored when IP or NXC file is provided.{Style.RESET_ALL}")
    #     args.discovery_scanners = []

    # Validate chunked value if provided
    if args.chunked and (args.chunked < 9 or args.chunked > 32):
        print(f"{Fore.RED}[!] --chunked value must be between 9 and 32.{Style.RESET_ALL}")
        parser.print_help()
        exit(1)



    return args

def main():
    # banner.print_banner_slowly()

    #check for root
    if not misc.is_root():
        print(f"{Fore.RED}[-] This script requires root privileges. Please run with sudo or as root.{Style.RESET_ALL}")
        exit(1)
        
    args = parse_args()
    
    try:
        if args.ip_file or args.nxc_file:
            sources = []
            if args.ip_file:
                sources.append(f"IP file: {args.ip_file}")
            if args.nxc_file:
                sources.append(f"NXC file: {args.nxc_file}")
            sources_str = " & ".join(sources)

            print(f"{Fore.YELLOW}[!] Provided sources: {sources_str}, skipping discovery scans.{Style.RESET_ALL}")

            # Initialize orchestrator without a subnet or discovery scanners
            orchestrator = Orchestrator(None, args.outdir, [])

            # Pass both files (or None if not provided)
            ip_file_path = args.ip_file if args.ip_file else None
            nxc_file_path = args.nxc_file if args.nxc_file else None
            orchestrator.run_processing_scanners(ip_file_path, nxc_file_path)

        else:
            # Normal discovery scan path
            orchestrator = Orchestrator(args.subnet, args.outdir, args.discovery_scanners)
            orchestrator.run_discovery_scanners(args.chunked)

    except Exception as e:
        print(f"{Fore.RED}[FATAL ERROR] {e}{Style.RESET_ALL}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
