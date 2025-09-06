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
files ={"nxc_output_file": Path("test_cme_output.txt"), "fping_output_file": None}

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

# ------------------------------------------- SORT IPS IN ASCENDING -----------------------------------------------

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


# ------------------------------------------- RUN FPING SCANNER -----------------------------------------------

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

        # Write the output to a file
        fping_output_file = outdir / "octopops_fping_results.txt"
        fping_output_file.write_text(fping_output_sorted)
        print(f"{Fore.GREEN}[+] fping scan completed. Results saved to {fping_output_file}{Style.RESET_ALL}")
        print(fping_output_sorted)
        files["fping_output_file"] = fping_output_file

    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] fping failed: {e.stderr.strip()}{Style.RESET_ALL}")


# ------------------------------------------- RUN NXC SCANNER -----------------------------------------------

def run_nxc(subnet, outdir):
    """Run nxc (NetExec) on a subnet and save results to a file."""
    print(f"{Fore.YELLOW}[*] Running nxc on {subnet} ...{Style.RESET_ALL}")
    
    try:
        command = ["nxc", "smb", subnet]
        nxc_output = subprocess.run(command, stdout=None, capture_output=True, text=True)

        # Path(output_file).write_text(nxc_output.stdout)
        nxc_output = nxc_output.stdout.strip()

        if re.search(r"Running nxc against \d+ targets", nxc_output):
            print(f"{Fore.YELLOW}[!] nxc did not return any output (subnet {subnet} empty maybe ?)")
            return

        
        nxc_output_file = outdir / "octopops_nxc_results.txt"
        nxc_output_file_2 = outdir / "octopops_nxc_ips.txt"

        nxc_output_file.write_text(nxc_output)
        print(f"{Fore.GREEN}[+] nxc scan completed. Results saved to {nxc_output_file}{Style.RESET_ALL}")
        
        print(nxc_output)
        files["nxc_output_file"] = nxc_output_file


        
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] nxc failed: {e.stderr.strip()}{Style.RESET_ALL}")

# ------------------------------------------- SPLIT 64 HOSTS BY FILE -----------------------------------------------

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

# ------------------------------------------- FILTER ETERNAL BLUE HOSTS -----------------------------------------------

def filter_eternalblue_hosts(file_content: str, outdir):
    """
    Extract hosts that may be vulnerable to MS17-010 (EternalBlue) from nxc output.

    Criteria:
        - Windows versions <= Windows Server 2012 or Windows 7/8/8.1
        - SMBv1 enabled (True)

    Args:
        nxc_output (str): Raw output string from nxc

    Returns:
        List[Dict[str, str]]: List of dictionaries containing vulnerable IPs and reason
            e.g., [{"ip": "192.168.1.10", "reason": "Windows 7"}, ...]
    """
    potentially_vulnerable_hosts = []
    potentially__vulnerable_ips = []

    try:
        # Regex to match IP + Windows version line
        ip_version_pattern = re.compile(
            r"(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b).*?\[\*\]\s*"
            r"(?P<version>Windows\s(?:Server\s)?(?:2003|2008|2008 R2|2012|2012 R2|7|8|8\.1)[^\(]*)",
            re.IGNORECASE
        )

        # Regex to check SMBv1 enabled
        smb1_pattern = re.compile(r"(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b).*SMBv1\s*:\s*True", re.IGNORECASE)

        # Split output by lines to check each host
        lines = file_content.splitlines()
        for line in lines:
            # Check Windows version
            version_match = ip_version_pattern.search(line)
            smb1_match = smb1_pattern.search(line)

            if version_match:
                ip = version_match.group("ip")
                reason = version_match.group("version")
            elif smb1_match:
                ip = smb1_match.group("ip")
                reason = "SMBv1 enabled"
            else:
                continue

            # Avoid duplicates
            if not any(host["ip"] == ip for host in potentially_vulnerable_hosts):
                potentially_vulnerable_hosts.append({"ip": ip, "reason": reason})
            
            if ip not in potentially__vulnerable_ips:
                potentially__vulnerable_ips.append(ip)

        # Save to output file
        subdir = outdir / "potentially_eternalblue_hosts"
        subdir.mkdir(exist_ok=True)
        
        output_file = subdir / "potentially_vulnerable_hosts.txt"
        with output_file.open("w") as f:
            for host in potentially_vulnerable_hosts:
                f.write(f"Host: {host['ip']} - Reason: {host['reason']}\n")
        
        print(f"{Fore.GREEN}[+] Potential EternalBlue vulnerable hosts (with reason) saved to {output_file}{Style.RESET_ALL}")
        
        output_file_2 = subdir / "potentially_vulnerable_ips.txt"
        output_file_2.write_text("\n".join(potentially__vulnerable_ips))
        print(f"{Fore.GREEN}[+] Potential EternalBlue vulnerable IPs saved to {output_file_2}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error filtering EternalBlue hosts: {e}{Style.RESET_ALL}")
        return

# ------------------------------------------- EXTRACT IPS FROM NXC OUTPUT -----------------------------------------------
def extract_ips_from_nxc(file_content: str, outdir):
    """
    Extract valid IPv4 addresses from nxc output.

    Args:
        output (str): Raw output string from nxc.

    Returns:
        list: A list of IPv4 addresses (as strings).
    """
    print(f"{Fore.YELLOW}[*] Extracting IPs from nxc output...{Style.RESET_ALL}")
    try:
        # Regex for matching valid IPv4 addresses
        ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

        # Find all IPs in the output
        ips = ip_pattern.findall(file_content)

        # Remove duplicates while preserving order
        seen = set()
        unique_ips = [ip for ip in ips if not (ip in seen or seen.add(ip))]
        filtered_ips = "\n".join(unique_ips)

        # Save to output file
        output_file = outdir / "nxc_extracted_ips.txt"
        output_file.write_text(filtered_ips)
        print(f"{Fore.GREEN}[+] Extracted {len(unique_ips)} unique IPs. Saved to {output_file}{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}[!] Error extracting IPs from nxc output: {e}{Style.RESET_ALL}")
        return

# ------------------------------------------- MAIN -----------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="🐙 OctoScanner - simple subnet scanner using fping and nxc")
    parser.add_argument("-s", "--subnet", help="Subnet to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--outdir", default="octopops_results", help="Directory to store results")


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
    

    # ------------------------- Discover hosts using fping + nxc (using threading) -----------------------------
    thread_fping = threading.Thread(target=run_fping, args=(subnet,outdir))
    thread_nxc = threading.Thread(target=run_nxc, args=(subnet,outdir))

    thread_fping.start()
    thread_nxc.start()

    thread_fping.join()
    thread_nxc.join()

    # --------------------------------- Perform further actions on the discovered hosts from both tools ----------------------
    # print(files)

    nxc_output_file = files["nxc_output_file"].read_text()
    filter_eternalblue_hosts(nxc_output_file, outdir)
    extract_ips_from_nxc(nxc_output_file, outdir)


if __name__ == "__main__":
    main()