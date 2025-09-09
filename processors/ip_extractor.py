import re
from colorama import Fore, Style

# class IPExtractor:
#     banner = "[IPExtractor]"

#     @staticmethod
#     def extract(output: str) -> str | None:
#         """
#         Extract valid IPv4 addresses from nxc output.

#         Args:
#             output (str): Raw output string from nxc.

#         Returns:
#             list: A list of IPv4 addresses (as strings).
#         """
#         print(f"{Fore.YELLOW}[*]{IPExtractor.banner} Extracting IPs from nxc output...{Style.RESET_ALL}")
#         try:
#             # Regex for matching valid IPv4 addresses
#             ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

#             # Find all IPs in the output
#             ips = ip_pattern.findall(output)

#             # Remove duplicates while preserving order
#             seen = set()
#             unique_ips = [ip for ip in ips if not (ip in seen or seen.add(ip))]
#             extracted_ips = "\n".join(unique_ips)
#             return extracted_ips
        
#         except Exception as e:
#             print(f"{Fore.RED}[!]{IPExtractor.banner} Error extracting IPs from nxc output: {e}{Style.RESET_ALL}")
#             return

import re
import ipaddress
from colorama import Fore, Style

class IPExtractor:
    banner = "[IPExtractor]"

    @staticmethod
    def extract(output: str) -> str:
        """
        Extract valid IPv4 addresses from any text using ipaddress for validation.

        Args:
            output (str): Raw text containing IPs.
            return_list (bool): If True, return a list of IPs. Otherwise, return a string with newline separation.

        Returns:
            str | list[str] | None: Extracted IPs as a newline string or list, or None on error.
        """
        print(f"{Fore.CYAN}[*]{IPExtractor.banner} Extracting IPs...{Style.RESET_ALL}")
        try:
            # Find candidate IPv4 patterns
            ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
            candidates = ip_pattern.findall(output)

            # Validate each candidate with ipaddress.IPv4Address
            seen = set()
            valid_ips = []
            for ip in candidates:
                try:
                    ipaddress.IPv4Address(ip)  # Will raise if invalid
                    if ip not in seen:
                        seen.add(ip)
                        valid_ips.append(ip)
                except ipaddress.AddressValueError:
                    print(f"{Fore.YELLOW}[!]{IPExtractor.banner} Skipping invalid IP: {ip}{Style.RESET_ALL}")
                    continue  # skip invalid IPs

            if not valid_ips:
                return ""

            return "\n".join(valid_ips)

        except Exception as e:
            print(f"{Fore.RED}[-]{IPExtractor.banner} Error extracting IPs: {e}{Style.RESET_ALL}")
            return ""
