import re
from colorama import Fore, Style

class IPExtractor:
    banner = "[IPExtractor]"

    @staticmethod
    def extract(output: str) -> str | None:
        """
        Extract valid IPv4 addresses from nxc output.

        Args:
            output (str): Raw output string from nxc.

        Returns:
            list: A list of IPv4 addresses (as strings).
        """
        print(f"{Fore.YELLOW}[*]{IPExtractor.banner} Extracting IPs from nxc output...{Style.RESET_ALL}")
        try:
            # Regex for matching valid IPv4 addresses
            ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

            # Find all IPs in the output
            ips = ip_pattern.findall(output)

            # Remove duplicates while preserving order
            seen = set()
            unique_ips = [ip for ip in ips if not (ip in seen or seen.add(ip))]
            extracted_ips = "\n".join(unique_ips)
            return extracted_ips
        
        except Exception as e:
            print(f"{Fore.RED}[!]{IPExtractor.banner} Error extracting IPs from nxc output: {e}{Style.RESET_ALL}")
            return