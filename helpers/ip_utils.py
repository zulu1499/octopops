import ipaddress
import re
from colorama import Fore, Style

class IPUtils:

    banner = "[IPUtils]"
    # Regex to match a valid IPv4 subnet in CIDR notation
    subnet_regex = re.compile(
        r'^('
        r'(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'  # first octet
        r'(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'  # second octet
        r'(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.'  # third octet
        r'(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'    # fourth octet
        r')/(3[0-2]|[12]?\d)$'                  # CIDR mask /0 - /32
    )

    # Chunk size for subnet splitting, default to /24
    chunk_size = 24

    # ------------------------------------------- VALIDATE SUBNET ------------------------------------------------------
    @staticmethod
    def is_valid_subnet(subnet):
        return bool(IPUtils.subnet_regex.match(subnet))

    # ------------------------------------------- SORT IPS IN ASCENDING -----------------------------------------------
    @staticmethod
    def sort_ips_in_ascending(ips: str) -> str:
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

    # ------------------------------------------- CHUNK SUBNET --------------------------------------------------------
    @staticmethod
    def _chunk_subnet(subnet: str):
        """
        Split a large subnet into /x subnets.

        Args:
            subnet (str): The subnet to split, e.g., "10.0.0.0/16"

        Yields:
            ipaddress.IPv4Network: Each /x subnet within the larger subnet.
        """

        network = ipaddress.IPv4Network(subnet, strict=False)
        if network.prefixlen >= IPUtils.chunk_size:
            yield network  # Network is already smaller than or equal to chunk size
        else:
            for chunk in network.subnets(new_prefix=IPUtils.chunk_size):
                yield chunk