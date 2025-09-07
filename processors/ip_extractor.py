import re


class IPExtractor:
    @staticmethod
    def extract(output: str) -> str:
        ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        ips = ip_pattern.findall(output)
        seen = set()
        ips_list = [ip for ip in ips if not (ip in seen or seen.add(ip))]
        extracted_ips = "\n".join(ips_list)
        return extracted_ips