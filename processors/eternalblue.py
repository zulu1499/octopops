import re


class EternalBlueFilter:
    def __init__(self, output: str):
        self.output = output

    def find_vulnerable_hosts(self) -> list[dict[str, str]]:
        vulnerable = []

        ip_version_pattern = re.compile(
            r"(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b).*?\[\*\]\s*"
            r"(?P<version>Windows\s(?:Server\s)?(?:2003|2008|2008 R2|2012|2012 R2|7|8|8\.1)[^\(]*)",
            re.IGNORECASE
        )
        smb1_pattern = re.compile(
            r"(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b).*SMBv1\s*:\s*True",
            re.IGNORECASE
        )

        for line in self.output.splitlines():
            match = ip_version_pattern.search(line) or smb1_pattern.search(line)
            if match:
                ip = match.group("ip")
                reason = match.groupdict().get("version", "SMBv1 enabled")
                if not any(host["ip"] == ip for host in vulnerable):
                    vulnerable.append({"ip": ip, "reason": reason})

        return vulnerable
