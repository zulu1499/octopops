# 🐙 Octopops

**Octopops** is a fast and extensible **internal network dissection tool** designed for penetration testers.  
It automates subnet discovery, service enumeration, and vulnerability checks to help you quickly identify valuable attack surfaces inside corporate networks.

---

## 🚀 Features
- **Host Discovery**
  - Uses `fping` to quickly enumerate live hosts.
- **Service Enumeration**
  - Uses `nxc (NetExec)` to identify SMB hosts and gather OS information.
- **Vulnerability Detection**
  - Identifies potential **EternalBlue (MS17-010)** vulnerable hosts (Windows 2003 → Windows 8.1, SMBv1 enabled).
- **Automation Ready**
  - Results are written into structured files for further use.
  - Splits large subnets into manageable chunks.
- **Modular Design**
  - Built with an OOP architecture (scanners & processors).
  - Easy to add new modules (e.g., web discovery, printers, masscan, aquatone).
- **Universal CLI Tool**
  - Install once → run `octopops` from any directory.
  - Output is always saved in your **current working directory**.

---

## 📦 Installation

Clone the repository:
```bash
git clone https://github.com/<your-username>/octopops.git
cd octopops
```
Install globally:
```bash
pip3 install .
```

---

## 🛠️ Requirements

* Python 3.8+

* fping (host discovery)

* NetExec (nxc) (SMB scanner)

* colorama (output formatting)

---

## Install Python dependencies:
```bash
pip install -r requirements.txt
```

---

## 🐙 Usage

Basic scan:
```bash
octopops -s 192.168.0.0/24 -o octopops_results
```
`Results are saved under: ./octopops_results/`

## Example output:
```bash
octopops_results/
├── octopops_fping_results.txt
├── octopops_nxc_results.txt
├── nxc_extracted_ips.txt
├── potentially_eternalblue_hosts/
│   ├── potentially_vulnerable_hosts.txt
│   └── potentially_vulnerable_ips.txt
```

---

## 🔧 Roadmap

Planned features:

* Web discovery via httpx / aquatone

* Printer discovery

* Masscan integration for lightning-fast scans

* Banner grabbing

---

## 📂 Project Structure

octopops/
├── core/orchestrator.py      # Main runner
├── scanners/            # Scanners (fping, nxc, etc.)
├── processors/          # Post-processing modules (filters, reports, etc.)
├── utils/               # Helper functions (IP sorting, parsing)
└── setup.py             # Setup for pip install

---

## 🤝 Contributing

    Fork the repo

    Create a feature branch (git checkout -b feature-xyz)

    Commit your changes (git commit -m "Added xyz feature")

    Push to your fork (git push origin feature-xyz)

    Create a Pull Request

---

## ⚠️ Disclaimer

This tool is provided for educational and penetration testing purposes only.
Do not use it on networks without explicit authorization.
The author is not responsible for any misuse or damage caused.