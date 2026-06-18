# 🐙 Octopops

> Internal Pentest Subnet Dissector — a root-only Linux CLI that wraps `fping`, `nxc` (NetExec) and `nmap` into a single two-phase recon pipeline for authorized internal-network assessments.

Octopops sweeps a subnet for live hosts (phase 1: **discovery**), merges and de-duplicates the results, then automatically port-scans the discovered hosts and stores structured findings in a SQLite database (phase 2: **processing**). Along the way it mines `nxc` SMB output for EternalBlue/MS17-010 candidates, SMB-relay targets (signing disabled) and unique domains.

---

## ✨ Features

- **Two-phase pipeline** — host discovery feeds directly into port-scan processing, in one run.
- **Three discovery scanners**, run concurrently in threads:
  - `fping` — fast ICMP host sweep.
  - `nxc` — NetExec SMB enumeration.
  - `nmap` — ICMP/ARP ping sweep (`-sn -n`).
- **IP merge & sort** — results from every scanner are merged, de-duplicated and numerically sorted into a single host list.
- **nxc output mining** (from live scans *or* a saved `nxc` output file):
  - 🩸 **EternalBlue / MS17-010 candidates** — flags hosts running legacy Windows or with `SMBv1: True`.
  - 🔁 **SMB-relay targets** — extracts hosts advertising `(signing:False)`.
  - 🌐 **Unique domains** — pulls every `(domain:...)` value seen.
- **Automated nmap port-scan processing** — runs `nmap --open -Pn` against the discovered hosts, parses the XML, and writes results to SQLite.
- **Chunked discovery mode** — split a large supernet into smaller subnets (default `/24`) and scan/append incrementally.
- **Large-list batching** — host lists over 64 entries are automatically split into 64-host files for the nmap processing stage.
- **Processing-only modes** — feed an existing IP list (`--ip-file`) or raw `nxc` output (`--nxc-file`) and skip discovery entirely.

---

## 📦 Requirements

**Python**

- Python **3.8+**
- Third-party Python dependency (installed via `requirements.txt`): **`colorama`**

Everything else Octopops uses on the Python side is from the standard library (`argparse`, `ipaddress`, `pathlib`, `sqlite3`, `subprocess`, `threading`, `xml.etree`, …).

**External binaries** (these are **not** pip packages — install them with your system package manager)

| Binary | Used by |
| ------ | ------- |
| `fping` | fping discovery scanner |
| `nmap`  | nmap discovery scanner + nmap processing scanner |
| `nxc`   | nxc (NetExec) discovery scanner |

**Privileges**

- Octopops **must run as root** (it checks `os.geteuid() == 0` and exits otherwise). Run it with `sudo` or as the root user.

---

## 🚀 Installation

```bash
# 1. Clone
git clone https://github.com/<your-org>/octopops.git
cd octopops

# 2. Install the Python dependency
pip install -r requirements.txt

# 3. Install Octopops to get the `octopops` console command
pip install .
```

After `pip install .`, the `octopops` command is available on your `PATH` (it maps to `octopops:main`).

> ⚠️ Octopops requires root. Invoke it with `sudo` (and make sure `fping`, `nmap` and `nxc` are reachable on root's `PATH`):
>
> ```bash
> sudo octopops -s 192.168.1.0/24
> ```

You can also run it directly from the source tree without installing:

```bash
sudo python3 octopops.py -s 192.168.1.0/24
```

---

## 🧭 Usage

```
octopops [-h] [-s SUBNET] [-o OUTDIR] [-ds DISCOVERY_SCANNERS]
         [--ip-file IP_FILE] [--nxc-file NXC_FILE] [-c [CHUNKED]]
```

### CLI flags

| Flag | Alias | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--subnet` | `-s` | `None` | Subnet to scan in CIDR notation, e.g. `192.168.1.0/24`. **Required unless** `--ip-file` or `--nxc-file` is given. Validated against a CIDR regex (`/0`–`/32`). |
| `--outdir` | `-o` | `octopops_results` | Directory (created under the current working directory) where all results are written. |
| `--discovery_scanners` | `-ds` | `fping,nxc` | Comma-separated list of discovery scanners. Valid choices: `fping`, `nmap`, `nxc`, `all` (`all` runs every scanner). |
| `--ip-file` | | `None` | Path to a file of IPs to feed straight into processing. **Skips discovery.** |
| `--nxc-file` | | `None` | Path to a file containing raw `nxc` output, used only for nxc processing (EternalBlue, SMB-relay targets, domains). **Skips discovery.** To also run the nmap processing stage on those IPs, pass the same hosts via `--ip-file`. |
| `--chunked` | `-c` | `None` | Run discovery in chunked mode. Used **with no value** → chunks of `/24`. Given **with a value** (`nargs='?'`, e.g. `-c 25`) → that prefix length. Valid range: **`/9` to `/32`**. |

**Notes on behavior**

- If `--ip-file` or `--nxc-file` is provided, discovery is skipped and `--subnet`, `--discovery_scanners` and `--chunked` are ignored (you'll see a yellow warning if you also passed `--subnet`/`--chunked`).
- An invalid subnet, an out-of-range `--chunked` value, or an unknown scanner name all cause Octopops to print help and exit. A missing/invalid `--ip-file` or `--nxc-file` prints an error and exits (without printing help).

### Examples

**Basic subnet scan** (default scanners: `fping,nxc`):

```bash
sudo octopops -s 192.168.1.0/24
```

**Choose specific discovery scanners:**

```bash
# Only nmap discovery
sudo octopops -s 10.0.0.0/24 -ds nmap

# Run them all
sudo octopops -s 10.0.0.0/24 -ds all
```

**Custom output directory:**

```bash
sudo octopops -s 192.168.1.0/24 -o engagement_acme
```

**Chunked mode** (split a large supernet):

```bash
# Default /24 chunks
sudo octopops -s 10.0.0.0/16 -c

# /25 chunks
sudo octopops -s 10.0.0.0/16 -c 25
```

**Processing-only: feed an existing IP list** (skips discovery, runs nmap processing):

```bash
sudo octopops --ip-file live_hosts.txt
```

**Processing-only: mine a saved `nxc` output file** (EternalBlue, SMB-relay targets, domains):

```bash
sudo octopops --nxc-file nxc_smb_output.txt
```

**Mine `nxc` output *and* port-scan those hosts** (provide the same hosts both ways):

```bash
sudo octopops --nxc-file nxc_smb_output.txt --ip-file live_hosts.txt
```

---

## 🌳 Example output tree

All paths below are written under your `--outdir` (default `octopops_results/`). Exactly which files appear depends on which scanners ran and how many hosts were found.

```
octopops_results/
├── fping_raw_results.txt                         # raw fping results (non-chunked runs)
├── nxc_raw_results.txt                            # raw nxc results (non-chunked runs)
├── nmap_raw_results.txt                           # raw nmap results (non-chunked runs)
├── nxc_discovery_scanner_extracted_ips.txt       # IPs extracted from nxc output
├── nmap_discovery_scanner_extracted_ips.txt      # IPs extracted from nmap output
├── all_discovery_scanners_ips.txt                # merged, de-duplicated, sorted host list
│
├── nxc_processing/                               # produced from nxc output mining
│   ├── nxc_eternalblue_ips.txt                   # EternalBlue/MS17-010 candidate IPs
│   ├── nxc_eternalblue_hosts.txt                 # "Host: <ip> - Reason: <reason>" lines
│   ├── smb_relay_targets.txt                     # hosts with SMB signing disabled
│   └── nxc_extracted_unique_domains.txt          # unique (domain:...) values
│
├── 64_ip_per_file_for_nmap/                      # only when > 64 hosts: split lists
│   ├── subnet_chunk_1.txt
│   └── subnet_chunk_2.txt
│
└── nmap_processing/
    ├── nmap_scan_results.db                       # SQLite DB (table: hosts_ports)
    ├── nmap_scan_results.txt                      # nmap normal output (≤ 64 hosts path)
    └── chunked_scans_result/                      # nmap output per 64-host chunk (> 64 hosts path)
        ├── nmap_chunk_result_1.txt
        └── nmap_chunk_result_2.txt
```

Notes:

- In **chunked discovery mode**, scanners append to `<scanner>_raw_results.txt` incrementally instead of writing one final raw file.
- The `nxc_processing/` files appear only when nxc discovery (or `--nxc-file`) produced output.
- `nmap_scan_results.txt` is written when the host list is **≤ 64**; for larger lists, per-chunk files land under `chunked_scans_result/` instead.

---

## ⚙️ How it works

Octopops is coordinated by `core/orchestrator.py`, which runs the two phases in sequence.

```
                 ┌─────────────────────────────────────────────┐
                 │            PHASE 1 — DISCOVERY              │
                 │   (threaded, one thread per chosen scanner) │
                 │                                             │
   subnet ──────▶│   fping ─┐                                  │
                 │   nxc   ─┼──▶ extract IPs ──▶ merge + sort  │
                 │   nmap  ─┘        │                         │
                 │                   ▼                         │
                 │     all_discovery_scanners_ips.txt          │
                 └──────────────────┬──────────────────────────┘
                                    │
   nxc output ────────────┐         │ (also: --ip-file / --nxc-file
   mining (EternalBlue,   │         │  enter directly at phase 2)
   SMB-relay, domains) ◀──┘         ▼
                 ┌─────────────────────────────────────────────┐
                 │           PHASE 2 — PROCESSING              │
                 │                                             │
                 │   host list ──▶ nmap --open -Pn (-oX/-oN)   │
                 │        │              │                     │
                 │        │       (split into 64-host files    │
                 │        │        when > 64 hosts)            │
                 │        ▼              ▼                     │
                 │   XML ──▶ JSON ──▶ SQLite (hosts_ports)     │
                 └─────────────────────────────────────────────┘
```

**Phase 1 — Discovery** (`run_discovery_scanners`)

- For each selected scanner (`fping`, `nxc`, `nmap`), a scanner object is created and started in its own thread; the orchestrator waits for all threads to finish.
  - **fping** runs `fping -a -s -g -q <subnet>` and sorts the live IPs.
  - **nxc** runs `nxc smb --no-progress <subnet>` and keeps the raw SMB output.
  - **nmap** runs `sudo nmap -sn -n <subnet>` (ICMP/ARP ping sweep).
- In chunked mode, each scanner iterates the supernet split into `/chunk_size` subnets and appends results per chunk.
- **nxc output mining** (`output_processing_nxc`) extracts IPs and writes the four `nxc_processing/` files:
  - **EternalBlue/MS17-010** (`processors/eternalblue.py`): flags any host line matching legacy Windows versions (2003/2008/2012/XP/7/8/8.1, …) or `SMBv1: True`.
  - **SMB-relay targets**: hosts whose line contains `(signing:False)`.
  - **Unique domains**: every distinct `(domain:...)` value.
- IPs from all scanners are merged, de-duplicated and numerically sorted into `all_discovery_scanners_ips.txt`.

**Phase 2 — Processing** (`run_processing_scanners`)

- Initializes the SQLite DB `nmap_processing/nmap_scan_results.db` with a `hosts_ports` table (`ip, port, protocol, service, version`, unique on `ip+port+protocol`).
- If the host list has **more than 64** entries, it is split into 64-host files (`64_ip_per_file_for_nmap/subnet_chunk_*.txt`) and each is scanned in turn, with output under `chunked_scans_result/`.
- Otherwise a single `sudo nmap -iL <list> --open -Pn -oX - -oN nmap_scan_results.txt` run is performed.
- For each scan, the nmap **XML** is parsed (`processors/xml_to_json.py`) into a JSON mapping of `ip → [open ports]`, which is inserted into the database (`processors/db.py`).

**Direct-to-phase-2 modes**

- `--ip-file`: IPs are extracted/validated, sorted, written to `all_discovery_scanners_ips.txt`, then processed.
- `--nxc-file`: the file's raw `nxc` text is run through the same nxc mining as a live scan.

---

## 🗂️ Project Structure

```
octopops.py                       # CLI entry point (argparse, root check, validation, dispatch)
core/
  orchestrator.py                 # two-phase coordinator (discovery -> processing)
discovery_scanners/
  base_scanner.py                 # DiscoveryScanner base class (run/save/append/extract_ips)
  fping_scanner.py                # fping host sweep
  nxc_scanner.py                  # NetExec SMB enum + eternalblue/relay/domain extraction
  nmap_scanner.py                 # nmap -sn ping sweep
processing_scanners/
  base_processing_scanner.py      # ProcessingScanner base class
  nmap_processing_scanner.py      # nmap port-scan + XML->JSON->SQLite
processors/
  db.py                           # SQLite init + insert (hosts_ports table)
  eternalblue.py                  # EternalBlue/MS17-010 candidate filter
  ip_extractor.py                 # IPv4 extraction & validation
  xml_to_json.py                  # nmap XML -> JSON parser
helpers/
  ip_utils.py                     # subnet validation, sorting, chunking
  misc.py                         # merge/sort, IP-list splitting, root checks
  banner.py                       # banner art
setup.py                          # packaging + `octopops` console script
requirements.txt                  # colorama
.gitignore
```

---

## 🗺️ Roadmap

These are **future ideas, not implemented** in this release:

- Additional discovery scanners (e.g. `masscan`, `httpx`).
- More vulnerability/service processing modules and nmap NSE integration.
- Service-credential and Kerberos enumeration helpers.
- Exporters for downstream tools (e.g. BloodHound, Metasploit).
- A richer interactive interface / TUI.
- A test suite and CI.

---

## 🤝 Contributing

Contributions are welcome. Please:

1. Fork the repo and create a feature branch.
2. Keep changes focused and consistent with the existing procedural structure.
3. Test against a lab network you control before opening a PR.
4. Open a pull request describing the change and its motivation.

---

## ⚠️ Disclaimer

Octopops is intended **solely for authorized security testing**. Running network discovery and port scans against systems you do not own or do not have explicit, written permission to test may be illegal. You are responsible for ensuring you have proper authorization. The authors accept no liability for misuse or for any damage caused by this tool. 🐙
