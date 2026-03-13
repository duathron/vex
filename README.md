<p align="center">
  <img src="vex/vex.png" alt="vex logo" width="200"/>
</p>

<h1 align="center">vex</h1>

<p align="center">
  <b>VirusTotal IOC enrichment for SOC triage and DFIR investigations, straight from your terminal.</b>
</p>

```
 ██╗   ██╗███████╗██╗  ██╗
 ██║   ██║██╔════╝╚██╗██╔╝
 ██║   ██║█████╗   ╚███╔╝
 ╚██╗ ██╔╝██╔══╝   ██╔██╗
  ╚████╔╝ ███████╗██╔╝ ██╗
   ╚═══╝  ╚══════╝╚═╝  ╚═╝
```

---

## Features

- **Auto-detection** of IOC types: MD5, SHA1, SHA256, IPv4, IPv6, Domain, URL
- **Two modes**: `triage` (fast, 1 API call) and `investigate` (deep, multiple calls)
- **Output formats**: JSON (default), Rich tables, plain console, CSV, STIX 2.1
- **MITRE ATT&CK mapping** from sandbox behaviors and VT tags
- **IOC defanging/refanging** for safe sharing (`hxxps[://]evil[.]com`)
- **Automation-ready**: exit codes, `--alert` filtering, `--summary` on stderr
- **Timeline enrichment**: chronological event reconstruction for DFIR
- **Local knowledge base**: tag, annotate, and watchlist IOCs in SQLite
- **Plugin architecture**: extensible enrichment sources via Protocol interface
- **Parallel batch processing** with progress bar for large IOC lists
- **STIX 2.1 export** for threat intelligence sharing
- **SQLite cache** with configurable TTL (default 24h)
- **Rate limiting**: token-bucket, free tier (4 req/min) and premium configurable

---

## Setup

### Prerequisites

- Python 3.11+
- A [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) (free tier works)

### Installation

```bash
git clone https://github.com/duathron/vex.git
cd vex

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -r requirements.txt
pip install -e .
```

### Upgrade

```bash
# If installed from git clone (editable)
cd vex
git pull
pip install -r requirements.txt
pip install -e .

# If installed from PyPI (pip install vex)
pip install --upgrade vex
```

### API Key

Set your API key using **one** of these methods (priority order):

```bash
# Option 1: Per-command flag (highest priority)
vex triage 8.8.8.8 --api-key YOUR_KEY
vex investigate evil.com -k YOUR_KEY

# Option 2: Environment variable
export VT_API_KEY="your-virustotal-api-key"

# Option 3: Save permanently to ~/.vex/config.yaml
vex config --set-api-key YOUR_KEY

# Option 4: Manual config.yaml or .env
# api:
#   key: "your-key"
```

---

## Quickstart

```bash
# Fast triage
vex triage 44d88612fea8a8f36de82e1278abb02f

# Rich terminal output
vex investigate evil-domain.com -o rich

# Batch from file, CSV export
vex triage -f iocs.txt --csv

# Pipe from another tool
echo "8.8.8.8" | vex triage -o rich

# Defanged IOC support
vex triage "hxxps[://]evil[.]com"

# STIX 2.1 export
vex investigate evil.com --stix > bundle.json

# Timeline reconstruction
vex investigate evil.com -o rich --timeline

# Automation: exit code + alert filter + summary
vex triage -f iocs.txt --alert SUSPICIOUS --summary
echo $?  # 0=clean, 1=suspicious, 2=malicious
```

---

## Documentation

### Subcommands

| Command | Description |
|---------|-------------|
| `vex triage <ioc>` | Fast SOC triage (1 API call) |
| `vex investigate <ioc>` | Deep DFIR investigation (multiple calls) |
| `vex config` | Manage configuration (save API key, etc.) |
| `vex cache-clear` | Clear the SQLite result cache |
| `vex version` | Show version |
| `vex tag <ioc>` | Manage IOC tags in local knowledge base |
| `vex note <ioc>` | Manage IOC notes in local knowledge base |
| `vex watchlist <name>` | Manage IOC watchlists |

### Triage / Investigate Options

| Flag | Description |
|------|-------------|
| `-k` / `--api-key` | VirusTotal API key (overrides env var & config) |
| `-q` / `--quiet` | Suppress the ASCII banner |
| `-o` / `--output` | Output format: `json` \| `rich` \| `console` (default: `console`) |
| `-f` / `--file` | File with one IOC per line |
| `-c` / `--config` | Custom config.yaml path |
| `--no-cache` | Bypass cache, force fresh lookup |
| `--csv` | CSV output (triage only) |
| `--defang` | Defang IOCs in output |
| `--stix` | Export as STIX 2.1 JSON bundle |
| `--alert <LEVEL>` | Only show results >= verdict level |
| `--summary` | Print verdict summary to stderr |
| `--timeline` | Show chronological timeline (investigate only) |

### Configuration Command

Manage vex configuration:

```bash
# Save API key permanently
vex config --set-api-key YOUR_KEY

# Show usage
vex config
```

Saved config is stored at `~/.vex/config.yaml` with restricted permissions (0o600).

### IOC Types

| Type | Example |
|------|---------|
| MD5 | `44d88612fea8a8f36de82e1278abb02f` |
| SHA1 | `3395856ce81f2b7382dee72602f798b642f14140` |
| SHA256 | `275a021bbfb6489e54d471899f7db9d1663fc695...` |
| IPv4 | `8.8.8.8` |
| IPv6 | `2001:4860:4860::8888` |
| Domain | `example.com` |
| URL | `https://example.com/malware.exe` |

Defanged IOCs are automatically refanged before lookup:
`hxxps[://]evil[.]com` becomes `https://evil.com`.

### Verdict System

| Verdict | Condition | Exit Code |
|---------|-----------|-----------|
| **MALICIOUS** | >= 3 malicious detections | 2 |
| **SUSPICIOUS** | >= 1 malicious detection | 1 |
| **UNKNOWN** | Zero detections OR too few engines | 0 |
| **CLEAN** | Zero detections AND enough engines | 0 |

**Zero detections does not mean CLEAN.** If too few engines reported, the verdict is UNKNOWN.

### MITRE ATT&CK Mapping

In `investigate` mode, vex maps sandbox behaviors and VT tags to MITRE ATT&CK techniques. Mappings cover 80+ keywords across all major tactics (Execution, Persistence, Defense Evasion, etc.) and appear in Rich output and STIX exports.

### Knowledge Base

Manage local IOC metadata that persists across sessions:

```bash
# Tag IOCs
vex tag 8.8.8.8 --add dns --add google
vex tag 8.8.8.8  # list tags

# Add notes
vex note evil.com --add "Seen in phishing campaign Q4"
vex note evil.com  # list notes

# Watchlists
vex watchlist priority --add 8.8.8.8 --add evil.com
vex watchlist priority --list
```

### Plugin Architecture

vex uses a Protocol-based plugin system. The built-in VirusTotal plugin implements `EnricherProtocol`. Third-party sources (OTX, AbuseIPDB, etc.) can be added by implementing the same protocol.

---

## Config Reference

```yaml
api:
  # key: "your-key"        # or set VT_API_KEY env var
  tier: free                # free | premium
  rate_limit:
    free:
      requests_per_minute: 4
      requests_per_day: 500
    premium:
      requests_per_minute: 1000
      requests_per_day: 50000

thresholds:
  malicious_min_detections: 3
  suspicious_min_detections: 1
  min_engines_for_clean: 10

cache:
  enabled: true
  ttl_hours: 24
  # db_path: "/custom/path/cache.db"  # default: ~/.vex/cache.db

output:
  default_format: json
  quiet: false  # suppress banner (-q)
```

---

## Project Structure

```
vex/
├── __init__.py          # Package version (1.0.0)
├── main.py              # Typer CLI app with all subcommands
├── banner.py            # ASCII art banner (ffuf-style)
├── client.py            # Sync VT API v3 client + rate limiter
├── async_client.py      # Async VT API client for parallel ops
├── config.py            # Pydantic config from config.yaml
├── cache.py             # SQLite result cache with TTL
├── ioc_detector.py      # Regex auto-detection of IOC types
├── defang.py            # IOC defanging/refanging
├── models.py            # Pydantic v2 models + Verdict enum
├── batch.py             # Parallel batch processing
├── timeline.py          # Timeline event reconstruction
├── vex.png              # Logo
├── enrichers/
│   ├── base.py          # Shared enricher utilities
│   ├── protocol.py      # EnricherProtocol interface
│   ├── hash.py          # MD5/SHA1/SHA256 enrichment
│   ├── ip.py            # IPv4/IPv6 enrichment
│   ├── domain.py        # Domain enrichment
│   └── url.py           # URL enrichment
├── plugins/
│   ├── registry.py      # Plugin discovery & registration
│   ├── loader.py        # Plugin loading
│   └── virustotal.py    # Built-in VT plugin
├── mitre/
│   ├── mapping.py       # VT behavior → ATT&CK technique dict
│   └── mapper.py        # Result → ATT&CK mapping engine
├── knowledge/
│   ├── db.py            # SQLite knowledge base (tags/notes/watchlists)
│   └── api.py           # High-level knowledge base API
└── output/
    ├── formatter.py     # Rich + console + timeline formatters
    ├── export.py        # JSON + CSV export
    └── stix.py          # STIX 2.1 bundle generation
```

---

*Built by [Christian Huhn](https://github.com/duathron) — [github.com/duathron/vex](https://github.com/duathron/vex)*
