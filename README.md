<p align="center">
  <img src="vex/vex.png" alt="vex logo" width="200"/>
</p>

<h1 align="center">vex</h1>

<p align="center">
  <b>VirusTotal IOC enrichment for SOC triage and DFIR investigations, straight from your terminal.</b>
</p>

<div align="center">
<pre>
 ██╗   ██╗███████╗██╗  ██╗
 ██║   ██║██╔════╝╚██╗██╔╝
 ██║   ██║█████╗   ╚███╔╝
 ╚██╗ ██╔╝██╔══╝   ██╔██╗
  ╚████╔╝ ███████╗██╔╝ ██╗
   ╚═══╝  ╚══════╝╚═╝  ╚═╝
</pre>
</div>

---

## Features

- **Auto-detection** of IOC types: MD5, SHA1, SHA256, IPv4, IPv6, Domain, URL
- **Two modes**: `triage` (fast, 1 API call) and `investigate` (deep, multiple calls)
- **Output formats**: JSON (default), Rich tables, plain console, CSV, STIX 2.1
- **MITRE ATT&CK mapping** from sandbox behaviors and VT tags
- **ATT&CK Navigator export**: `--navigator` to export ATT&CK layer JSON for Navigator
- **IOC defanging/refanging** for safe sharing (`hxxps[://]evil[.]com`)
- **Automation-ready**: exit codes, `--alert` filtering, `--summary` on stderr
- **Timeline enrichment**: chronological event reconstruction for DFIR
- **Local knowledge base**: tag, annotate, and watchlist IOCs in SQLite
- **Plugin architecture**: extensible enrichment sources via Protocol interface
- **Parallel batch processing** with progress bar for large IOC lists
- **STIX 2.1 export** for threat intelligence sharing
- **WHOIS enrichment**: direct WHOIS lookups for domain IOCs (included in base install)
- **SQLite cache** with configurable TTL (default 24h)
- **AI-powered explanations**: `--explain` for threat narratives via Claude, OpenAI, or Ollama (opt-in)
- **barb pipeline**: `--from-barb` to combine barb heuristic pre-scan with VT enrichment
- **Addon discoverability**: `vex addons` shows available extras and install status
- **Rate limiting**: token-bucket, free tier (4 req/min) and premium configurable

> **Part of the security portfolio:** Use [**barb**](https://github.com/duathron/barb) for offline heuristic phishing URL triage. Use **vex** for VirusTotal IOC enrichment. Pipe barb JSON output into vex for full enrichment (v1.2).

---

## Setup

### Prerequisites

- Python 3.11+
- A [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) (free tier works)

### Installation

**From PyPI (recommended):**

```bash
pip install vex-ioc

# With AI support (Claude + OpenAI)
pip install vex-ioc[ai]

# Ollama (local models) works out of the box — no extras needed
# WHOIS enrichment is included in the base install (core dep since v1.2.0)
```

> **Kali Linux / Debian / system Python?** Use `pipx` to avoid system package conflicts:
> ```bash
> sudo apt install pipx && pipx ensurepath
> pipx install vex-ioc
> pipx install "vex-ioc[ai]"   # with AI support
> ```

After installation, run `vex addons` to see all available extras and their status.

**From source:**

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
# If installed from PyPI
pip install --upgrade vex-ioc

# If installed from git clone (editable)
cd vex
git pull
pip install -r requirements.txt
pip install -e .
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

# AI-powered explanation (template fallback if no LLM configured)
vex triage 44d88612fea8a8f36de82e1278abb02f --explain

# With Claude as AI provider
vex investigate evil.com -o rich --explain --explain-model claude-sonnet-4-20250514

# Show active configuration
vex config --show

# Automation: exit code + alert filter + summary
vex triage -f iocs.txt --alert SUSPICIOUS --summary
echo $?  # 0=clean, 1=suspicious, 2=malicious

# barb → vex pipeline (combine heuristic pre-scan with VT enrichment)
barb analyze https://evil.com -o json | vex triage --from-barb -o rich
barb analyze https://evil.com -o json | vex investigate --from-barb -o rich

# ATT&CK Navigator layer export
vex investigate evil.com --navigator > layer.json
# Open layer.json at https://mitre-attack.github.io/attack-navigator/

# Domain WHOIS enrichment (included in base install since v1.2.0)
vex investigate evil.com -o rich   # WHOIS panel shown automatically
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
| `vex addons` | Show available extras and installation status |
| `vex tag <ioc>` | Manage IOC tags in local knowledge base |
| `vex note <ioc>` | Manage IOC notes in local knowledge base |
| `vex watchlist <name>` | Manage IOC watchlists |
| `vex manual [topic]` | Show usage guide (topics: ai, config, examples, pipeline, addons) |

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
| `-e` / `--explain` | Add AI-powered threat explanation to output |
| `--explain-model` | Override AI model (e.g. `claude-sonnet-4-20250514`, `gpt-4o`, `llama3`) |
| `--from-barb` | Read barb JSON from stdin, use URLs as IOCs (triage & investigate) |
| `--navigator` | Export ATT&CK Navigator layer JSON to stdout (investigate only) |

### Configuration Command

Manage vex configuration:

```bash
# Save API key permanently
vex config --set-api-key YOUR_KEY

# Show active configuration (API keys masked)
vex config --show
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

### ATT&CK Navigator Export

Export investigation results as an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) v4.5 layer JSON:

```bash
# Export a Navigator layer
vex investigate evil.com --navigator > layer.json

# Open layer.json at https://mitre-attack.github.io/attack-navigator/
# Click "Open Existing Layer" → upload layer.json
```

The layer visualizes all mapped techniques with a red heat gradient, tactic labels, and evidence comments. Requires at least one `investigate` result with ATT&CK mappings.

### WHOIS Enrichment

In `investigate` mode, vex automatically performs a direct WHOIS lookup for domain IOCs. This is especially useful for free-tier VT users (VT WHOIS is a premium feature). `python-whois` is included in the base install since v1.2.0 — no extra needed.

```bash
# WHOIS data appears automatically in rich/console output
vex investigate evil.com -o rich
```

To disable: set `enrichment.whois_enabled: false` in `~/.vex/config.yaml`.

### barb → vex Pipeline

Combine [**barb**](https://github.com/duathron/barb) offline heuristic analysis with VirusTotal live enrichment:

```bash
# Install barb
pip install barb-phish

# Pipe barb JSON into vex triage
barb analyze https://evil.com -o json | vex triage --from-barb -o rich

# Deep investigation with barb context
barb analyze https://evil.com -o json | vex investigate --from-barb -o rich

# Batch: screen multiple URLs, enrich high-risk ones
barb analyze -f urls.txt -o json | vex triage --from-barb --alert SUSPICIOUS -o rich

# JSON output includes barb_context field
barb analyze https://evil.com -o json | vex triage --from-barb -o json
```

**Workflow:** barb runs offline (no HTTP requests to target), providing instant verdict + signal breakdown. vex then enriches with live VT detection data. The `--from-barb` flag reads barb's JSON from stdin, extracts URLs as IOCs, and displays a "barb pre-scan" panel alongside VT results.

See `vex manual pipeline` for full documentation.

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
├── __init__.py          # Package version (1.2.0)
├── main.py              # Typer CLI app with all subcommands
├── banner.py            # ASCII art banner (ffuf-style)
├── client.py            # Sync VT API v3 client + rate limiter
├── async_client.py      # Async VT API client for parallel ops
├── config.py            # Pydantic config from config.yaml
├── cache.py             # SQLite result cache with TTL
├── ioc_detector.py      # Regex auto-detection of IOC types
├── defang.py            # IOC defanging/refanging
├── models.py            # Pydantic v2 models + Verdict enum
├── addons.py            # Addon registry + get_addon_status()
├── batch.py             # Parallel batch processing
├── timeline.py          # Timeline event reconstruction
├── version_check.py     # PyPI update check
├── vex.png              # Logo
├── ai/
│   ├── __init__.py      # Provider factory + availability
│   ├── protocol.py      # LLMProviderProtocol interface
│   ├── prompt.py        # Prompt builder (input sanitization)
│   ├── template.py      # Template-based fallback (no LLM)
│   ├── cache.py         # AI response cache (SQLite, 72h TTL)
│   ├── anthropic.py     # Claude provider
│   ├── openai.py        # OpenAI provider
│   └── ollama.py        # Ollama local provider
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
├── pipeline/
│   ├── __init__.py      # Package marker
│   └── barb_bridge.py   # barb JSON parser, BarbContext model
└── output/
    ├── formatter.py     # Rich + console + timeline + barb formatters
    ├── export.py        # JSON + CSV export
    ├── stix.py          # STIX 2.1 bundle generation
    └── navigator.py     # ATT&CK Navigator layer export
```

---

## Changelog

### 2026-03-18
- **v1.2.0** — AI integration: `--explain` flag for AI-powered threat narratives (Claude, OpenAI, Ollama), template-based fallback, AI response caching (72h), `vex config --show`, optional deps (`pip install vex-ioc[ai]`)
- **v1.2.0** — barb pipeline: `--from-barb` to pipe barb heuristic JSON into vex triage/investigate, barb pre-scan panel in Rich/console output, `barb_context` field in JSON output
- **v1.2.0** — WHOIS enrichment: direct WHOIS lookups for domains via python-whois (now a **core dependency**), free-tier supplement for VT premium WHOIS
- **v1.2.0** — ATT&CK Navigator export: `--navigator` to generate Navigator v4.5 layer JSON from investigation results
- **v1.2.0** — `vex manual pipeline` topic, updated `vex manual examples` with new flags
- **v1.2.0** — Addon discoverability (MeetUp VEX-2026-007): `vex addons` command, addon status in `vex config --show`, one-time first-run hint, `vex manual addons` topic, AI/Template explanation labels
- **v1.2.0** — `pipx` install documented for Kali/Debian/system-Python environments

### 2026-03-16
- **v1.1.0** — Resolved all known limitations: batch processing activated, premium endpoint graceful degradation, entry-point plugin discovery, IPv6 detection upgraded to RFC 4291, passive version update check
- **PyPI** — Package published as [`vex-ioc`](https://pypi.org/project/vex-ioc/) (`pip install vex-ioc`); CLI command remains `vex`
- **CI/CD** — GitHub Actions workflow added: automatic PyPI publish on `v*.*.*` tag push
- **License** — LICENSE.md added (MIT)
- **v1.0.1** — UX improvements: color-coded console verdicts, batch failure count, alert filter feedback, config.yaml.example schema fix, consistent list truncation

### 2026-03-13
- **v1.0.0** — Initial release: triage & investigate, MITRE ATT&CK mapping, STIX 2.1, knowledge base, timeline, plugin architecture, rate limiting, SQLite cache

---

*Built by [Christian Huhn](https://github.com/duathron) — [github.com/duathron/vex](https://github.com/duathron/vex)*
