# Commands

[← Docs index](README.md)

Every command and flag below is taken verbatim from `vex <cmd> --help` on
`vex 1.5.0`. Nothing here is invented.

```
vex [OPTIONS] COMMAND [ARGS]...
```

| Command | Purpose |
|---------|---------|
| [`triage`](#triage) | Fast SOC triage — detection ratio, verdict, families. Minimal API calls. |
| [`investigate`](#investigate) | Deep DFIR investigation — PE info, sandbox, passive DNS, relationships. |
| [`doctor`](#doctor) | Diagnose enricher/service config + connectivity. |
| [`config`](#config) | Manage configuration — save API key, AI provider, show settings. |
| [`addons`](#addons) | Show available addons — AI providers, extras, installation status. |
| [`manual`](#manual) | Show the built-in usage guide. |
| [`tag`](#tag) | Manage IOC tags in the local knowledge base. |
| [`note`](#note) | Manage IOC notes in the local knowledge base. |
| [`watchlist`](#watchlist) | Manage watchlists in the local knowledge base. |
| [`cache-clear`](#cache-clear) | Clear all cached results. |
| [`version`](#version) | Show version. |

---

## triage

```
vex triage [OPTIONS] [IOC]
```

Fast SOC triage. `IOC` is optional — omit it to read one IOC from stdin.

### Input / batch flags

| Flag | Type | Description |
|------|------|-------------|
| `IOC` (arg) | text | IOC to enrich (hash / IP / domain / URL). Reads from stdin if omitted. |
| `--file`, `-f` | path | File with one IOC per line. |
| `--no-dedup` | flag | Disable IOC deduplication (default: dedup enabled). |
| `--max-quota` | int | Cap the number of fresh API lookups this run. Cached IOCs are always served and do not count against the quota. |
| `--no-cache` | flag | Bypass cache and force a fresh API lookup. |
| `--api-key`, `-k` | text | VirusTotal API key (overrides `VT_API_KEY` and config.yaml). |
| `--config`, `-c` | path | Path to a `config.yaml`. |

### Output flags

| Flag | Type | Description |
|------|------|-------------|
| `--output`, `-o` | `json` \| `rich` \| `console` \| `ndjson` | Output format (default: `console`). |
| `--csv` | flag | Output as CSV (triage only; overrides `--output`). |
| `--stix` | flag | Export results as a STIX 2.1 JSON bundle. |
| `--html` | text (path) | Write a self-contained HTML report to this path. IOCs are defanged in the report. Works alongside normal console/rich output. |
| `--defang` | flag | Defang IOCs in output (e.g. `evil.com` → `evil[.]com`). |
| `--alert` | text | Only show results with at least this verdict (`CLEAN`/`UNKNOWN`/`SUSPICIOUS`/`MALICIOUS`). |
| `--summary` | flag | Print a one-line verdict summary to stderr. |
| `--quiet`, `-q` | flag | Suppress the ASCII banner. |

### Analysis flags

| Flag | Type | Description |
|------|------|-------------|
| `--explain`, `-e` | flag | Add an AI-powered threat explanation. Providers: anthropic, openai, ollama. Falls back to a template if unconfigured. See `vex manual ai`. |
| `--explain-model` | text | Override the AI model (e.g. `claude-sonnet-4-20250514`, `gpt-4o`, `llama3`). Requires a provider in `~/.vex/config.yaml`. |
| `--correlate` | flag | Cluster batch IOCs by shared infrastructure (ASN, malware family, contacted IPs/domains, passive DNS). Batch only; no-op for a single IOC. |
| `--from-barb` | flag | Read barb JSON from stdin and use its URLs as IOCs. See [Pipeline](pipeline.md). |
| `--from-sift` | flag | Read sift JSON (TriageReport) from stdin and enrich the IOCs it found. See [Pipeline](pipeline.md). |

**Examples**

```bash
vex triage 8.8.8.8                              # single IOC, console output
vex triage --file iocs.txt -o json              # batch from a file, JSON
vex triage 8.8.8.8 --csv                         # CSV (triage only)
vex triage --file iocs.txt --correlate -o json  # batch + correlation clusters
cat iocs.txt | vex triage --alert SUSPICIOUS     # stdin, show only ≥ SUSPICIOUS
```

---

## investigate

```
vex investigate [OPTIONS] [IOC]
```

Deep DFIR investigation. Shares all `triage` input/output/analysis flags **except
`--csv`** (triage-only), and adds two investigate-only flags:

| Flag | Type | Description |
|------|------|-------------|
| `--timeline` | flag | Show a chronological event timeline (investigate only). |
| `--navigator` | flag | Export an ATT&CK Navigator layer JSON to stdout (investigate only). Redirect to a file: `vex investigate <ioc> --navigator > layer.json`. |

All other flags (`--file`, `--no-dedup`, `--max-quota`, `--no-cache`, `--api-key`,
`--config`, `--output`, `--stix`, `--html`, `--defang`, `--alert`, `--summary`,
`--quiet`, `--explain`, `--explain-model`, `--correlate`, `--from-barb`,
`--from-sift`) behave exactly as in [`triage`](#triage).

> [!NOTE]
> `investigate` is where the [secondary enrichers](enrichment.md) run (AbuseIPDB,
> Shodan, WHOIS, MISP, OpenCTI). `triage` never calls them.

**Examples**

```bash
vex investigate 203.0.113.10                       # deep dive on an IP
vex investigate evil.com --timeline                # add the event timeline
vex investigate <sha256> --navigator > layer.json  # ATT&CK Navigator layer
vex investigate 203.0.113.10 --stix > ioc.json     # STIX 2.1 bundle
```

---

## doctor

```
vex doctor [OPTIONS]
```

Diagnose enricher/service config + connectivity — surfaces silently-failing
enrichers. **Config-only by default** (no network); use `--probe` to test live
connectivity.

| Flag | Type | Description |
|------|------|-------------|
| `--config`, `-c` | path | Path to a `config.yaml`. |
| `--probe` | flag | Test live connectivity (network). Default off: config-only, no network. |
| `--output`, `-o` | `rich` \| `json` | Output format (default: `rich`). |

**Example**

```bash
vex doctor             # which enrichers are configured?
vex doctor --probe     # also test live connectivity
```

See [Configuration → diagnosing](configuration.md#diagnosing-with-vex-doctor).

---

## config

```
vex config [OPTIONS]
```

Manage configuration — save API key, AI provider, show settings. Writes to
`~/.vex/config.yaml`.

| Flag | Type | Description |
|------|------|-------------|
| `--set-api-key` | text | Save the VirusTotal API key to `~/.vex/config.yaml`. |
| `--set-ai-provider` | text | Set the AI provider (`anthropic` \| `openai` \| `ollama` \| `none`). |
| `--set-ai-key` | text | Save the AI provider API key to `~/.vex/config.yaml`. |
| `--show` | flag | Display the active configuration with secrets masked. |

**Examples**

```bash
vex config --set-api-key YOUR_VT_KEY
vex config --set-ai-provider ollama
vex config --show
```

---

## addons

```
vex addons [OPTIONS]
```

Show available addons — AI providers, extras, and installation status. No flags
beyond `--help`. See [Getting started](getting-started.md#install) for sample
output.

---

## manual

```
vex manual [OPTIONS] [TOPIC]
```

Show the built-in usage guide. `TOPIC` is one of: `ai`, `config`, `examples`,
`pipeline`, `addons`. Omit it for the overview.

```bash
vex manual
vex manual pipeline
vex manual ai
```

---

## tag

```
vex tag [OPTIONS] IOC
```

Manage IOC tags in the local knowledge base (`~/.vex/knowledge.db`). `IOC` is
**required**.

| Flag | Type | Description |
|------|------|-------------|
| `--add`, `-a` | text | Tag(s) to add. |
| `--remove`, `-r` | text | Tag(s) to remove. |

```bash
vex tag 8.8.8.8 --add benign-dns
vex tag 203.0.113.10 --remove false-positive
```

Local tags later appear in the `local_tags` field of a `triage` result.

---

## note

```
vex note [OPTIONS] IOC
```

Manage IOC notes in the local knowledge base. `IOC` is **required**.

| Flag | Type | Description |
|------|------|-------------|
| `--add`, `-a` | text | Note text to add. |
| `--delete`, `-d` | int | Note ID to delete. |

```bash
vex note 203.0.113.10 --add "seen in proxy logs 2026-05-29"
vex note 203.0.113.10 --delete 3
```

Notes appear in the `local_notes` field of a result.

---

## watchlist

```
vex watchlist [OPTIONS] NAME
```

Manage watchlists in the local knowledge base. `NAME` is **required**.

| Flag | Type | Description |
|------|------|-------------|
| `--add`, `-a` | text | IOC(s) to add. |
| `--remove`, `-r` | text | IOC(s) to remove. |
| `--list`, `-l` | flag | List all IOCs in this watchlist. |

```bash
vex watchlist priority --add 203.0.113.10
vex watchlist priority --list
```

Watchlist membership appears in the `watchlists` field of a result.

---

## cache-clear

```
vex cache-clear [OPTIONS]
```

Clear all cached results (`~/.vex/cache.db`).

| Flag | Type | Description |
|------|------|-------------|
| `--config`, `-c` | path | Path to a `config.yaml`. |

```bash
vex cache-clear
```

---

## version

```
vex version [OPTIONS]
```

Show the version and the loaded plugins.

```bash
vex version
# vex 1.5.0
# Plugins: VirusTotal
```
