# vex — Project History and Documentation

**Author:** Christian Huhn (GitHub: [duathron](https://github.com/duathron))
**Version:** 1.1.0
**Date:** 2026-03-13
**Repository:** https://github.com/duathron/vex

---

## The Idea

### The Problem

SOC analysts and DFIR responders spend significant time manually querying the same APIs: open the VirusTotal web interface, paste a hash, wait, screenshot, next IOC. With dozens or hundreds of hashes, IPs, and domains per incident, this becomes tedious busywork that distracts from actual analysis.

Free tools exist, but they come with trade-offs: JSON dumps without interpretation, no rate limiting for free-tier accounts, no automation-friendly exit codes, or support for only a single IOC type. Integrating results into SIEM pipelines or playbooks rarely works without manual post-processing.

### The Solution

vex (VirusTotal IOC Enrichment Tool) addresses this directly. It is a Python CLI that:

- **auto-detects** the IOC type (hash, IP, domain, URL),
- **offers two modes**: fast triage lookup (1 API call) and deep DFIR investigation (multiple calls with sandbox, passive DNS, relationships),
- **is automation-ready** through defined exit codes, `--alert` filtering, and machine-readable JSON output,
- **fits into the terminal** with Rich output and colour-coded verdicts,
- **supports analyst workflows** through a local knowledge base, defanging, and timeline reconstruction.

The goal was not a full SOAR system, but a precise, fast tool for the terminal-first analyst that integrates into existing pipelines.

---

## Technical Architecture

### Stack and Dependencies

Dependencies were kept deliberately minimal:

| Package | Purpose |
|---|---|
| `typer` | CLI framework with argument parsing and subcommands |
| `rich` | Terminal formatting (tables, panels, colours) |
| `httpx` | Sync and async HTTP client for the VT API |
| `pydantic` (v2) | Configuration and data models with validation |
| `pyyaml` | Configuration file (`config.yaml`) reading and writing |
| `python-dotenv` | `.env` file loading (API key) |

No heavy dependencies like `stix2`, `pandas`, or external threat intelligence libraries. The STIX 2.1 bundle is generated using only the built-in `json` and `uuid` modules.

### Package Structure

```
vex/
├── main.py              # Typer CLI, all subcommands
├── banner.py            # ASCII art banner (ffuf-style)
├── client.py            # Sync VT API v3 client + RateLimiter
├── async_client.py      # Async client for parallel batch processing
├── config.py            # Pydantic config + save_config()
├── cache.py             # SQLite cache with TTL
├── ioc_detector.py      # Regex-based IOC type detection + refanging
├── defang.py            # IOC defanging / refanging
├── models.py            # Pydantic v2 data models (TriageResult, InvestigateResult, ...)
├── batch.py             # Parallel batch processing with ThreadPoolExecutor
├── timeline.py          # Chronological timeline reconstruction
├── enrichers/           # Enricher modules per IOC type (hash, ip, domain, url)
├── plugins/             # Plugin registry and VirusTotal plugin
├── mitre/               # ATT&CK mapping table + mapper
├── knowledge/           # SQLite knowledge base (tags, notes, watchlists)
└── output/              # Formatter (Rich + Console), export (JSON, CSV), STIX 2.1
```

### Core Design Decisions

#### IOC Type Detection with Automatic Refanging

The `ioc_detector` (`vex/ioc_detector.py`) recognises seven IOC types via regex: MD5, SHA1, SHA256, IPv4, IPv6, domain, and URL. Before detection, the input is checked for defanged notation (`hxxps[://]`, `[.]`, etc.) and normalised via `defang.refang()` if needed. This enables copy-paste workflows directly from threat intelligence reports without manual preprocessing.

#### Verdict System with Numeric Severity

The `Verdict` enum (`vex/models.py`) has four levels with assigned severity values:

```
CLEAN      = 0
UNKNOWN    = 1
SUSPICIOUS = 2
MALICIOUS  = 3
```

The severity property enables numeric comparison for `--alert` filtering and exit code calculation. Key design decision: **zero detections does not mean CLEAN**. If too few engines scanned (below the configurable `min_engines_for_clean` threshold), the verdict is UNKNOWN. This prevents false negatives for very new or rare samples.

Exit code mapping:

```
CLEAN / UNKNOWN  → Exit 0
SUSPICIOUS       → Exit 1
MALICIOUS        → Exit 2
Error            → Exit 3
```

This allows vex invocations to be embedded directly in shell scripts and SOAR playbooks.

#### Configuration with Priority Hierarchy

Configuration (`vex/config.py`) follows a clear priority chain:

1. `--api-key` flag (highest priority, overrides everything)
2. `VT_API_KEY` environment variable
3. `~/.vex/config.yaml` (user config)
4. `config.yaml` in the package directory
5. Default values from Pydantic models

The `Config` class is a Pydantic `BaseModel` with nested submodels (`ApiConfig`, `CacheConfig`, `ThresholdConfig`, `OutputConfig`). The `api_key` property outputs a clear error message with all three options when no key is found.

#### SQLite in Two Places

vex uses SQLite for two independent purposes:

- **Cache** (`~/.vex/cache.db`): TTL-based caching of API results (default: 24h). Avoids redundant API calls for the same IOC.
- **Knowledge base** (`~/.vex/knowledge.db`): Persistent analyst annotations — tags, free-text notes, and watchlists per IOC. This data persists across sessions and is independent of the cache.

Both files are stored in `~/.vex/` with `0o700` permissions on the directory.

#### Plugin Architecture via typing.Protocol

The plugin system (`vex/plugins/`) is based on `typing.Protocol` rather than inheritance. `EnricherProtocol` defines the expected interface (methods `triage()` and `investigate()`) without requiring a base class — structural subtyping. The built-in `VirusTotalPlugin` implements this protocol. Third-party sources (OTX, AbuseIPDB, Shodan, etc.) can be integrated by implementing the same protocol without modifying vex's code.

#### STIX 2.1 Without External Library

STIX generation (`vex/output/stix.py`) was implemented entirely without the `stix2` Python library. This avoids a heavy dependency and allows precise control over the bundle format. Each IOC becomes a STIX `indicator` SDO, malware families become `malware` SDOs, ATT&CK mappings become `attack-pattern` SDOs. IDs are generated deterministically via UUID-5 with a fixed vex namespace, so the same objects (e.g., the same malware family) retain the same ID across multiple exports and deduplicate cleanly in STIX databases.

#### Rate Limiting via Token Bucket

The `VTClient` (`vex/client.py`) contains a thread-safe `RateLimiter` implemented as a simplified token bucket: it measures time since the last API call and sleeps the difference if needed. Free-tier default is 4 requests/minute (60s / 4 = 15s interval). On `HTTP 429`, the client sleeps 60 seconds and retries once before raising a `RuntimeError`. Premium tier can be configured for 1000 requests/minute.

---

## Feature Development

### triage — Fast SOC Triage

The primary use case: an analyst has a hash or IP and wants to know within seconds whether it is a concern. `vex triage` makes exactly one API call and returns the verdict, detection ratio, malware families, and the most important flagging engines.

Batch support via `--file` (one IOC per line, comment lines starting with `#` are skipped) and stdin piping enable integration into existing toolchains:

```bash
# From grep output
strings malware.exe | grep -E '^[a-f0-9]{64}$' | vex triage -o rich

# From file with alert filter
vex triage -f daily_iocs.txt --alert SUSPICIOUS --summary
```

### investigate — Deep DFIR Investigation

Active incident response requires more: sandbox behaviour, passive DNS, WHOIS, PE header information, dropped files, contacted IPs and domains. `vex investigate` collects this data via multiple parallel API calls and returns a structured `InvestigateResult`.

MITRE ATT&CK mapping is performed centrally in `main.py` after the enricher call: `result.attack_mappings = map_to_attack(result)`. This keeps the enrichers clean (they have no ATT&CK awareness) and makes the mapping logic replaceable.

### MITRE ATT&CK Mapping

The mapping table in `vex/mitre/mapping.py` contains two dictionaries:

- `BEHAVIOR_MAP`: Keyword-to-technique mapping for sandbox behaviour fields (process names, registry keys, API calls like `VirtualAlloc`, `CreateRemoteThread`, `mimikatz`, etc.) — 80+ entries across all tactics.
- `TAG_MAP`: VT tags to ATT&CK techniques (`ransomware → T1486`, `rat → T1219`, `rootkit → T1014`, etc.).

Matching is case-insensitive and searches for substrings in the relevant sandbox report fields. This is not full ATT&CK coverage, but a pragmatic best-effort approach that delivers immediately actionable insights in daily DFIR work.

### IOC Defanging and Refanging

`vex/defang.py` implements bidirectional defanging. Defanged notations like `hxxps[://]evil[.]com`, `8[.]8[.]8[.]8`, or `evil[dot]com` are automatically normalised before the API request. This enables direct pasting from threat intel reports where IOCs are defanged for safety. With `--defang`, the output itself can be defanged again (for safe sharing).

### Timeline Reconstruction

`vex investigate` collects timestamps from various sources (first_seen, last_seen, last_analysis_date, PE compilation timestamp, passive DNS entries). `timeline.py` sorts these chronologically into `TimelineEvent` objects with event type, source, and description. This gives analysts a quick overview of an IOC's lifecycle: when it was first seen, when last active, and how far back that was.

### Knowledge Base

The local knowledge base (`vex/knowledge/db.py`) stores analyst annotations that exist independently of the API database:

- **Tags**: Labels like `ransomware`, `apt29`, `phishing-campaign-q4` — via `vex tag IOC --add TAG`
- **Notes**: Free-text notes with timestamps — via `vex note IOC --add "text"`
- **Watchlists**: Named lists of IOCs — via `vex watchlist NAME --add IOC`

This data persists across sessions and enables collaborative annotation in teams (with a shared `~/.vex/` structure).

### Output Formats

Three output modes for different purposes:

- **console** (default): Plaintext output without Rich markup, pipe-friendly.
- **rich**: Colourful panels and tables with verdict badges for interactive terminal use.
- **json**: Machine-readable JSON output for post-processing in scripts or SIEM.

Additionally: `--csv` for tabular batch analysis, `--stix` for STIX 2.1 bundle export for integration with threat intelligence platforms.

### Banner

The ASCII art banner (`vex/banner.py`) follows the style of ffuf and other security tools. It is automatically suppressed when stdout is not a TTY (pipe usage), when `--quiet` / `-q` is set, or when `output.quiet: true` is configured. This prevents the banner from polluting machine-readable output formats.

---

## End-User Test and Bugfixes

The first complete end-to-end test of the installed package uncovered several issues that had not surfaced during development.

### Bug 1: Incorrect Build Backend in pyproject.toml

**Problem:** The initial `pyproject.toml` contained an invalid value in the `build-backend` field:

```toml
# Broken:
build-backend = "setuptools.backends._legacy:_Backend"
```

This is an internal, private path within setuptools not intended as a public backend interface. `pip install -e .` failed with an import error.

**Fix:**

```toml
# Correct:
build-backend = "setuptools.build_meta"
```

`setuptools.build_meta` is the official PEP 517 build backend for setuptools.

### Bug 2: Invalid Email Address in Author Metadata

**Problem:** The `authors` field contained a GitHub URL instead of an email address:

```toml
# Broken:
authors = [
    { name = "Christian Huhn", email = "github.com/duathron" },
]
```

The PEP 621 schema for `pyproject.toml` requires a valid RFC 5322 email address in the `email` field. PyPI and build tools validate this and throw an error during publishing.

**Fix:**

```toml
# Correct:
authors = [
    { name = "Christian Huhn", email = "duathron@gmail.com" },
]
```

### New Feature: `--api-key` / `-k` Flag

**Context:** The original implementation only supported the API key via `VT_API_KEY` environment variable or `config.yaml`. A direct option for ad-hoc use (e.g., on a foreign machine or in CI pipelines with key injection via flag) was missing.

**Implementation:** Both subcommands (`triage` and `investigate`) received an `--api-key` / `-k` parameter of type `Optional[str]`. In the subcommand function, the provided key is written directly to the loaded config object:

```python
config = load_config(config_path)
if api_key:
    config.api.key = api_key
```

The `config.api_key` property then checks `VT_API_KEY` env first, then `config.api.key`. The flag thus overrides the config, but the environment variable still has higher priority. This is consistent with the Twelve-Factor App principle (env overrides file).

### New Feature: `vex config --set-api-key`

**Context:** Previously, permanent key storage required manual editing of `config.yaml`. This is error-prone and requires knowledge of the file path.

**Implementation:** A new `config` subcommand with `--set-api-key` option calls `save_config()`, which writes the config to `~/.vex/config.yaml`. The file receives `0o600` permissions (owner read/write only), the `~/.vex/` directory receives `0o700`.

```bash
vex config --set-api-key YOUR_KEY
# ✓ API key saved to /Users/username/.vex/config.yaml
```

### New Feature: `~/.vex/config.yaml` as User Config Path

**Context:** The original config logic only searched for `config.yaml` in the project directory (next to `pyproject.toml`). This is unsuitable for an installed CLI — after `pip install vex` there is no project directory.

**Implementation:** `load_config()` now checks in this order:

1. Explicit `--config` path
2. `~/.vex/config.yaml` (user config, created by `vex config --set-api-key`)
3. `config.yaml` in the package directory (development fallback)
4. Default values

### Change: `-q`/`--quiet` Moved to Subcommands

**Context:** The original `--quiet` flag was only registered on the global app callback. With Typer's subcommand architecture (without forwarding via `ctx.obj`), the flag did not reach the subcommands — the banner was printed regardless of the flag.

**Fix:** The `_QuietOpt` alias was added to both subcommand signatures (`cmd_triage`, `cmd_investigate`) as an explicit parameter. `print_banner()` is then called with `quiet=quiet or config.output.quiet`.

### Change: Default Output from `json` to `console`

**Context:** `json` as default was intended for automation, but uncomfortable in interactive use: the output was a massive JSON blob without structure. For a CLI tool primarily used by analysts at the terminal, `console` (readable plaintext format) is the more sensible default.

**Fix:** The `_OutputOpt` alias sets `OutputFormat.console` as default instead of `OutputFormat.json`:

```python
output: _OutputOpt = OutputFormat.console
```

Those who need JSON output (automation, pipelines) pass `-o json` explicitly. Those who want Rich tables use `-o rich`.

---

## Current Status and Outlook

### Status v1.0.0

vex 1.0.0 is a fully functional CLI tool for SOC/DFIR use:

- All IOC types are supported (MD5/SHA1/SHA256/IPv4/IPv6/Domain/URL)
- Triage and investigate work with rate limiting and caching
- MITRE ATT&CK mapping is implemented (80+ keywords)
- STIX 2.1 export runs without external dependencies
- Knowledge base (tags, notes, watchlists) is operational
- The package is correctly installable via `pip install -e .`

### Status v1.0.1

Patch release focused on UX polish and quality management. No API changes, no new features — purely improvements to existing behaviour and documentation accuracy.

### Known Limitations

- **Async client (`async_client.py`) and batch processing (`batch.py`)** are present in the code, but the `investigate` subcommand still uses the sync `VTClient` with a sequential loop. Parallel batch processing for `investigate` is prepared but not fully activated.
- **Sandbox behaviour** (`get_file_behaviors`) is restricted to the premium tier of the VT API. With free-tier keys, the corresponding calls return empty results without errors.
- **Plugin registry** (`vex/plugins/`) is implemented, but loading third-party plugins from external packages is not yet documented and not supported through automatic discovery (e.g., via entry points).
- **IPv6 regex** covers the most common formats but is not fully RFC 4291 compliant for all edge cases.

### Possible Next Steps

- Full activation of async batch processing for `investigate` with large IOC lists
- Entry-point-based plugin discovery for third-party enrichers
- `vex config --show` to display the active configuration
- Integration of community scores and VT graph relationships
- Optional: local ATT&CK Navigator layer export from `attack_mappings`

---

## v1.0.1 — UX Improvements & Quality Polish

**Released:** 2026-03-16

### Background

After the initial 1.0.0 release, a UX Design Agent and a Quality Management (QM) Agent reviewed the tool. The UX review identified five concrete improvement opportunities in the output layer. The QM review independently found a configuration file inconsistency. Both sets of findings were implemented as a patch release.

### Change 1: Color-Coded Verdicts in Console Output

**Problem:** The `--output console` mode displayed verdicts as plain text (`CLEAN`, `MALICIOUS`). The color coding (red/yellow/green) existed only in Rich mode.

**Fix:** `print_triage_console()` and `print_investigate_console()` in `vex/output/formatter.py` were updated to use `console.print()` with the existing `_VERDICT_ICON` Rich markup strings instead of `print()`. Rich automatically strips ANSI escape codes when writing to a non-TTY (pipe), so machine-readability is preserved.

### Change 2: Batch Failure Count on stderr

**Problem:** When processing multiple IOCs, failed lookups were individually reported to stderr, but there was no summary. If 2 of 10 IOCs failed, the user only saw the individual error lines with no final count.

**Fix:** A `failed_count` variable was added to both `cmd_triage()` and `cmd_investigate()` in `main.py`. It is incremented for unknown IOC types and for enricher exceptions. After the loop, if `failed_count > 0`, the message `"N processed, M failed (see errors above)"` is printed to stderr.

### Change 3: Alert Filter "No Matches" Message

**Problem:** Using `--alert MALICIOUS` on a batch containing only clean/unknown IOCs produced no output at all — not even a notification. The exit code was 0, which meant the user had to know that silence implies "below threshold".

**Fix:** After `_filter_by_alert()` / `_filter_inv_by_alert()`, both subcommands check whether the pre-filter count was non-zero but the post-filter result is empty. If so, a dim informational message is printed to stderr: `"No IOCs matched alert threshold MALICIOUS (8 below threshold)"`.

### Change 4: config.yaml.example Schema Fix (QM Finding)

**Problem:** The QM Agent found that `config.yaml.example` was significantly incomplete compared to both the real `config.yaml` and the Pydantic model definitions in `vex/config.py`:

- The entire `api.rate_limit` section was missing (4 fields)
- The entire `thresholds` section was missing (3 fields)
- `api.key` was set to an empty string `""` instead of being commented out (inconsistent with `config.yaml`)
- The `output.default_format` key was written as `output.format` (wrong key name, silently ignored by Pydantic)

**Fix:** `config.yaml.example` was rewritten to be a complete, copy-ready mirror of `config.yaml`. All sections and keys are present with their defaults and explanatory comments. The API key is commented out rather than set to an empty string.

### Change 5: Consistent List Truncation Indicator

**Problem:** In Rich output, long lists (malware families, categories, tags) were truncated to 5–8 items but without any indication that more items existed. In console output, truncation was completely silent.

**Fix:** A `_truncated(items, limit) -> str` helper was added to `formatter.py`. It joins the visible items and appends `"(+N more)"` when the list exceeds the limit. Used consistently in both Rich panel grids and console output for families, categories, tags, file names, YARA hits, sandbox data, and network fields.

### Quality Management Process

Starting with v1.0.1, the QM Agent runs an end-to-end validation before each release:

1. **Syntax check**: `py_compile` on all modified modules
2. **Module integrity**: import, version string, Verdict model, IOC detection
3. **CLI smoke test**: `--help`, `version`, basic triage call, pipe mode, `-q` flag
4. **Dependency check**: `pip check` for broken requirements
5. **Config validation**: YAML parse of both config files, field comparison against Pydantic models

All 12 tests passed for the v1.0.1 release (SHIP verdict).

---

## v1.1.0 — Known Limitations Resolved

**MeetUp:** VEX-2026-003 (Architect, SOC Analyst, DFIR, Code Debug, Code Security, UX Design, QM — all decisions unanimous)

### Change 1: Batch Processing Activated

**Problem:** `batch.py` contained fully implemented `batch_triage()` and `batch_investigate()` functions with ThreadPoolExecutor and Rich progress bars, but neither `cmd_triage()` nor `cmd_investigate()` in `main.py` used them. Both commands ran IOCs sequentially in inline loops. Additionally, `batch.py` had three bugs: (1) `detect()` returns a tuple but batch.py assigned it to a single variable, (2) `_process_single_investigate()` did not call `map_to_attack()`, (3) the SQLite `Cache` was not thread-safe for concurrent access.

**Fix:** Fixed all three bugs in `batch.py` (tuple unpacking, ATT&CK mapping, error logging). Added `check_same_thread=False` and WAL journal mode to `cache.py`. Wired `batch_triage()` / `batch_investigate()` into `main.py` for multi-IOC input (`len(iocs) > 1`). Single-IOC lookups retain the inline path. Both batch functions now return `(results, failed_count)` tuples.

### Change 2: Premium Endpoint Graceful Degradation

**Problem:** Only `hash.py` gated sandbox behavior requests behind `config.is_premium`. The IP, domain, and URL enrichers called premium VT endpoints (communicating_files, downloaded_files, historical_whois) without checking the tier. Free-tier users would hit HTTP 403 errors with no graceful handling.

**Fix:** Two-pronged approach: (1) `client.py _get()` now accepts a `premium_optional` parameter — when True, HTTP 403 responses return an empty dict with a logged info message instead of raising. Applied to all 6 premium relationship methods as defense-in-depth. (2) The enrichers (`ip.py`, `domain.py`, `url.py`) now gate premium calls behind `config.is_premium`, matching the existing pattern from `hash.py`. Free-tier resolutions (passive DNS) remain ungated.

### Change 3: Entry-Point Plugin Discovery

**Problem:** The plugin loader only registered the built-in VirusTotal plugin. The entry_points discovery code was present but commented out. Third-party plugins had no supported installation path.

**Fix:** Implemented `importlib.metadata.entry_points(group="vex.plugins")` discovery in `loader.py` with Python 3.11 compatibility fallback. Each entry point is loaded inside a try/except with logging — a broken third-party plugin logs a warning but never crashes the CLI. Added `[project.entry-points."vex.plugins"]` section to `pyproject.toml` as documentation for plugin authors. Added `PluginConfig(load_local)` to config for future `~/.vex/plugins/` directory scanning (opt-in). `vex version` now shows loaded plugins.

### Change 4: IPv6 Detection Upgraded to RFC 4291

**Problem:** The IPv6 regex pattern (13 alternations) could not match IPv4-mapped addresses (`::ffff:192.0.2.1`), IPv4-compatible addresses (`::192.0.2.1`), or zone-scoped link-local addresses (`fe80::1%eth0`).

**Fix:** Replaced the regex with Python's `ipaddress.ip_address()` stdlib module, which natively handles all RFC 4291 forms. Zone ID suffixes (`%eth0`) are stripped before validation and not included in the normalised IOC sent to VT. The returned value uses canonical compressed form via `str(addr)`. The IPv4 regex check runs first, preventing IPv4 addresses from being misclassified as IPv6.

### Change 5: Passive Version Update Check

**Problem:** Users had no way of knowing when a newer vex release was available on GitHub. Stale security tooling can miss detection improvements.

**Fix:** New `vex/version_check.py` module queries the GitHub releases API (`/repos/duathron/vex/releases/latest`) with a 3-second timeout. Results are cached in `~/.vex/version_check.json` with configurable interval (default: 24 hours). The notice is displayed after the banner on stderr (yellow bold). Pre-releases and drafts are skipped. All errors fail silently — the version check never breaks the tool. Configurable via `update_check.enabled` and `update_check.check_interval_hours` in config.yaml. No auto-update command was implemented (MeetUp decision: supply chain risk, SOC change management concerns).

---

*Documentation created on 2026-03-13 based on the complete source code and end-user test session.*
*Updated 2026-03-16 for v1.0.1 (UX improvements, QM process, config fix).*
*Updated 2026-03-16 for v1.1.0 (known limitations resolved, MeetUp VEX-2026-003).*
