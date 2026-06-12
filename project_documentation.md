# vex — Project History and Documentation

**Author:** Christian Huhn (GitHub: [duathron](https://github.com/duathron))
**Version:** 1.6.1 (released) — see [On main (pending 1.7.0)](#on-main-pending-170) for unreleased features
**Date:** 2026-06-12
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
| `shipwright-kit` | Shared Shipwright library — design tokens, eval harness, prompt-injection engine, and config mechanism, consumed from PyPI (`>=0.6.0,<0.7.0`). Added in v1.6.0; backs the injection detector and config loader (see Core Design Decisions). |

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

Since v1.6.0, `load_config()` delegates the resolve→load→validate skeleton to `shipwright_kit.config` (the shared, secure config mechanism). vex keeps its own `Config` schema, dotenv loading, packaged-default fallback, lazy `@property` env accessors, and `save_config()` verbatim — only the candidate-path resolution and validation plumbing is single-sourced from the shared library. The priority chain above is preserved.

#### Shared Prompt-Injection Engine (v1.6.0)

The AI layer scans attacker-influenced enrichment data before it is inserted into LLM prompts. Since v1.6.0, vex's `PromptInjectionDetector` (`vex/ai/injection_detector.py`) **subclasses** the shared `shipwright_kit.security.injection.PromptInjectionDetector` instead of being a standalone copy of the patterns. vex contributes only its prompt-insertion `sanitize()` method on top of the shared `detect()` engine. Because the pattern set and detection engine are now single-sourced across vex, barb, and sift, a bypass fixed once in the shared engine propagates to all three tools automatically.

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

**Problem:** The `authors` field contained a GitHub URL where an email address belongs:

```toml
# Broken:
authors = [
    { name = "Christian Huhn", email = "github.com/duathron" },
]
```

The PEP 621 schema for `pyproject.toml` requires a valid RFC 5322 email address in the `email` field. A GitHub profile URL is not a valid email address. PyPI and the build tools validate this field and reject the package during build/publishing.

**Fix:** the `email` field was corrected to a real, RFC 5322-valid email address (kept out of this document), leaving the `name` field as `"Christian Huhn"`. The package then built and published cleanly.

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

### Status v1.6.1

vex 1.6.1 is a mature, multi-source IOC enrichment hub for SOC/DFIR use, live on PyPI as **`vex-ioc`** (`pip install vex-ioc`). It is covered by **996 automated tests** (deterministic, no network) with a green CI pipeline (ruff + pytest). On main (pending 1.7.0): TI write-back, `watchlist run`, daily quota counter, `--version` flag. The state of the tool:

- All IOC types are supported (MD5/SHA1/SHA256/IPv4/IPv6/Domain/URL), with full refang parity to barb/sift and a guard against misclassifying executable/script filenames as domains.
- `triage` and `investigate` work with rate limiting, caching, IOC deduplication, NDJSON streaming, rate-limit-aware scheduling (`--max-quota`, ETA), and a `vex doctor` diagnostic.
- Multi-source enrichment: VirusTotal (primary) plus secondary enrichers for AbuseIPDB, Shodan, MISP, and OpenCTI — all fail-open and key-gated. vex acts as an enrichment hub in the barb→vex→sift / sift↔vex flows.
- Opt-in AI explanations and correlation narratives across three providers (Anthropic, OpenAI, Ollama) with a template fallback, hardened by a shared prompt-injection defense.
- MITRE ATT&CK mapping, STIX 2.1 export (OpenCTI-hardened, with TLP markings), and ATT&CK Navigator layer export.
- Knowledge base (tags, notes, watchlists) is operational.
- v1.6.0 onboards vex onto the shared **shipwright-kit** library: the injection detector subclasses the shared engine and the config loader delegates to `shipwright_kit.config`.
- v1.6.1 bundles attribution metadata and the `__version__` literal fix (version consistency guarded by CI).

### On main (pending 1.7.0)

The following features are merged on main and pending the 1.7.0 release. They are present in the editable install but not yet in the PyPI package.

#### TI write-back (`--sight` / `--dry-run-sight`)

`vex investigate --sight` writes MISP sightings and OpenCTI observables for IOCs at or above a configurable verdict floor. Three explicit gates must all be open:

1. `enrichment.writeback_enabled: true` in `~/.vex/config.yaml` (default `false`).
2. `--sight` on `vex investigate`.
3. Use `--dry-run-sight` first to preview payloads without sending.

Key design properties:
- **Verdict floor** (`enrichment.writeback_min_verdict`, default `SUSPICIOUS`) — IOCs below the floor are silently skipped.
- **TLP marking-check** — before each write, the source IOC's most-restrictive known TLP (from `misp_tlp` / `opencti_tlp`) is compared against the ceiling (`enrichment.writeback_tlp`, default `"green"`). If the source is more restrictive, the write is blocked. This prevents pushing `TLP:RED`-marked data to a platform that only accepts `TLP:GREEN`.
- **Fail-open** — a write failure (network error, HTTP error, GraphQL error) is logged at DEBUG and sets the result field to `false`. It never crashes the run.
- **No credential leaks** — MISP and OpenCTI tokens are stored only in `~/.vex/config.yaml` (0o600) or environment variables; they never appear in CLI arguments, logs, or output.

The GraphQL mutation used for OpenCTI is:

```graphql
mutation AddObservable($type: String!, $value: String!) {
  stixCyberObservableAdd(type: $type, observableData: { value: $value }) {
    id
  }
}
```

For network observables this works on OpenCTI ≥ 5.x. File-hash observables may require `hashes: { MD5: $value }` on some versions — verify against your instance before relying on hash write-back. The operator must run `--dry-run-sight` → review the payload → confirm one real sighting (MISP) and one observable (OpenCTI) in the lab UI before enabling in production.

New result fields: `writeback_misp` (`null` = not attempted, `true` = written, `false` = failed/skipped) and `writeback_opencti` (same).

#### Watchlist re-triage (`vex watchlist run`)

`vex watchlist run <name>` re-triages every IOC in a named watchlist, compares each fresh verdict against the cached prior verdict, prints a diff table, and exits non-zero (code 1) if any IOC worsened. The daily VT-quota counter applies; the quota status line is printed to stderr after the run.

```bash
vex watchlist run priority              # rich diff table
vex watchlist run priority -o json      # machine-readable summary
```

JSON output fields: `watchlist`, `total`, `worsened`, `unchanged`, `improved`, `cache_misses`, `errors`, `diffs` (array of `{ioc, old_verdict, new_verdict}`).

The flat `vex watchlist <name> --add/--remove/--list` manage shape is preserved unchanged.

#### Daily VT-quota counter

Fresh VT lookups are counted in a persistent UTC-keyed JSON file (`~/.vex/quota.json`) that resets at midnight UTC. After every batch or `watchlist run`, a status line is printed to stderr:

```
VT quota: 38/500 used today, 462 remaining
```

When fewer than 10 % of the daily limit remain, an additional warning is printed. The counter is fail-open and never blocks triage. The daily limit comes from `api.rate_limit.requests_per_day` (default 500 for free tier).

#### `--version` eager flag

`vex --version` is now available as a global eager flag that prints the version and exits before any subcommand is evaluated. The `vex version` subcommand continues to work as before.

### Known Limitations

- **Sandbox behaviour** (`get_file_behaviors`) is restricted to the premium tier of the VT API. With free-tier keys, the corresponding calls return empty results without errors (graceful degradation, resolved in v1.1.0).
- **Async high-throughput mode** is deliberately deferred: at the VT free-tier rate ceiling, async ≈ threads (vex's throughput is quota-bound, not concurrency-bound). The `ThreadPoolExecutor` batch path stays the default; `async_client.py` is retained as a tested seed for a future premium-gated mode.
- **OpenCTI write-back mutation shape** — the `stixCyberObservableAdd` mutation works for network observables on OpenCTI ≥ 5.x. File-hash observables may need a different shape on some versions. Always run `--dry-run-sight` and verify against your instance before production use.

*(Earlier limitations — sequential batch processing, entry-point plugin discovery, and full RFC 4291 IPv6 handling — were resolved in v1.1.0. TI write-back shipped on main and is pending 1.7.0.)*

### Possible Next Steps

- Optional `pymisp`/`pycti` extras if raw-REST/GraphQL version-resilience ever demands them.
- Premium-gated async high-throughput batch mode (wiring `AsyncVTClient`), only if high-volume/premium demand appears.
- Integration of community scores and VT graph relationships.

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

## v1.1.0 Post-Release — PyPI Publication & CI/CD

**Date:** 2026-03-16

### PyPI Publication as "vex-ioc"

The package name `vex` was already taken on PyPI. The package was published under the name **`vex-ioc`** — the PyPI name, the CLI command (`vex`), and the Python module (`vex`) are three independent identifiers. The `[project.scripts]` entry in `pyproject.toml` defines the command name independently:

```toml
name = "vex-ioc"          # PyPI: pip install vex-ioc

[project.scripts]
vex = "vex.main:main"     # CLI: vex triage ...
```

`pyproject.toml` was updated accordingly. `README.md` was updated with `pip install vex-ioc`.

### Version Check: GitHub API → PyPI JSON API

After publication, `version_check.py` was updated to use the PyPI JSON API as the canonical version source (more reliable for published packages than the GitHub releases API):

```python
_PYPI_API = "https://pypi.org/pypi/vex-ioc/json"
```

The caching logic and `~/.vex/version_check.json` state file remain unchanged.

### GitHub Actions: Automatic PyPI Publishing

`.github/workflows/publish.yml` was added. It triggers on any tag matching `v*.*.*` and runs the full build + publish pipeline:

1. `actions/checkout@v4` — checkout source
2. `actions/setup-python@v5` (Python 3.11) — set up environment
3. `pip install build twine` — install build tools
4. `python -m build` — build wheel + sdist
5. `twine check dist/*` — validate package
6. publish to PyPI

Future releases are triggered with:

```bash
git tag v1.2.0 && git push origin main --tags
```

**Publishing model: OIDC Trusted Publisher with a gated environment.** vex publishes to PyPI through an **OIDC Trusted Publisher** — there is no long-lived API token stored as a GitHub Secret. The publish job runs in a `pypi` GitHub Environment that requires a human reviewer to approve each upload, so every release to PyPI is explicitly gated by a person. (An earlier iteration used an `PYPI_API_TOKEN` GitHub Secret "for simplicity"; this was replaced with the tokenless, environment-gated OIDC flow.)

---

## v1.2.0 — AI Integration

**MeetUp:** VEX-2026-006 (Architect, SOC Analyst, DFIR, Code Security, UX Design, AI Specialist, Marketing, QM — 8 agents)
**Date:** 2026-03-18

### Overview

v1.2.0 adds AI-powered threat explanations as a strictly opt-in feature via the `--explain` flag. Three LLM providers are supported: Anthropic Claude, OpenAI, and Ollama (local). When no AI provider is configured, a deterministic template-based fallback produces structured explanations. AI is never default-on — the base install and all existing commands work exactly as before.

### New Package: vex/ai/

```
vex/ai/
├── __init__.py      # get_provider(config) factory, availability checks
├── protocol.py      # LLMProviderProtocol (runtime_checkable)
├── prompt.py        # build_explain_prompt(result), input sanitization (defanged IOCs)
├── template.py      # template_explain(result) — deterministic, no LLM needed
├── cache.py         # AI response cache (SQLite, SHA-256 key, 72h TTL)
├── anthropic.py     # ClaudeProvider (anthropic SDK)
├── openai.py        # OpenAIProvider (openai SDK)
└── ollama.py        # OllamaProvider (httpx, no extra deps)
```

Architecture follows the established Protocol pattern from `enrichers/protocol.py`. `LLMProviderProtocol` defines `explain(prompt) -> str` and `is_available() -> bool`. Providers are instantiated via `get_provider(config)` which enforces `ai.local_only` and validates API keys.

### Data Flow

```
triage/investigate result
    ↓
prompt.py → build_explain_prompt(result) → prompt string (defanged IOC, sanitized)
    ↓
provider.explain(prompt) → explanation string  [or template.py fallback]
    ↓
formatter.py → Rich panel "AI Analysis" (blue border) / console text
```

### AIConfig

New Pydantic model in `config.py`:

- `provider`: `none` | `anthropic` | `openai` | `ollama` (default: `none`)
- `model`: optional override per provider
- `api_key`: overridden by `VEX_AI_API_KEY` env var
- `base_url`: for Ollama (default: `http://localhost:11434`)
- `max_tokens`: 500 (default)
- `temperature`: 0.3 (default)
- `local_only`: when `true`, blocks cloud providers (Anthropic, OpenAI)
- `cache_ttl_hours`: 72 (default)

### Optional Dependencies

Optional extras in `pyproject.toml`:

- `pip install vex-ioc[ai]` — installs `anthropic` + `openai`
- `pip install vex-ioc[ai-local]` — no extras (Ollama uses httpx, already a core dep)
- `pip install vex-ioc[ai-all]` — installs all AI packages
- `pip install vex-ioc[whois]` — installs `python-whois` for direct WHOIS enrichment

Base install remains unchanged (6 core deps).

### Security Controls (MeetUp decision: unanimous)

1. **`ai.local_only: true`** — blocks all cloud providers, only allows Ollama. For air-gapped SOCs.
2. **Input sanitization** — IOCs are defanged in prompts (`evil.com` → `evil[.]com`). No raw user input in system prompt sections.
3. **Explicit data documentation** — the prompt contains only VT enrichment data (verdict, detections, families, ATT&CK techniques). No config, API keys, or file system paths.
4. **API keys** — same security model as VT API key: env var > config file (0o600) > CLI flag.
5. **Graceful degradation** — if AI provider fails, falls back to template. AI never blocks the main enrichment pipeline.

### CLI Changes

New flags on `triage` and `investigate`:
- `--explain` / `-e` — generate AI explanation after results
- `--explain-model <name>` — override the configured model

New flag on `config`:
- `--show` — display active configuration as Rich table with masked API keys

### AI Response Cache

AI responses are cached in `~/.vex/ai_cache.db` (separate from the main result cache). Cache key is SHA-256 of `(provider, model, prompt)`. Default TTL: 72 hours. This avoids redundant API calls when re-analyzing the same IOC with the same AI configuration.

---

## v1.2.0 — barb Pipeline, WHOIS, ATT&CK Navigator (2026-03-18)

### Feature: barb → vex Pipeline

**Problem:** Analysts needed to manually switch between barb (heuristic URL analysis) and vex (VT enrichment). No data flow connected them.

**Solution:** `--from-barb` flag on both `triage` and `investigate` reads barb JSON from stdin, extracts URLs as IOCs, and displays barb's pre-scan verdict and signal breakdown alongside VT results.

**New files:**
- `vex/pipeline/__init__.py` — package marker
- `vex/pipeline/barb_bridge.py` — `BarbContext` + `BarbSignal` models, `parse_barb_json()` function

**Models (`BarbContext`):**
- `url: str`, `verdict: str`, `risk_score: float`, `signals: list[BarbSignal]`, `defanged_url: Optional[str]`
- `top_signals` property: up to 5 signals sorted by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)

**Formatter additions (`vex/output/formatter.py`):**
- `print_barb_context_rich()` — orange-bordered panel with verdict badge, risk score, signal table
- `print_barb_context_console()` — plain-text barb pre-scan block

**CLI changes (`vex/main.py`):**
- `--from-barb` on `triage` and `investigate`
- JSON output with `--from-barb -o json` includes `"barb_context"` field per result
- `vex manual pipeline` topic added

**Usage:**
```bash
barb analyze https://evil.com -o json | vex triage --from-barb -o rich
barb analyze https://evil.com -o json | vex investigate --from-barb -o rich
barb analyze -f urls.txt -o json | vex triage --from-barb --alert SUSPICIOUS
```

---

### Feature: WHOIS Enrichment

**Problem:** VT WHOIS is a premium-only endpoint. Free-tier users saw empty WHOIS panels in `investigate` output even though the `WHOISInfo` model already existed.

**Solution:** Direct WHOIS lookup via `python-whois` (optional dep) as a fallback when VT WHOIS is not available.

**New file:** `vex/enrichers/whois_enricher.py`
- `is_available()` — checks if python-whois is installed
- `enrich_whois(domain)` — queries WHOIS, handles all python-whois quirks (list values, datetime coercion), catches all exceptions gracefully

**Config change (`vex/config.py`):**
- `EnrichmentConfig(whois_enabled: bool = True)` model added
- `enrichment: EnrichmentConfig = EnrichmentConfig()` on `Config`

**Integration (`vex/enrichers/domain.py`):**
```python
if whois is None and config.enrichment.whois_enabled:
    from .whois_enricher import enrich_whois
    whois = enrich_whois(ioc)
```

**No formatter changes needed** — `WHOISInfo` rendering was already implemented in `print_investigate_rich()` and `print_investigate_console()`.

**Optional dep:** `pip install vex-ioc[whois]` (adds `python-whois>=0.9.0`)

---

### Feature: ATT&CK Navigator Layer Export

**Problem:** No way to visualize vex's ATT&CK mappings in standard tooling.

**Solution:** `--navigator` flag on `investigate` exports a Navigator v4.5 compatible JSON layer, ready for upload to https://mitre-attack.github.io/attack-navigator/

**New file:** `vex/output/navigator.py`
- `to_navigator_layer(results, *, title, ioc)` — serializes `ATTACKMapping` objects
- `_TACTIC_NORMALIZE` dict — maps vex tactic names (Title Case) to Navigator IDs (lowercase-hyphenated)
- Deduplication by technique_id (first occurrence wins)
- Full Navigator v4.5 JSON structure: name, versions, domain, techniques, gradient, metadata

**CLI changes (`vex/main.py`):**
- `--navigator` on `investigate` — exclusive with other output formats (outputs only Navigator JSON)
- Redirect to file: `vex investigate evil.com --navigator > layer.json`

**Usage:**
```bash
vex investigate evil.com --navigator > layer.json
# Open layer.json at https://mitre-attack.github.io/attack-navigator/
```

---

## v1.2.1 — Concurrency Fix (2026-04-28)

A patch release fixing a real failure in batch mode. Under `ThreadPoolExecutor`, concurrent workers sharing the SQLite `Cache` connection raised `InterfaceError: bad parameter or other API misuse`. A `threading.Lock` was added to `Cache` to serialize concurrent SQLite access. No API or feature changes.

---

## v1.3.0 — Batch Intelligence

**MeetUp:** VEX-2026-008 (8 agents, 2026-05-31)

v1.3.0 turns vex from a per-IOC lookup tool into one that reasons across a *batch* of IOCs. It was never published separately — its work was folded into the v1.4.0 release (see below) — but it represents a distinct theme and a distinct MeetUp scope. The strategic decision made here: **vex commits to being a multi-source threat-intelligence aggregation engine, not just a VirusTotal wrapper.** The plugin registry, until now decorative (only feeding `vex addons`), becomes load-bearing.

### Batch IOC Correlation (`--correlate`)

`--correlate` clusters a multi-IOC run by shared infrastructure — ASN, malware family, contacted IPs/domains, passive DNS. The result is a deterministic cluster table (Rich/console) and a `"clusters"` array in JSON. This is the v1.2.0 miss that DFIR and SOC analysts wanted most: seeing which IOCs in a dump belong to the same campaign. Implemented in `vex/correlate.py`, fully deterministic (no LLM).

### AI Correlation Narratives

With `--correlate` **and** `--explain` on a batch run, vex generates a short per-cluster campaign-correlation narrative. Opt-in, cached, with a template fallback when no LLM is configured. `--correlate` on its own stays deterministic — the AI layer is gated on the explain flag. IOCs are defanged in the prompts.

### Plugin Registry Wired Into the Hot Path

Internally, enrichment now dispatches through the `PluginRegistry` (`EnricherProtocol`) instead of a hardcoded resolver. The VirusTotal plugin owns a single lazily-created, lock-guarded `VTClient` reused across the run and across batch threads — preserving rate-limit continuity (a naive registry wiring would reset the per-IOC `RateLimiter` and trigger 429 storms). This is the foundation for genuine multi-source enrichment. A new `SecondaryEnricherProtocol` lets a plugin augment an `InvestigateResult` in place after the primary source; third-party secondary plugins register via the `vex.secondary_plugins` entry-point group.

### AbuseIPDB and Shodan Enrichers

Two new built-in secondary enrichers, both for IP investigation:

- **AbuseIPDB** — adds confidence score, total reports, and last-reported date when `VEX_ABUSEIPDB_API_KEY` (or `enrichment.abuseipdb_api_key`) is configured.
- **Shodan** — adds open ports, hostnames, org, and tags when `VEX_SHODAN_API_KEY` (or `enrichment.shodan_api_key`) is configured.

Both are built-in first-party secondaries (like WHOIS), fail-open, key-gated, and add no new dependency. They never block the run.

### HTML Report Export (`--html`)

`--html <path>` on `triage`/`investigate` writes a self-contained HTML report (reusing the Rich rendering with embedded CSS) alongside the normal output. IOC strings are defanged in the report body. `vex/output/html.py`.

### Automated Test Suite

Before v1.3.0, vex had **zero** automated tests. The suite was bootstrapped to 375 unit tests covering cache (including the v1.2.1 concurrency regression), IOC detector, defang, knowledge base, timeline, config, async client, plugin dispatch, correlation, the AbuseIPDB/Shodan enrichers, HTML export, and AI narratives — all deterministic, no network. A `[dev]` optional dependency group (`pytest`, `ruff`) and a GitHub Actions `tests.yml` workflow (ruff + pytest on push/PR) were added at the same time.

### Deferred: Async Batch Executor

The MeetUp originally scoped an async batch executor (P1). It was **deferred to v1.4.0** after analysis showed that at the VT free-tier rate ceiling async ≈ threads, and `AsyncVTClient` cannot drive the sync enrichers without a rewrite. `ThreadPoolExecutor` stays the default; `async_client.py` is kept as a tested seed.

---

## v1.4.0 — Scale & Pipeline

**MeetUp:** VEX-2026-009 (9 agents, 2026-05-31)

v1.4.0 bundles the v1.3.0 "Batch Intelligence" work with the new "Scale & Pipeline" work into a single published release. The test suite grew from 0 → 375 deterministic tests with CI as part of this line of work. The scaling philosophy decided here: **vex is quota-bound, not concurrency-bound** — future-proofing for large pipeline batches means spending less quota and surviving long runs, not running faster. Principle: cache-first, quota-thrifty, rate-limit-aware, streamable; concurrency is second-order.

### Topology: vex as an Enrichment Hub

A topology clarification framed the rest of the release: vex is an enrichment **hub/service**, not a fixed linear pipeline stage. It is called by multiple consumers; the primary real flow is **sift ↔ vex** (sift extracts IOCs from alerts → vex enriches → sift prioritizes/tickets), with barb as an occasional specialized URL feeder. Standalone use stays first-class.

### `--from-sift` Adapter

`--from-sift` reads sift's JSON `TriageReport` from stdin, extracts the IOCs sift found (cluster + alert IOCs, source/dest IPs, deduped), and enriches them — closing the sift ↔ vex enrichment loop. It mirrors the existing `--from-barb` adapter and is mutually exclusive with it. `vex/pipeline/sift_bridge.py`.

### IOC Deduplication

Batch input is de-duplicated (order-preserving) before any query, saving API quota on pipeline-scale runs with repeated IOCs. A `N → M unique (K removed)` notice prints to stderr. `--no-dedup` disables it.

### NDJSON Streaming Output (`-o ndjson`)

`-o ndjson` emits one JSON object per result line, flushed per line (pipeline- and crash-friendly), following the same JSON defang rule (real IOCs unless `--defang`). Under `--correlate`, clusters are emitted as `{"_type":"cluster",...}` lines.

### Rate-Limit-Aware Scheduling

Multi-IOC runs now print an up-front ETA (IOC count · tier · estimated time) to stderr, a post-run `processed (N from API, M cached), K failed` summary (the cached count doubles as a resume signal), and a `--max-quota N` budget guard that caps fresh API lookups — cached results are always served, excess IOCs are skipped with a notice. All notices are stderr-only. `vex/scheduling.py`.

Resume was delivered via the existing SQLite cache (a re-run skips cached IOCs, surfaced by the cache/fresh counter) rather than a separate `--resume` flag. Streaming GB-scale log *input* was dropped as unnecessary — vex ingests IOC strings, which are small; the large logs live upstream.

### `vex doctor`

`vex doctor` reports configuration and connectivity for every service (VirusTotal, AI provider, AbuseIPDB, Shodan, MISP, OpenCTI). Config-only by default (no network); `--probe` tests live connectivity and **surfaces the actual error** instead of the silent fail-open behaviour the enrichers would otherwise hide (e.g. an unreachable MISP/OpenCTI). Secrets are never printed; quota-costing services are not auto-probed. `-o json` for scripting. `vex/doctor.py`.

---

## v1.5.0 — TI Platform Integration

**MeetUp:** VEX-2026-010 (2026-05-31)

v1.5.0 turns vex into a multi-source enrichment hub that connects to the open-source threat-intelligence stack: MISP and OpenCTI lookup, OpenCTI-ready STIX with TLP markings, plus pre-release hardening. The governing principle: **lookup-before-write-back** — reading platforms for context is low-risk/high-value, while write-back carries TLP governance weight (and is deferred). TLP/markings are respected throughout and never leaked into unmarked output; platform secrets are masked and TLS is verified by default; platform SDKs are optional, raw REST is preferred. The MISP (2.5.38) and OpenCTI (demo 7.26) enrichers were live-verified end-to-end, as were the Anthropic and Ollama AI paths.

### MISP IOC Lookup

`investigate` now consults a MISP instance (`/attributes/restSearch`) for every IOC type when `MISP_URL` + `MISP_API_KEY` are configured, attaching `misp_known`, event IDs, tags, a **TLP marking** (most-restrictive wins), and last-seen. It is a built-in secondary enricher using raw httpx (no `pymisp` dependency), fail-open, a no-op without config, with TLS verification on by default (`misp_verify_tls` opts out for lab instances). TLP and markings are carried through and never dropped.

### OpenCTI IOC Lookup

`investigate` also consults an OpenCTI instance (GraphQL `stixCyberObservables`) for every IOC type when `OPENCTI_URL` + `OPENCTI_TOKEN` are configured, attaching `opencti_known`, the observable id, `x_opencti_score`, labels, and a **TLP marking** (most-restrictive). It is a built-in secondary enricher using **raw GraphQL over httpx (no `pycti` dependency)** — defensive parsing tolerates OpenCTI schema/version drift, fail-open, a no-op without config, TLS-verify by default. The token is never logged and is masked in `config --show`. (The MeetUp voted for a `pycti` extra; the implementation deviated to raw httpx — leaner, mockable, and fail-open absorbs version drift, matching the MISP precedent. Live validation against the public demo caught a real bug mocks missed: a GraphQL variable typed `String!` had to become `Any!`.)

### STIX 2.1 Hardened for OpenCTI

The STIX 2.1 export was hardened for OpenCTI ingestion: bundles now include a vex `identity` (`created_by_ref` provenance), STIX **Cyber-observables (SCOs)** with `indicator → based-on → observable` relationships, ATT&CK `external_references` on attack-patterns, and **TLP `marking-definition`s**. When an IOC carries a MISP TLP, the canonical STIX 2.1 TLP marking is attached via `object_marking_refs` — markings are never dropped. IDs remain deterministic (idempotent re-export). A README "Feeding OpenCTI" section was added.

### Pre-Release Hardening

Several hardening items shipped alongside the TI work:

- **AI prompt-injection defense** (adapted from sift): attacker-influenced fields fed to the LLM by `--explain` / `--correlate --explain` (malware-family labels, file names, sandbox process/DNS/mutex/registry strings, tags, categories, WHOIS org) are scanned, and CRITICAL injection attempts (instruction-override, output-manipulation, shell-command) are redacted before prompt submission. NFKC normalization defeats unicode/zero-width bypasses; IOC/hash fields skip the encoded-payload check to avoid false positives. `vex/ai/injection_detector.py`. *(This standalone copy of sift's patterns is what v1.6.0 later replaced with a subclass of the shared engine.)*
- **AI provider robustness** (adapted from sift): instructions moved into a proper `system` prompt (distinct for `--explain` vs correlation, with an IOC-type glossary) instead of being jammed into the user message; defensive response-content extraction (tolerates non-text blocks); `anthropic.APIError` wrapped with a friendly message; the Anthropic default model refreshed to `claude-sonnet-4-6`. Backward-compatible.
- **Test coverage round 2**: VT client (rate limiter, 404/429/premium paths), all four VT enrichers (ip/domain/hash/url triage + investigate parsing), and the batch path — 91 new tests, all mocked/no-network. The suite reached **625 tests**.

---

## v1.5.1 — Filename, PE-Hash, and Refang Patch (2026-06-02)

A patch release fixing two real failures found in normal use against live 1.5.0, plus full refang parity. **841 tests, ruff clean, CI green.**

### Filename Misclassified as Domain

IOC detection misread executable/script filenames as domains. `wcdbcrk.dll`, `payload.exe`, and similar matched the domain regex — their extension looked like a TLD — and triggered a bogus VirusTotal domain lookup, returning HTTP 400 / `HTTPStatusError`. Non-TLD file extensions (`exe`/`dll`/`sys`/`scr`/`bat`/`ps1`/`vbs`/…) now detect as `UNKNOWN` and are skipped cleanly. Real TLDs (`.com`, `.app`, `.dev`, `.zip`, `.mov`, `.sh`) are unaffected.

### PE-Hash Investigate Crash

`investigate` on a PE-file hash crashed with a Pydantic `ValidationError`. VirusTotal returns `pe_info.machine_type` as an int (e.g. `332` = `0x14C` i386), but `PEInfo.target_machine` is a string field — the value is now coerced. This affected any PE sample with an integer `machine_type`.

### Full Refang Parity

Refang now covers the full defang spectrum, reaching parity with barb and sift: `(.)`, `{.}`, `(dot)`/`{dot}`, `(at)`/`{at}` (domain-guarded), `[/]`, fullwidth `．＠：／`, and zero-width/BOM stripping — in addition to the existing `hxxp(s)`/`fxp`, `[://]`, `[.]`, `[:]`, `[@]`, `[dot]`, `[at]`. It is idempotent, preserves IPv6 `[::1]`, and `is_defanged()` detection was extended to match. The public API is unchanged.

---

## v1.6.0 — Shipwright Onboarding

**Date:** 2026-06-05
**Decision:** onboard onto the shared `shipwright-kit` library; publish vex-ioc 1.6.0 to PyPI consuming it from PyPI.

vex, barb, and sift are three security tools that had independently grown overlapping code — most notably each carried its own copy of a prompt-injection pattern set and its own config-loading skeleton. v1.6.0 onboards vex onto **shipwright-kit**, a shared Shipwright library (design tokens, an eval harness, a prompt-injection engine, and a config mechanism) now **published to PyPI**. The payoff is the classic shared-library benefit: **build or fix something once, and it propagates to every tool** that consumes the engine — instead of fixing the same injection bypass three times in three repos.

### Injection Detector Now Subclasses the Shared Engine

vex's prompt-injection detector (`vex/ai/injection_detector.py`) was a standalone copy of sift's patterns (introduced in v1.5.0). It now **subclasses `shipwright_kit.security.injection.PromptInjectionDetector`** and contributes only vex's own prompt-insertion `sanitize()` method on top of the shared `detect()` engine. By inheriting the shared engine, vex **gained** detections it never had:

- **jailbreak / role-override** ("act as an unrestricted assistant", "you are now DAN", …)
- **system-prompt exfiltration** ("print the contents of your system prompt", …)

These are now flagged in attacker-influenced enrichment data before it is inserted into LLM prompts. Public behaviour is otherwise preserved: the existing patterns, `sanitize()`, and the redaction of CRITICAL findings all still work the same. A drift-guard test asserts the subclass relationship so the inheritance can't silently regress.

### Config Loading Delegates to the Shared Skeleton

`load_config()` now delegates the resolve→load→validate skeleton to `shipwright_kit.config`, eliminating duplicated logic. vex keeps its own `Config` schema, dotenv loading, packaged-default fallback, lazy `@property` env accessors, and `save_config()` verbatim — the config priority hierarchy and all `~/.vex` handling are unchanged.

### Dependency from PyPI

The `shipwright-kit` dependency is now resolved from **PyPI** (`shipwright-kit>=0.6.0,<0.7.0`) instead of a git URL, so `pip install vex-ioc` resolves cleanly without needing a git source. (Publishing the previously git-only library to PyPI is what unblocked using it as a runtime dependency of a published tool.)

### Also in 1.6.0

- **Liberal parsing of VirusTotal responses** — defensive type coercion so malformed or edge-case API payloads no longer raise.
- Test suite at **898 tests**, ruff clean, CI green. Released to PyPI as **vex-ioc 1.6.0** via the reviewer-gated OIDC publish flow, with a clean-room `pip install` verified.

> **Note:** this v1.6.0 is *not* the originally-planned "write-back" v1.6.0. TI write-back (MISP sightings / OpenCTI observables, opt-in and marking-aware) remains deferred to a later version — see "Current Status and Outlook".

---

*Documentation created on 2026-03-13 based on the complete source code and end-user test session.*
*Updated 2026-03-16 for v1.0.1 (UX improvements, QM process, config fix).*
*Updated 2026-03-16 for v1.1.0 (known limitations resolved, MeetUp VEX-2026-003).*
*Updated 2026-03-16: PyPI publication as vex-ioc, version check switched to PyPI JSON API, GitHub Actions CI/CD workflow added.*
*Updated 2026-03-18 for v1.2.0 (AI integration, config --show, MeetUp VEX-2026-006).*
*Updated 2026-03-18 for v1.2.0 (barb pipeline, WHOIS enrichment, ATT&CK Navigator export).*
*Updated 2026-03-21 for v1.2.0 (addon discoverability: vex addons, config --show addon section, first-run hint, explanation labels, python-whois promoted to core, pipx install docs, MeetUp VEX-2026-007).*
*Updated 2026-04-28 for v1.2.1 (concurrency fix: threading.Lock on Cache for ThreadPoolExecutor batch workers).*
*Updated 2026-05-31 for v1.3.0 "Batch Intelligence" (--correlate clustering, AI correlation narratives, plugin registry wired into hot path, AbuseIPDB/Shodan secondary enrichers, --html export, 375-test suite + CI, MeetUp VEX-2026-008).*
*Updated 2026-05-31 for v1.4.0 "Scale & Pipeline" (vex as enrichment hub, --from-sift, IOC dedup, NDJSON streaming, rate-limit-aware scheduling/--max-quota, vex doctor, MeetUp VEX-2026-009).*
*Updated 2026-06-01 for v1.5.0 "TI Platform Integration" (MISP + OpenCTI lookup, OpenCTI-hardened STIX with TLP markings, AI prompt-injection defense + provider robustness, 625 tests, MeetUp VEX-2026-010).*
*Updated 2026-06-02 for v1.5.1 (filename≠domain guard, PE-hash investigate ValidationError fix, full refang parity, 841 tests).*
*Updated 2026-06-05 for v1.6.0 "Shipwright onboarding" (consumes shipwright-kit from PyPI; injection detector subclasses the shared engine — gained jailbreak + system-prompt-exfil detection; config delegates to shipwright_kit.config; 898 tests). Publishing corrected to OIDC Trusted Publisher with reviewer-gated pypi environment; personal email removed from author-metadata bugfix narrative.*
*Updated 2026-06-12 for v1.6.1 (attribution metadata + __version__ literal fix, 996 tests) and on-main / pending-1.7.0 features: TI write-back (--sight / --dry-run-sight), vex watchlist run, daily VT-quota counter, --version eager flag.*
