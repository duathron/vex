# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- AI correlation narratives: with `--correlate` **and** `--explain` on a batch run, vex generates a short per-cluster campaign-correlation narrative (opt-in, cached, template fallback when no LLM). `--correlate` alone stays deterministic. IOCs defanged in prompts. (v1.3.0 P1, MeetUp VEX-2026-008)
- HTML report export: `--html <path>` on `triage`/`investigate` writes a self-contained HTML report (reuses the Rich rendering, embedded CSS) alongside normal output. IOC strings are defanged in the report body. `vex/output/html.py`. (v1.3.0 P1, MeetUp VEX-2026-008)
- Shodan IP enrichment: investigate on an IP adds Shodan open ports, hostnames, org, and tags when `VEX_SHODAN_API_KEY` (or `enrichment.shodan_api_key`) is configured. Built-in secondary enricher, fail-open, no-op without a key, no new dependency. (v1.3.0 P2, MeetUp VEX-2026-008)
- AbuseIPDB IP enrichment: investigate on an IP now adds AbuseIPDB confidence score, total reports, and last-reported date when `VEX_ABUSEIPDB_API_KEY` (or `enrichment.abuseipdb_api_key`) is configured. Built-in secondary enricher, fail-open (never blocks the run), no-op without a key, no new dependency. (v1.3.0 P1, MeetUp VEX-2026-008)
- Secondary-enricher abstraction (`SecondaryEnricherProtocol`): plugins can augment an investigate result in place after the primary source; third-party secondary plugins via the `vex.secondary_plugins` entry-point group
- Batch IOC correlation: `--correlate` clusters multi-IOC runs by shared infrastructure (ASN, malware family, contacted IPs/domains, passive DNS). Deterministic cluster table (Rich/console) + `"clusters"` array in JSON. `vex/correlate.py`. (v1.3.0 P0, MeetUp VEX-2026-008)
- Automated test suite (`tests/`): 301 unit tests

### Changed
- Internal: enrichment now dispatches through the plugin registry (`PluginRegistry`/`EnricherProtocol`) instead of a hardcoded resolver. The VirusTotal plugin owns a single lazily-created, lock-guarded `VTClient` reused across the run (and across batch threads), preserving rate-limit continuity. Foundation for multi-source enrichment (AbuseIPDB/Shodan as real plugins). covering cache (incl. v1.2.1 concurrency regression), IOC detector, defang, knowledge base, timeline, config, and async client — all deterministic, no network
- `[dev]` optional dependency group (`pytest`, `ruff`)
- CI: GitHub Actions `tests.yml` workflow (ruff + pytest on push/PR)

### Fixed
- Lint cleanup: removed unused imports and f-strings without placeholders (ruff F401/F541) across `ai/prompt`, `main`, `mitre/mapper`, `output/formatter`, `output/stix`, `timeline`

## [1.2.1] - 2026-04-28

### Fixed
- Batch mode `InterfaceError: bad parameter or other API misuse` — added `threading.Lock` to `Cache` to serialize concurrent SQLite access from `ThreadPoolExecutor` workers

## [1.2.0] - 2026-03-21

### Added
- AI enrichment: `--explain` and `--explain-model` flags on `triage` and `investigate`
- `vex/ai/` package with protocol, prompt, template, anthropic, openai, ollama, and cache modules
- `AIConfig` and generalized service config system
- AI output: Rich panel "AI Analysis" and JSON field `"explanation"`
- Optional dependency groups: `[ai]`, `[ai-local]`, `[ai-all]`
- barb → vex pipeline: `--from-barb` flag with `BarbContext` and `BarbSignal` bridge
- WHOIS enrichment: `vex/enrichers/whois_enricher.py`
- ATT&CK Navigator export via `--navigator` flag
- `vex addons` subcommand with Rich table listing available plugins
- First-run hint in banner
- `vex config --show` with masked API keys

## [1.1.1] - 2026-03-18

### Changed
- CI: switched to Trusted Publisher (OIDC) for automated PyPI publish
- Package renamed from `vex` to `vex-ioc` for PyPI publication

## [1.1.0] - 2026-03-16

### Added
- Batch IOC processing in CLI
- Entry-point plugin discovery
- IPv6 detection via `ipaddress.ip_address()`
- Passive version check via PyPI JSON API

### Fixed
- Graceful degradation when premium endpoints are unavailable

## [1.0.1] - 2026-03-16

### Fixed
- UX improvements and quality polish

## [1.0.0] - 2026-03-13

### Added
- Core VirusTotal IOC enrichment for IP, domain, URL, and hash indicators
- MITRE ATT&CK mapping
- STIX export
- Configuration management via `vex config`
- Rich CLI output for `triage` and `investigate`
- API key configuration via terminal

[Unreleased]: https://github.com/duathron/vex/compare/v1.2.1...HEAD
[1.2.1]: https://github.com/duathron/vex/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/duathron/vex/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/duathron/vex/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/duathron/vex/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/duathron/vex/releases/tag/v1.0.0
