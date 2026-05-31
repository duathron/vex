# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Automated test suite (`tests/`): 179 unit tests covering cache (incl. v1.2.1 concurrency regression), IOC detector, defang, knowledge base, timeline, config, and async client — all deterministic, no network
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
