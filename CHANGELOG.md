# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.1] - 2026-06-02

Patch release: two real failures on core paths in 1.5.0 (`triage <filename>`, `investigate <PE hash>`) plus full refang parity.

### Fixed
- IOC detection no longer misreads executable/script filenames as domains. `wcdbcrk.dll`, `payload.exe`, etc. matched the domain regex (their extension looked like a TLD) and triggered a bogus VirusTotal domain lookup → HTTP 400 / `HTTPStatusError`. Non-TLD file extensions (`exe`/`dll`/`sys`/`scr`/`bat`/`ps1`/`vbs`/…) now detect as `UNKNOWN` and are skipped cleanly. Real TLDs (`.com`, `.app`, `.dev`, `.zip`, `.mov`, `.sh`) are unaffected.
- `investigate` on a PE-file hash no longer crashes with a Pydantic `ValidationError`. VirusTotal returns `pe_info.machine_type` as an int (e.g. `332` = `0x14C` i386), but `PEInfo.target_machine` is a string field — the value is now coerced. (Affected any PE sample with an integer `machine_type`.)
- Refang now covers the full defang spectrum (parity with barb/sift): `(.)`, `{.}`, `(dot)`/`{dot}`, `(at)`/`{at}` (domain-guarded), `[/]`, fullwidth `．＠：／`, and zero-width/BOM stripping — in addition to the existing `hxxp(s)`/`fxp`, `[://]`, `[.]`, `[:]`, `[@]`, `[dot]`, `[at]`. Idempotent; IPv6 `[::1]` preserved. `is_defanged()` detection extended to match. Public API unchanged.

## [1.5.0] - 2026-06-01

**TI Platform Integration** — vex becomes a multi-source enrichment hub. MISP + OpenCTI lookup, OpenCTI-ready STIX with TLP markings, plus pre-release hardening (parallel enrichers, `vex doctor`, AI prompt-injection defense). MISP (2.5.38) and OpenCTI (demo 7.26) enrichers live-verified end-to-end; Anthropic + Ollama AI live-verified.

### Security
- Prompt-injection defense for the AI layer (adapted from sift): attacker-influenced fields fed to the LLM by `--explain`/`--correlate --explain` (malware-family labels, file names, sandbox process/DNS/mutex/registry strings, tags, categories, WHOIS org) are now scanned and CRITICAL injection attempts (instruction-override, output-manipulation, shell-command) are redacted before prompt submission. NFKC normalization defeats unicode/zero-width bypasses; IOC/hash fields skip the encoded-payload check to avoid false positives. `vex/ai/injection_detector.py`.

### Changed
- AI provider robustness (adapted from sift): instructions moved to a proper `system` prompt (distinct prompts for `--explain` vs correlation, with an IOC-type glossary) instead of being jammed into the user message; defensive response-content extraction (tolerates non-text blocks); `anthropic.APIError` wrapped with a friendly message; Anthropic default model refreshed to `claude-sonnet-4-6`. Backward-compatible (`system` is optional). `--explain` output unchanged in shape (concise prose).

### Added
- Test coverage round 2: VT client (rate limiter, 404/429/premium paths), all four VT enrichers (ip/domain/hash/url triage + investigate parsing), and the batch path (cache hits, fail counting, thread-pool + sequential) — 91 new tests, all mocked/no-network. Suite now **625 tests**.
- OpenCTI IOC lookup: investigate consults an OpenCTI instance (GraphQL `stixCyberObservables`) for every IOC type when `OPENCTI_URL` + `OPENCTI_TOKEN` are configured, attaching `opencti_known`, observable id, `x_opencti_score`, labels, and **TLP marking** (most-restrictive). Built-in secondary enricher, **raw GraphQL over httpx (no `pycti` dependency)** — defensive parsing tolerates OpenCTI schema/version drift, fail-open, no-op without config, TLS-verify default. Token never logged, masked in `config --show`. (v1.5.0 P2, MeetUp VEX-2026-010 — built raw-httpx rather than the voted `pycti` extra: leaner, mockable, fail-open absorbs version drift; matches the MISP precedent)
- STIX 2.1 export hardened for OpenCTI: bundles now include a vex `identity` (`created_by_ref` provenance), STIX **Cyber-observables (SCOs)** with `indicator → based-on → observable` relationships, ATT&CK `external_references` on attack-patterns, and **TLP `marking-definition`s** — when an IOC carries a MISP TLP, the canonical STIX 2.1 TLP marking is attached via `object_marking_refs` (markings never dropped). Deterministic IDs (idempotent re-export). README "Feeding OpenCTI" section added. (v1.5.0 P1, MeetUp VEX-2026-010)
- MISP IOC lookup: investigate now consults a MISP instance (`/attributes/restSearch`) for every IOC type when `MISP_URL` + `MISP_API_KEY` are configured, attaching `misp_known`, event IDs, tags, **TLP marking** (most-restrictive wins), and last-seen. Built-in secondary enricher, raw httpx (no `pymisp` dep), fail-open, no-op without config, TLS-verify on by default (`misp_verify_tls` to opt out for lab instances). TLP/markings are carried through, never dropped. (v1.5.0 P0, MeetUp VEX-2026-010)

## [1.4.0] - 2026-05-31

This release bundles the **"Batch Intelligence"** (v1.3.0, never separately published) and **"Scale & Pipeline"** (v1.4.0) work. Test suite grew from 0 → 375 deterministic tests with CI.

### Added
- `vex doctor`: reports configuration + connectivity for every service (VirusTotal, AI provider, AbuseIPDB, Shodan, MISP, OpenCTI) — config-only by default (no network), `--probe` tests live connectivity and **surfaces the actual error** instead of the silent fail-open enrichers would otherwise hide (e.g. an unreachable MISP/OpenCTI). Secrets never printed; quota-costing services not auto-probed. `-o json` for scripting. `vex/doctor.py`. (pre-release hardening)
- sift → vex pipeline: `--from-sift` reads sift's JSON `TriageReport` from stdin, extracts the IOCs it found (cluster + alert IOCs, source/dest IPs, deduped), and enriches them. Closes the sift ↔ vex enrichment loop (symmetric to `--from-barb`; mutually exclusive with it). `vex/pipeline/sift_bridge.py`. (v1.4.x, topology clarification 2026-05-31)
- Rate-limit-aware scheduling: multi-IOC runs print an up-front ETA (IOC count · tier · est. time) to stderr, a post-run `processed (N from API, M cached), K failed` summary (the cached count doubles as a resume signal), and a `--max-quota N` budget guard that caps fresh API lookups (cached always served; excess IOCs skipped with a notice). All notices stderr-only. (v1.4.0 P1, MeetUp VEX-2026-009)
- IOC deduplication: batch input is de-duplicated (order-preserving) before any query, saving API quota on pipeline-scale runs with repeated IOCs; a `N → M unique (K removed)` notice prints to stderr. `--no-dedup` disables it. (v1.4.0 P0, MeetUp VEX-2026-009)
- NDJSON streaming output: `-o ndjson` emits one JSON object per result line, flushed per line (pipeline/crash-friendly), following the JSON defang rule (real IOCs unless `--defang`). Clusters emitted as `{"_type":"cluster",...}` lines under `--correlate`. (v1.4.0 P0, MeetUp VEX-2026-009)
- AI correlation narratives: with `--correlate` **and** `--explain` on a batch run, vex generates a short per-cluster campaign-correlation narrative (opt-in, cached, template fallback when no LLM). `--correlate` alone stays deterministic. IOCs defanged in prompts. (v1.3.0 P1, MeetUp VEX-2026-008)
- HTML report export: `--html <path>` on `triage`/`investigate` writes a self-contained HTML report (reuses the Rich rendering, embedded CSS) alongside normal output. IOC strings are defanged in the report body. `vex/output/html.py`. (v1.3.0 P1, MeetUp VEX-2026-008)
- Shodan IP enrichment: investigate on an IP adds Shodan open ports, hostnames, org, and tags when `VEX_SHODAN_API_KEY` (or `enrichment.shodan_api_key`) is configured. Built-in secondary enricher, fail-open, no-op without a key, no new dependency. (v1.3.0 P2, MeetUp VEX-2026-008)
- AbuseIPDB IP enrichment: investigate on an IP now adds AbuseIPDB confidence score, total reports, and last-reported date when `VEX_ABUSEIPDB_API_KEY` (or `enrichment.abuseipdb_api_key`) is configured. Built-in secondary enricher, fail-open (never blocks the run), no-op without a key, no new dependency. (v1.3.0 P1, MeetUp VEX-2026-008)
- Secondary-enricher abstraction (`SecondaryEnricherProtocol`): plugins can augment an investigate result in place after the primary source; third-party secondary plugins via the `vex.secondary_plugins` entry-point group
- Batch IOC correlation: `--correlate` clusters multi-IOC runs by shared infrastructure (ASN, malware family, contacted IPs/domains, passive DNS). Deterministic cluster table (Rich/console) + `"clusters"` array in JSON. `vex/correlate.py`. (v1.3.0 P0, MeetUp VEX-2026-008)
- Automated test suite (`tests/`): 375 unit tests covering cache (incl. v1.2.1 concurrency regression), IOC detector, defang, knowledge base, timeline, config, async client, plugin dispatch, correlation, AbuseIPDB/Shodan enrichers, HTML export, and AI narratives — all deterministic, no network

### Changed
- Internal: enrichment now dispatches through the plugin registry (`PluginRegistry`/`EnricherProtocol`) instead of a hardcoded resolver. The VirusTotal plugin owns a single lazily-created, lock-guarded `VTClient` reused across the run (and across batch threads), preserving rate-limit continuity. Foundation for multi-source enrichment (AbuseIPDB/Shodan as real plugins).
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

[Unreleased]: https://github.com/duathron/vex/compare/v1.5.1...HEAD
[1.5.1]: https://github.com/duathron/vex/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/duathron/vex/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/duathron/vex/compare/v1.2.1...v1.4.0
[1.2.1]: https://github.com/duathron/vex/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/duathron/vex/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/duathron/vex/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/duathron/vex/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/duathron/vex/releases/tag/v1.0.0
