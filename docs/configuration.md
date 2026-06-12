# Configuration

[← Docs index](README.md)

`vex` resolves every setting through a fixed priority chain and stores user state
under `~/.vex/`.

## Priority chain

For any given value, the **first** source that provides it wins:

```
command-line flag  >  environment variable  >  ~/.vex/config.yaml  >  built-in defaults
```

For example the VirusTotal key resolves as `--api-key` → `VT_API_KEY` →
`api.key` in config → error if none. Config loading itself follows: an explicit
`--config <path>` → `~/.vex/config.yaml` (if it exists) → the packaged default
`config.yaml` → built-in `Config()` defaults. (Source: `vex/config.py`.)

## Environment variables

| Variable | Sets | Config equivalent |
|----------|------|-------------------|
| `VT_API_KEY` | VirusTotal API key | `api.key` |
| `VEX_AI_API_KEY` | AI provider API key | `ai.api_key` |
| `VEX_ABUSEIPDB_API_KEY` | AbuseIPDB key | `enrichment.abuseipdb_api_key` |
| `VEX_SHODAN_API_KEY` | Shodan key | `enrichment.shodan_api_key` |
| `MISP_URL` | MISP base URL | `enrichment.misp_url` |
| `MISP_API_KEY` | MISP API key | `enrichment.misp_api_key` |
| `OPENCTI_URL` | OpenCTI base URL | `enrichment.opencti_url` |
| `OPENCTI_TOKEN` | OpenCTI API token | `enrichment.opencti_token` |

For each of these the env var takes precedence over the config-file value.
A `.env` file in the working directory is loaded automatically (`python-dotenv`).

## Config file: `~/.vex/config.yaml`

Written by `vex config --set-api-key / --set-ai-provider / --set-ai-key`, or
edited by hand. The model (`vex/config.py`):

### `api`

| Key | Default | Meaning |
|-----|---------|---------|
| `api.key` | `null` | VirusTotal API key. |
| `api.tier` | `free` | `free` or `premium`. Controls rate limits. |

Rate limits per tier — free: 4 req/min, 500/day; premium: 1000 req/min,
50000/day.

### `thresholds`

| Key | Default | Meaning |
|-----|---------|---------|
| `thresholds.malicious_min_detections` | `3` | Detections at/above this → MALICIOUS. |
| `thresholds.suspicious_min_detections` | `1` | Detections at/above this (below malicious) → SUSPICIOUS. |
| `thresholds.min_engines_for_clean` | `10` | Minimum engines that must weigh in before CLEAN. |

### `cache`

| Key | Default | Meaning |
|-----|---------|---------|
| `cache.enabled` | `true` | Use the local result cache. |
| `cache.ttl_hours` | `24` | Cache entry lifetime. |
| `cache.db_path` | `null` | Override path; default is `~/.vex/cache.db`. |

### `output`

| Key | Default | Meaning |
|-----|---------|---------|
| `output.default_format` | `json` | Default output when `--output` is not given by config. |
| `output.quiet` | `false` | Suppress the banner. |

### `ai`

| Key | Default | Meaning |
|-----|---------|---------|
| `ai.provider` | `none` | `none` \| `anthropic` \| `openai` \| `ollama`. |
| `ai.model` | `null` | Model override (else provider default). |
| `ai.api_key` | `null` | AI key (overridden by `VEX_AI_API_KEY`). |
| `ai.base_url` | `null` | For Ollama, e.g. `http://localhost:11434`. |
| `ai.max_tokens` | `500` | Explanation length cap. |
| `ai.temperature` | `0.3` | Sampling temperature. |
| `ai.local_only` | `false` | When `true`, reject cloud providers. |
| `ai.cache_ttl_hours` | `72` | AI explanation cache lifetime. |

### `enrichment`

| Key | Default | Meaning |
|-----|---------|---------|
| `enrichment.whois_enabled` | `true` | Direct WHOIS lookup for domains. |
| `enrichment.abuseipdb_api_key` | `null` | AbuseIPDB key. |
| `enrichment.abuseipdb_max_age_days` | `90` | AbuseIPDB report window. |
| `enrichment.shodan_api_key` | `null` | Shodan key. |
| `enrichment.misp_url` | `null` | MISP base URL. |
| `enrichment.misp_api_key` | `null` | MISP API key. |
| `enrichment.misp_verify_tls` | `true` | Verify MISP TLS certs. |
| `enrichment.opencti_url` | `null` | OpenCTI base URL. |
| `enrichment.opencti_token` | `null` | OpenCTI API token. |
| `enrichment.opencti_verify_tls` | `true` | Verify OpenCTI TLS certs. |
| `enrichment.stix_tlp_version` | `"1.0"` | TLP marking-definition id set for STIX export: `"1.0"` or `"2.0"`. |
| `enrichment.writeback_enabled` | `false` | Master switch for TI write-back. Must be `true` before `--sight` does anything. *(on main — pending 1.7.0)* |
| `enrichment.writeback_tlp` | `"green"` | TLP ceiling for writes. A write is blocked when the source IOC's TLP is more restrictive than this value. Rank: `red` (most restrictive) → `amber` → `green` → `clear`. *(on main — pending 1.7.0)* |
| `enrichment.writeback_min_verdict` | `"SUSPICIOUS"` | Verdict floor — IOCs below this verdict are silently skipped. Valid: `CLEAN`, `UNKNOWN`, `SUSPICIOUS`, `MALICIOUS`. *(on main — pending 1.7.0)* |

> [!NOTE]
> `stix_tlp_version` controls which canonical TLP marking-definition IDs the STIX
> exporter emits. `"1.0"` (default) uses the original STIX 2.1 TLP IDs — note
> that **TLP:CLEAR/WHITE both map to the TLP 1.0 WHITE id**. Set `"2.0"` to emit
> FIRST TLP 2.0 IDs (separate CLEAR id). See
> [output formats → STIX](output-formats.md#stix-21).

### `plugins` / `update_check`

| Key | Default | Meaning |
|-----|---------|---------|
| `plugins.load_local` | `false` | Opt-in scanning of `~/.vex/plugins/`. |
| `update_check.enabled` | `true` | Passive PyPI version check. |
| `update_check.check_interval_hours` | `24` | How often to check. |

### Daily VT-quota counter *(on main — pending 1.7.0)*

`vex` tracks actual fresh-lookup consumption in a persistent UTC-keyed JSON file (`~/.vex/quota.json`). It resets automatically at midnight UTC. After every batch or `watchlist run`, the quota status is printed to stderr:

```
VT quota: 38/500 used today, 462 remaining
```

When fewer than 10 % of the daily limit remain, an additional warning line is printed. The counter is fail-open — any read/write error is swallowed silently. The daily limit comes from `api.rate_limit.requests_per_day` in config (default 500 for free tier). The `--max-quota` flag caps fresh lookups per *run*; the quota counter tracks cumulative usage across *all* runs in the day.

## The `~/.vex/` directory

| File | Purpose | Permissions |
|------|---------|-------------|
| `~/.vex/` (dir) | All user state | `0o700` (owner-only) |
| `config.yaml` | Saved configuration (keys, AI provider) | `0o600` (owner read/write) on save |
| `cache.db` | SQLite VirusTotal result cache | inside the `0o700` dir |
| `knowledge.db` | SQLite local knowledge base (tags / notes / watchlists) | inside the `0o700` dir |
| `quota.json` | Daily VT-quota counter (resets at midnight UTC) *(on main — pending 1.7.0)* | inside the `0o700` dir |

> [!WARNING]
> The `~/.vex/` directory is created with `0o700` and `config.yaml` is saved with
> `0o600`, so secrets are owner-readable only. Keep it that way — do not relax
> these permissions.

Clear the result cache with `vex cache-clear`. The knowledge base is managed via
the `tag`, `note`, and `watchlist` commands ([Commands](commands.md)).

## Diagnosing with `vex doctor`

`vex doctor` reports which enrichers/services are configured and reachable — it is
the fastest way to find a **silently failing** enricher (since secondaries fail
open, a wrong key produces no error during a normal run).

```bash
vex doctor             # config-only: which keys/URLs are set? No network.
vex doctor --probe     # also test live connectivity to each service.
vex doctor -o json     # machine-readable diagnostics
```

| Flag | Effect |
|------|--------|
| (none) | Config-only check, no network. |
| `--probe` | Live connectivity test (network calls). |
| `-o json` | JSON output instead of the rich table. |
| `-c <path>` | Use a specific `config.yaml`. |

If an `investigate` run is missing AbuseIPDB / Shodan / MISP / OpenCTI fields you
expected, run `vex doctor --probe` first — the enricher is probably unconfigured
or its key/URL is wrong, and the fail-open design hid it.
