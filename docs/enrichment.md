# Enrichment model

[← Docs index](README.md)

`vex` has one **primary** source and several **secondary** ones.

- **VirusTotal (primary)** — always runs. It produces the **verdict** and the core
  fields. This is the only source consulted by `triage`.
- **Secondary enrichers** — AbuseIPDB, Shodan, WHOIS, MISP, OpenCTI. They run on
  **`investigate` only**, add extra context fields, and never change the verdict.

## VirusTotal (primary)

VirusTotal is queried for every IOC. The detection statistics it returns are
mapped to a verdict using the thresholds in
[configuration](configuration.md#thresholds):

| Verdict | Rough rule (configurable) |
|---------|---------------------------|
| 🔴 MALICIOUS | malicious detections ≥ `malicious_min_detections` (default 3) |
| 🟠 SUSPICIOUS | detections ≥ `suspicious_min_detections` (default 1) but below malicious |
| 🟢 CLEAN | enough engines weighed in (≥ `min_engines_for_clean`, default 10) and none flagged it |
| 🟡 UNKNOWN | not enough signal to decide |

VirusTotal populates these `TriageResult` fields (see
[output formats](output-formats.md) for full JSON):

`ioc`, `ioc_type`, `verdict`, `detection_stats` (`malicious`/`suspicious`/
`undetected`/`harmless`/…), `malware_families`, `categories`, `tags`,
`first_seen`, `last_seen`, `last_analysis_date`, `flagging_engines`, `reputation`.

On `investigate`, VirusTotal also fills the deep `InvestigateResult` fields it has
data for: `file_type`/`file_size`/`pe_info`/`sandbox_behaviors`/`contacted_ips`/
`contacted_domains`/`dropped_files`/`yara_hits` (files), `asn`/`asn_owner`/
`country`/`network`/`passive_dns` (network), `whois`/`dns_records`/`subdomains`
(domains), `final_url`/`title` (URLs), plus `attack_mappings`.

## Secondary enrichers — shared invariants

Every secondary enricher obeys the same rules. These are hard guarantees, not
defaults you can accidentally lose:

- **`investigate` only.** They never run during `triage`.
- **Key-gated, no-op without a key.** With no credentials the enricher does
  **nothing** — no network call, no error, no fields written.
- **Fail-open.** Any exception (network, parse, schema mismatch, non-200) is
  caught and logged at DEBUG. The enricher never raises, never crashes the run,
  never blocks the others.
- **Parallel.** With two or more configured secondaries, `vex` dispatches them
  concurrently (`ThreadPoolExecutor`, up to 8 workers). Each writes its own
  distinct fields, so there is no shared mutable state. One failure does not
  prevent the rest from running. (Source: `vex/batch.py::run_secondary_enrichers`.)
- **Additive only.** Secondaries never change the VirusTotal verdict; they add
  context fields alongside it.

Run `vex doctor` to see which secondaries are configured, and `vex doctor --probe`
to test their live connectivity.

---

## AbuseIPDB

| | |
|---|---|
| Applies to | `ipv4`, `ipv6` |
| Needs | API key — `VEX_ABUSEIPDB_API_KEY` env or `enrichment.abuseipdb_api_key` |
| Queries | `GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=<n>` (default 90 days, `enrichment.abuseipdb_max_age_days`) |
| Adds fields | `abuse_confidence` (score 0–100), `abuse_total_reports`, `abuse_last_reported` |

---

## Shodan

| | |
|---|---|
| Applies to | `ipv4`, `ipv6` |
| Needs | API key — `VEX_SHODAN_API_KEY` env or `enrichment.shodan_api_key` |
| Queries | `GET https://api.shodan.io/shodan/host/<ip>?key=…` |
| Adds fields | `shodan_ports` (list[int]), `shodan_hostnames` (list[str]), `shodan_org`, `shodan_tags` (list[str]) |

---

## WHOIS

| | |
|---|---|
| Applies to | `domain` |
| Needs | Nothing — `python-whois` is a **core dependency** (since v1.2.0). Toggle with `enrichment.whois_enabled` (default `true`). |
| Queries | A direct WHOIS lookup for the bare domain. Used as a fallback when VirusTotal did not already provide WHOIS data. |
| Adds fields | `whois` → `WHOISInfo` { `registrar`, `creation_date`, `expiration_date`, `updated_date`, `name_servers` (list), `registrant_org`, `registrant_country` } |

> [!NOTE]
> WHOIS is the one secondary that needs no key. It still fails open: a failed
> lookup yields `whois = null`, never an error.

---

## MISP

| | |
|---|---|
| Applies to | all IOC types (`md5`, `sha1`, `sha256`, `ipv4`, `ipv6`, `domain`, `url`) |
| Needs | **both** a URL and an API key — `MISP_URL` + `MISP_API_KEY` env, or `enrichment.misp_url` + `enrichment.misp_api_key`. TLS verify on by default (`enrichment.misp_verify_tls`). |
| Queries | `POST <misp_url>/attributes/restSearch` with `{value, limit: 25, includeEventTags: true}` |
| Adds fields | `misp_known` (bool), `misp_event_ids` (list[str]), `misp_tags` (list[str]), `misp_tlp` (most-restrictive TLP found, e.g. `"AMBER"`), `misp_last_seen` (ISO date) |

TLP precedence (most restrictive wins): `red > amber > green > clear/white`. The
resolved `misp_tlp` flows into the STIX export's TLP marking (see
[output formats → STIX](output-formats.md#stix-21)).

---

## OpenCTI

| | |
|---|---|
| Applies to | all IOC types (`md5`, `sha1`, `sha256`, `ipv4`, `ipv6`, `domain`, `url`) |
| Needs | **both** a URL and a token — `OPENCTI_URL` + `OPENCTI_TOKEN` env, or `enrichment.opencti_url` + `enrichment.opencti_token`. TLS verify on by default (`enrichment.opencti_verify_tls`). |
| Queries | `POST <opencti_url>/graphql` — a `stixCyberObservables` search by value (raw GraphQL via httpx; no `pycti` dependency) |
| Adds fields | `opencti_known` (bool), `opencti_id` (STIX id), `opencti_score` (int), `opencti_labels` (list[str]), `opencti_tlp` (most-restrictive TLP) |

> [!NOTE]
> OpenCTI parsing is deliberately defensive (all `.get()`), so a schema
> difference across OpenCTI versions yields **no enrichment rather than an
> error** — the fail-open guarantee in action.

---

## Quick field map

| Source | Fields it writes |
|--------|------------------|
| VirusTotal | verdict + all core triage/investigate fields |
| AbuseIPDB | `abuse_confidence`, `abuse_total_reports`, `abuse_last_reported` |
| Shodan | `shodan_ports`, `shodan_hostnames`, `shodan_org`, `shodan_tags` |
| WHOIS | `whois` (WHOISInfo) |
| MISP | `misp_known`, `misp_event_ids`, `misp_tags`, `misp_tlp`, `misp_last_seen` |
| OpenCTI | `opencti_known`, `opencti_id`, `opencti_score`, `opencti_labels`, `opencti_tlp` |

See [output formats](output-formats.md) for a full `InvestigateResult` JSON with
these fields populated.

---

## Write-back (opt-in)

vex can write **MISP sightings** and **OpenCTI observables** for IOCs that
exceed a configurable verdict floor. This is an advanced feature with three
explicit opt-in gates:

1. `enrichment.writeback_enabled: true` in config (default `false`).
2. `--sight` flag on `vex investigate`.
3. `--dry-run-sight` for a network-free preview.

### Verdict floor

Only IOCs at or above `enrichment.writeback_min_verdict` (default `SUSPICIOUS`)
are written. IOCs below the floor are silently skipped.

### TLP marking-check

Before each write, vex compares the source IOC's most-restrictive known TLP
(from the enrichment result's `misp_tlp` / `opencti_tlp`) against the
configured ceiling (`enrichment.writeback_tlp`, default `"green"`).

If the source TLP is **more restrictive** than the ceiling, the write is
**blocked**. This prevents publishing RED-marked data from one platform to
another platform that only accepts GREEN.

Rank order: `red` (0, most restrictive) → `amber` (1) → `green` (2) → `clear` (3, least restrictive).

### Fail-open

A write failure (network error, HTTP error, GraphQL error) is logged at DEBUG
and sets the result field to `false`. It never crashes the run.

### OpenCTI mutation (operator must verify)

The GraphQL mutation used is:

```graphql
mutation AddObservable($type: String!, $value: String!) {
  stixCyberObservableAdd(type: $type, observableData: { value: $value }) {
    id
  }
}
```

IOC type mapping: `ipv4` → `IPv4-Addr`, `ipv6` → `IPv6-Addr`, `domain` →
`Domain-Name`, `url` → `Url`, `md5`/`sha1`/`sha256` → `StixFile`.

The `observableData { value: $value }` shape works for network observables on
OpenCTI >= 5.x. For file-hash observables some versions require
`hashes: { MD5: $value }` — verify against your instance before relying on
hash write-back.

### Config example

```yaml
enrichment:
  writeback_enabled: true
  writeback_tlp: "green"
  writeback_min_verdict: "SUSPICIOUS"
  misp_url: https://misp.corp.example
  misp_api_key: ${MISP_API_KEY}
  opencti_url: https://opencti.corp.example
  opencti_token: ${OPENCTI_TOKEN}
```

### New result fields

| Field | Type | Meaning |
|-------|------|---------|
| `writeback_misp` | `bool \| null` | `null` = not attempted, `true` = written, `false` = failed/skipped |
| `writeback_opencti` | `bool \| null` | same |

Run `vex manual writeback` for the full guide.
