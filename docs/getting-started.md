# Getting started

[← Docs index](README.md)

This page gets you from nothing to a first verdict.

## Install

`vex` is published on PyPI as `vex-ioc`. The command stays `vex`.

```bash
pip install vex-ioc
```

To enable AI-powered explanations (`--explain`), install an AI extra:

```bash
pip install vex-ioc[ai]        # Anthropic + OpenAI client libraries
```

Direct WHOIS enrichment for domains is part of the base install — no extra needed.

Check what is installed at any time:

```bash
vex addons
```

```
                                   vex addons
╭───────────┬───────┬─────────────────────┬─────────────────┬──────────────────╮
│ Package   │ Group │ Status              │ Description     │ Install          │
├───────────┼───────┼─────────────────────┼─────────────────┼──────────────────┤
│ anthropic │ ai    │ ✓ installed 0.105.2 │ AI explanations │ —                │
│ openai    │ ai    │ not installed       │ AI explanations │ pip install …    │
│ whois     │ core  │ ✓ installed         │ Direct WHOIS …  │ —                │
╰───────────┴───────┴─────────────────────┴─────────────────┴──────────────────╯
```

## Set the VirusTotal API key

`vex` needs a VirusTotal API v3 key. There are three ways to supply it, in
priority order (highest wins):

1. **Per-command flag** — `--api-key` / `-k`:

   ```bash
   vex triage 8.8.8.8 --api-key YOUR_VT_KEY
   ```

2. **Environment variable** — `VT_API_KEY`:

   ```bash
   export VT_API_KEY=YOUR_VT_KEY
   vex triage 8.8.8.8
   ```

3. **Saved config** — written to `~/.vex/config.yaml`:

   ```bash
   vex config --set-api-key YOUR_VT_KEY
   ```

> [!NOTE]
> If no key is found, `vex` raises a clear error listing all three options. See
> [Configuration](configuration.md) for the full priority chain and file
> permissions.

## Your first triage

```bash
vex triage 8.8.8.8
```

`triage` detects the IOC type automatically (hash / IP / domain / URL), makes a
minimal number of VirusTotal calls, and prints a verdict. The IOC argument is
optional — if you omit it, `vex` reads one IOC from stdin (or use `--file` for a
list, one IOC per line).

## How to read the output

The default format is `console`. The key fields:

- **Verdict** — one of four levels, color-coded:

  | Verdict | Meaning |
  |---------|---------|
  | 🟢 CLEAN | Enough engines saw it and none flagged it. |
  | 🟡 UNKNOWN | Not enough signal to decide (e.g. too few engines). |
  | 🟠 SUSPICIOUS | Some engines flagged it, below the malicious threshold. |
  | 🔴 MALICIOUS | Detections at or above the malicious threshold. |

  Thresholds are configurable (`thresholds.malicious_min_detections` etc. — see
  [Configuration](configuration.md)).

- **Detection ratio** — `malicious / total` engines (e.g. `7/68`).
- **Malware families**, **categories**, **tags** — what VirusTotal associates with the IOC.
- **Local knowledge** — any tags / notes / watchlists you have attached locally
  (see the `tag`, `note`, `watchlist` commands in [Commands](commands.md)).

The process **exit code** mirrors the verdict, so you can branch in scripts:

```bash
vex triage 8.8.8.8 && echo "not malicious" || echo "alert"
```

| Highest verdict in run | Exit code |
|------------------------|-----------|
| CLEAN / UNKNOWN | 0 |
| SUSPICIOUS | 1 |
| MALICIOUS | 2 |
| runtime error / bad input | 1 |

## `triage` vs `investigate`

| | `triage` | `investigate` |
|---|----------|---------------|
| Goal | Fast "is it bad?" | Deep "what is it, what did it do?" |
| VirusTotal calls | Minimal | More (relationships, behaviors) |
| Secondary enrichers | No | **Yes** (AbuseIPDB, Shodan, WHOIS, MISP, OpenCTI) |
| Extra data | Verdict, ratio, families | + PE info, sandbox behavior, passive DNS, ASN, ATT&CK mapping |
| Extra outputs | CSV (`--csv`) | ATT&CK Navigator (`--navigator`), timeline (`--timeline`) |

Rule of thumb: start with `triage`. When an IOC is interesting enough to dig
into, run `investigate` on it.

```bash
vex investigate 203.0.113.10
```

> [!NOTE]
> Secondary enrichers run on `investigate` only. A `triage` (even with
> `--explain`) gets no AbuseIPDB / Shodan / MISP / OpenCTI context by design.

## Next steps

- [Commands](commands.md) — full flag reference.
- [Enrichment](enrichment.md) — how the verdict is built and what each source adds.
- [Output formats](output-formats.md) — JSON, NDJSON, CSV, STIX, Navigator, HTML.
- [Pipeline](pipeline.md) — feed IOCs in from barb/sift and back out.
