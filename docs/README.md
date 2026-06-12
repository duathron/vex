# vex — Documentation

`vex` is a command-line tool that takes an indicator of compromise (IOC) — a file
hash, IP address, domain, or URL — and turns it into a verdict you can act on. It
queries the VirusTotal API as its primary source, optionally layers in secondary
threat-intel sources, and prints the result in whichever format your workflow
needs: a colored terminal table, JSON, NDJSON, CSV, STIX 2.1, an ATT&CK Navigator
layer, or a self-contained HTML report.

It is built for SOC triage and DFIR investigation. `triage` answers "is this bad,
and how bad?" in as few API calls as possible. `investigate` goes deep — PE
metadata, sandbox behavior, passive DNS, infrastructure, and MITRE ATT&CK mapping.
`vex` also sits in the middle of a small pipeline: it can pull IOCs out of a
[barb](https://github.com/duathron/vex) URL pre-scan or a `sift` alert report,
enrich them, and hand the results back.

**Released version: `vex 1.6.1`.** **On main (pending 1.7.0):** TI write-back (`--sight` / `--dry-run-sight`), `vex watchlist run`, daily VT-quota counter, `--version` flag.

## Who this is for

- **SOC analysts** doing fast triage on alert IOCs.
- **DFIR responders** who need the deep view and exportable evidence (STIX, ATT&CK).
- **Automation authors** wiring `vex` into pipelines via exit codes and machine output.

## Pages

| Page | What it covers |
|------|----------------|
| [Getting started](getting-started.md) | Install, set the VirusTotal key, your first `triage`, reading the output, `triage` vs `investigate`. |
| [Commands](commands.md) | Every command and every flag, taken from `--help`, with one example each. |
| [Enrichment](enrichment.md) | How verdicts are formed: VirusTotal (primary) vs the secondary enrichers (AbuseIPDB, Shodan, WHOIS, MISP, OpenCTI) and exactly which result fields each adds. TI write-back (`--sight`). |
| [Output formats](output-formats.md) | Every output format with a real example: console/rich, JSON, NDJSON, CSV, STIX 2.1, ATT&CK Navigator, HTML. Defang rules. |
| [Pipeline](pipeline.md) | The precise contracts for `barb → vex`, `sift → vex`, and the `sift --enrich vex` round-trip. Input shapes, extraction rules, outputs. |
| [Configuration](configuration.md) | Config priority, the full environment-variable table, the `~/.vex/` files and their permissions, and `vex doctor`. |

## Verdict and exit-code key

| Verdict | Severity | Exit code |
|---------|----------|-----------|
| 🟢 CLEAN | 0 | 0 |
| 🟡 UNKNOWN | 1 | 0 |
| 🟠 SUSPICIOUS | 2 | 1 |
| 🔴 MALICIOUS | 3 | 2 |
| (runtime error / bad input) | — | 1 |

> [!NOTE]
> The exit code is computed from the **highest-severity** verdict in the run
> (batches included) before any `--alert` filtering. Source of truth:
> `vex/main.py` (`_EXIT_CODES = {0: 0, 1: 0, 2: 1, 3: 2}`).
