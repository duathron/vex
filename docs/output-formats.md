# Output formats

[← Docs index](README.md)

`vex` can emit the same enrichment result in several shapes. Pick with `-o` /
`--output`, or with the dedicated `--csv`, `--stix`, `--navigator`, `--html`
flags. Every JSON / NDJSON / STIX / cluster block below was produced by the real
serializers in `vex/output/` (see the snippet at the bottom), not hand-written.

| Format | How to select | Stream |
|--------|---------------|--------|
| console (default) | `-o console` | stdout |
| rich | `-o rich` | stdout |
| json | `-o json` | stdout |
| ndjson | `-o ndjson` | stdout |
| csv | `--csv` (triage only) | stdout |
| STIX 2.1 | `--stix` | stdout |
| ATT&CK Navigator | `--navigator` (investigate only) | stdout |
| HTML | `--html <path>` | file |

## Defang rule

`vex` can rewrite IOCs into a non-clickable form (`evil.com` → `evil[.]com`).

| Format | Defang behavior |
|--------|-----------------|
| HTML (`--html`) | **Always defanged.** The report is built for safe sharing; the IOC string in the report is never live. |
| console / rich / json / ndjson / csv / stix | **Real IOCs by default.** Defanged only when you pass `--defang`. |

So machine formats keep real, parseable IOCs unless you explicitly ask for
defanging. (Source: `vex/main.py::_maybe_defang*` apply only under `--defang`;
`vex/output/html.py` defangs unconditionally.)

> [!NOTE]
> Machine output goes to **stdout**; banners, the `--summary` line, progress
> bars, and warnings go to **stderr**. So `... -o ndjson > out.ndjson` gives you
> a clean machine file with notices still visible in the terminal.

---

## console / rich

The default. A colored, human-oriented layout: the verdict (color-coded by
severity), detection ratio, malware families, categories, tags, key dates, and any
local knowledge-base tags/notes/watchlists. `rich` is the styled table view;
`console` is the same content with lighter formatting. These are for reading, not
parsing — use JSON/NDJSON/CSV downstream.

The ASCII banner prints by default; suppress it with `--quiet` / `-q`.

---

## json (`-o json`)

Pretty-printed (2-space indent), one object per result. Produced by
`to_json(result)`. Real output for a malicious-domain `TriageResult`:

```json
{
  "ioc": "evil-domain.example",
  "ioc_type": "domain",
  "verdict": "MALICIOUS",
  "detection_stats": {
    "malicious": 7,
    "suspicious": 1,
    "undetected": 58,
    "harmless": 2,
    "timeout": 0,
    "type_unsupported": 0,
    "confirmed_timeout": 0,
    "failure": 0
  },
  "malware_families": [
    "emotet"
  ],
  "categories": [
    "malware",
    "phishing"
  ],
  "tags": [
    "c2"
  ],
  "first_seen": "2025-11-01T08:00:00Z",
  "last_seen": null,
  "last_analysis_date": "2026-05-30T12:00:00Z",
  "flagging_engines": [
    {
      "engine": "Kaspersky",
      "category": "malicious",
      "result": "Trojan.Emotet"
    }
  ],
  "reputation": -44,
  "from_cache": false,
  "error": null,
  "local_tags": [
    "incident-2026-014"
  ],
  "local_notes": [
    "seen in proxy logs 2026-05-29"
  ],
  "watchlists": [
    "priority"
  ]
}
```

An `investigate` result wraps the above under a `triage` key and adds the deep
fields (a trimmed real example showing the secondary-enricher fields):

```json
{
  "triage": {
    "ioc": "203.0.113.10",
    "ioc_type": "ipv4",
    "verdict": "MALICIOUS",
    "detection_stats": { "malicious": 5, "suspicious": 0, "undetected": 80, "harmless": 4, "timeout": 0, "type_unsupported": 0, "confirmed_timeout": 0, "failure": 0 },
    "malware_families": ["cobaltstrike"],
    "first_seen": "2025-12-02T00:00:00Z",
    "...": "(remaining triage fields)"
  },
  "attack_mappings": [
    { "technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "Command and Control", "evidence": "HTTP beaconing to known C2" }
  ],
  "asn": 64500,
  "asn_owner": "Example Hosting LLC",
  "country": "US",
  "network": "203.0.113.0/24",
  "abuse_confidence": 92,
  "abuse_total_reports": 140,
  "abuse_last_reported": "2026-05-28T10:00:00+00:00",
  "shodan_ports": [443, 8080],
  "shodan_hostnames": ["c2.example"],
  "shodan_org": "Example Hosting LLC",
  "shodan_tags": ["malware"],
  "misp_known": true,
  "misp_event_ids": ["1423"],
  "misp_tags": ["tlp:amber", "malware:cobaltstrike"],
  "misp_tlp": "AMBER",
  "misp_last_seen": "2026-05-20",
  "opencti_known": true,
  "opencti_id": "indicator--1234",
  "opencti_score": 80,
  "opencti_labels": ["cobaltstrike"],
  "opencti_tlp": "AMBER",
  "passive_dns": [
    { "hostname": "evil-domain.example", "ip_address": "203.0.113.10", "resolver": null, "last_resolved": "2026-01-05T00:00:00Z" }
  ]
}
```

> The `"...": "(remaining triage fields)"` line is an editorial elision for this
> doc — the real output always contains the full triage object and every
> `InvestigateResult` field (most `null`/`[]` when no data). See the snippet at
> the bottom to reproduce the complete object.

---

## ndjson (`-o ndjson`)

One compact JSON object **per line** (no indentation, no trailing newline per
object), produced by `to_ndjson(result)`. Ideal for streaming into log pipelines.
The same `TriageResult` as above:

```
{"ioc": "evil-domain.example", "ioc_type": "domain", "verdict": "MALICIOUS", "detection_stats": {"malicious": 7, "suspicious": 1, "undetected": 58, "harmless": 2, "timeout": 0, "type_unsupported": 0, "confirmed_timeout": 0, "failure": 0}, "malware_families": ["emotet"], "categories": ["malware", "phishing"], "tags": ["c2"], "first_seen": "2025-11-01T08:00:00Z", "last_seen": null, "last_analysis_date": "2026-05-30T12:00:00Z", "flagging_engines": [{"engine": "Kaspersky", "category": "malicious", "result": "Trojan.Emotet"}], "reputation": -44, "from_cache": false, "error": null, "local_tags": ["incident-2026-014"], "local_notes": ["seen in proxy logs 2026-05-29"], "watchlists": ["priority"]}
```

In a batch, you get one such line per IOC. Notices stay on stderr, so the stdout
stream is clean NDJSON.

---

## csv (`--csv`, triage only)

A flattened, spreadsheet-friendly view. `--csv` overrides `--output` and is only
available on `triage`. Produced by `to_csv_triage(results)`. Fixed column set:

```
ioc,ioc_type,verdict,malicious,suspicious,undetected,total,ratio,malware_families,categories,tags,first_seen,last_seen,last_analysis_date,reputation,from_cache,error
evil-domain.example,domain,MALICIOUS,7,1,58,68,7/68,emotet,malware|phishing,c2,2025-11-01T08:00:00+00:00,,2026-05-30T12:00:00+00:00,-44,False,
```

List-valued fields (`malware_families`, `categories`, `tags`) are joined with `|`.

---

## STIX 2.1 (`--stix`)

Produced by `to_stix_bundle(results, config)`. Emits a valid STIX 2.1 `bundle`
without requiring the heavy `stix2` library. Per result it builds:

- a `vex` **identity** SDO (source attribution; `created_by_ref` on every SDO);
- an **indicator** SDO with the IOC pattern, verdict label, and confidence;
- a cyber-observable **SCO** (`domain-name` / `ipv4-addr` / `ipv6-addr` / `url` /
  `file`) plus an `indicator → based-on → SCO` relationship;
- a **malware** SDO + `indicates` relationship per malware family;
- (investigate) an **attack-pattern** SDO with an `external_references` ATT&CK
  link + a `uses` relationship per ATT&CK mapping;
- a TLP **marking-definition** (when `misp_tlp` is set) referenced via
  `object_marking_refs` on every object. The TLP id set is selected by
  `enrichment.stix_tlp_version` (`"1.0"` default, `"2.0"` for TLP 2.0 ids — see
  [configuration](configuration.md)).

Real excerpt for an `InvestigateResult` (IP, `cobaltstrike`, `T1071.001`,
`misp_tlp="AMBER"`). IDs are deterministic UUID-5; the `bundle` id and `created`
timestamps vary per run:

```json
{
  "type": "bundle",
  "id": "bundle--17f02967-3821-43e0-ab33-a237a3557107",
  "objects": [
    {
      "type": "marking-definition",
      "spec_version": "2.1",
      "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
      "created": "2017-01-20T00:00:00.000Z",
      "definition_type": "tlp",
      "name": "TLP:AMBER",
      "definition": { "tlp": "amber" }
    },
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--d7dafe66-42c1-5925-813e-35ad7f36aceb",
      "created": "2024-01-01T00:00:00.000Z",
      "modified": "2024-01-01T00:00:00.000Z",
      "name": "vex",
      "identity_class": "system",
      "description": "vex — VirusTotal IOC Enrichment Tool for SOC/DFIR workflows."
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--c3ac9c79-1c1c-5fe9-b3df-66b02f862e3e",
      "created_by_ref": "identity--d7dafe66-42c1-5925-813e-35ad7f36aceb",
      "name": "VEX: 203.0.113.10",
      "description": "VirusTotal verdict: MALICIOUS. Detections: 5/89.",
      "pattern": "[ipv4-addr:value = '203.0.113.10']",
      "pattern_type": "stix",
      "valid_from": "2025-12-02T00:00:00.000Z",
      "labels": ["verdict:malicious"],
      "confidence": 50,
      "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"]
    },
    {
      "type": "ipv4-addr",
      "spec_version": "2.1",
      "id": "ipv4-addr--0bbe9091-6bf3-5f36-914a-eb235b9683ac",
      "value": "203.0.113.10",
      "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"]
    },
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--c41f5ad4-36f3-554c-ac03-7e25a1922f04",
      "relationship_type": "based-on",
      "source_ref": "indicator--c3ac9c79-1c1c-5fe9-b3df-66b02f862e3e",
      "target_ref": "ipv4-addr--0bbe9091-6bf3-5f36-914a-eb235b9683ac"
    },
    {
      "type": "malware",
      "spec_version": "2.1",
      "id": "malware--a37d8ad4-5aa2-5502-b79a-7afeefe7af21",
      "name": "cobaltstrike",
      "is_family": true,
      "malware_types": ["unknown"]
    },
    {
      "type": "attack-pattern",
      "spec_version": "2.1",
      "id": "attack-pattern--e97d467b-31e6-51f9-8caf-33698ba482eb",
      "name": "T1071.001: Web Protocols",
      "external_references": [
        { "source_name": "mitre-attack", "external_id": "T1071.001", "url": "https://attack.mitre.org/techniques/T1071/001/" }
      ]
    }
  ]
}
```

(The full bundle also contains the `indicates` and `uses` relationship objects;
several SDO fields were trimmed here for length.)

---

## ATT&CK Navigator (`--navigator`, investigate only)

Produced by `to_navigator_layer(...)`. Emits a MITRE ATT&CK Navigator v4.5 JSON
layer to stdout — redirect it to a file and open at
[mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/).
Each `attack_mapping` becomes a scored technique (score 100, deduped by technique
id; ATT&CK evidence becomes the cell comment). Shape:

```json
{
  "name": "vex — 203.0.113.10",
  "versions": { "attack": "14", "navigator": "4.9", "layer": "4.5" },
  "domain": "enterprise-attack",
  "techniques": [
    { "techniqueID": "T1071.001", "tactic": "command-and-control", "score": 100, "comment": "HTTP beaconing to known C2", "enabled": true }
  ],
  "gradient": { "colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100 }
}
```

```bash
vex investigate 203.0.113.10 --navigator > layer.json
```

---

## HTML (`--html <path>`)

Writes a self-contained HTML report to the given path while still printing your
normal console/rich output. The IOC strings in the report are **always defanged**
for safe sharing.

```bash
vex investigate 203.0.113.10 --html report.html
```

---

## Correlation clusters (`--correlate`, batch)

When you add `--correlate` to a **batch** JSON run, the output becomes a JSON
object with `results` **and** `clusters` (produced by
`to_json_list_with_clusters(results, clusters)`). A cluster is only created when
≥ 2 distinct IOCs share an attribute (ASN, family, contacted IP/domain, network,
passive DNS). Real `clusters` block for two IPs sharing ASN 64500:

```json
"clusters": [
  {
    "cluster_id": "C1",
    "attribute_type": "asn",
    "shared_attribute": "ASN 64500 (Example Hosting LLC)",
    "member_count": 2,
    "members": ["203.0.113.10", "203.0.113.20"],
    "max_verdict": "MALICIOUS"
  }
]
```

`--correlate` is a no-op for a single IOC.

---

## Reproducing these samples

All non-console blocks above were generated offline (no network) by constructing
model objects and calling the real serializers:

```python
from datetime import datetime, timezone
from vex.models import (TriageResult, InvestigateResult, DetectionStats,
                        EngineResult, Verdict, ATTACKMapping, PassiveDNSRecord)
from vex.output.export import to_json, to_ndjson, to_csv_triage, to_json_list_with_clusters
from vex.output.stix import to_stix_bundle
from vex.correlate import build_clusters

tr = TriageResult(
    ioc="evil-domain.example", ioc_type="domain", verdict=Verdict.MALICIOUS,
    detection_stats=DetectionStats(malicious=7, suspicious=1, undetected=58, harmless=2),
    malware_families=["emotet"], categories=["malware", "phishing"], tags=["c2"],
    first_seen=datetime(2025, 11, 1, 8, 0, tzinfo=timezone.utc),
    last_analysis_date=datetime(2026, 5, 30, 12, 0, tzinfo=timezone.utc),
    flagging_engines=[EngineResult(engine="Kaspersky", category="malicious", result="Trojan.Emotet")],
    reputation=-44, local_tags=["incident-2026-014"],
    local_notes=["seen in proxy logs 2026-05-29"], watchlists=["priority"],
)
print(to_json(tr))
print(to_ndjson(tr))
print(to_csv_triage([tr]))
# Build an InvestigateResult similarly and call to_stix_bundle([inv]) /
# build_clusters([a, b]) + to_json_list_with_clusters([a, b], clusters).
```
