"""Built-in OpenCTI secondary enricher plugin.

Augments InvestigateResult for all IOC types with OpenCTI observable data:
STIX ID, threat score, TLP marking, and labels.

Requires both an OpenCTI URL and an API token (OPENCTI_URL / OPENCTI_TOKEN
env vars or enrichment.opencti_url / enrichment.opencti_token in config).
Without both values the enricher is a complete no-op — no network calls, no
errors.

OpenCTI exposes a single GraphQL endpoint: POST {url}/graphql
Raw httpx GraphQL — no pycti dependency.

TLS verification is ON by default and controlled via enrichment.opencti_verify_tls.
TLP precedence (most restrictive wins): red > amber > green > clear/white.

Parsing is intentionally defensive (all .get()) to tolerate schema differences
across OpenCTI versions — a schema mismatch yields no enrichment rather than
an error (fail-open).
"""

from __future__ import annotations

import logging

import httpx

from ..config import Config
from ..enrichers.protocol import SecondaryEnricherProtocol
from ..models import InvestigateResult

logger = logging.getLogger("vex.plugins.opencti")

_GRAPHQL_QUERY = """
query SearchObservable($value: String!) {
  stixCyberObservables(
    filters: {
      mode: and
      filters: [{ key: "value", values: [$value] }]
      filterGroups: []
    }
    first: 1
  ) {
    edges {
      node {
        id
        observable_value
        objectLabel {
          value
        }
        objectMarking {
          definition
        }
        indicators {
          edges {
            node {
              x_opencti_score
            }
          }
        }
      }
    }
  }
}
"""

# TLP precedence — lower index = more restrictive
_TLP_ORDER = ["tlp:red", "tlp:amber", "tlp:green", "tlp:clear", "tlp:white"]


def _most_restrictive_tlp(definitions: list[str]) -> str | None:
    """Return the most restrictive TLP level found in the marking definitions, or None.

    Accepts strings like 'TLP:AMBER', 'TLP:RED', 'TLP:GREEN', 'TLP:CLEAR', 'TLP:WHITE'.
    Comparison is case-insensitive.
    """
    found: str | None = None
    found_rank = len(_TLP_ORDER)
    for definition in definitions:
        def_lower = definition.lower()
        for rank, tlp in enumerate(_TLP_ORDER):
            if def_lower == tlp:
                if rank < found_rank:
                    found_rank = rank
                    found = tlp.split(":", 1)[1].upper()  # e.g. "RED"
                break
    return found


class OpenCTIEnricher:
    """Secondary enricher that adds OpenCTI observable data to investigate results.

    Supports all IOC types — OpenCTI indexes every kind of STIX cyber observable.
    """

    @property
    def name(self) -> str:
        return "OpenCTI"

    @property
    def supported_ioc_types(self) -> list[str]:
        return ["md5", "sha1", "sha256", "ipv4", "ipv6", "domain", "url"]

    def enrich(
        self,
        result: InvestigateResult,
        ioc: str,
        ioc_type: str,
        config: Config,
    ) -> None:
        """Augment *result* with OpenCTI observable data.

        Fail-open: any exception (network, parse, schema mismatch, etc.) is
        caught and logged at DEBUG level. The method never raises out of itself.
        The API token is never written to logs.
        """
        url = config.opencti_url
        token = config.opencti_token
        if not url or not token:
            return

        try:
            graphql_url = url.rstrip("/") + "/graphql"
            response = httpx.post(
                graphql_url,
                json={"query": _GRAPHQL_QUERY, "variables": {"value": ioc}},
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                timeout=8.0,
                verify=config.enrichment.opencti_verify_tls,
            )

            if response.status_code != 200:
                logger.debug("OpenCTI returned HTTP %d for IOC lookup", response.status_code)
                return

            data = response.json()

            # Defensive: tolerate missing/renamed fields across OpenCTI versions
            edges = (
                data.get("data", {})
                .get("stixCyberObservables", {})
                .get("edges", [])
            )
            if not edges:
                return

            node = edges[0].get("node", {})
            if not node:
                return

            result.opencti_known = True
            result.opencti_id = node.get("id")

            # Collect labels
            label_objects = node.get("objectLabel") or []
            # objectLabel may be a list of dicts or already deserialized
            labels: list[str] = []
            for lbl in label_objects:
                val = lbl.get("value") if isinstance(lbl, dict) else None
                if val:
                    labels.append(val)
            result.opencti_labels = labels

            # Collect TLP from markings (most restrictive wins)
            marking_objects = node.get("objectMarking") or []
            definitions: list[str] = []
            for marking in marking_objects:
                defn = marking.get("definition") if isinstance(marking, dict) else None
                if defn:
                    definitions.append(defn)
            result.opencti_tlp = _most_restrictive_tlp(definitions)

            # Score from first indicator
            indicators_edges = (
                (node.get("indicators") or {})
                .get("edges", [])
            )
            if indicators_edges:
                first_indicator_node = indicators_edges[0].get("node", {})
                score = first_indicator_node.get("x_opencti_score")
                if score is not None:
                    try:
                        result.opencti_score = int(score)
                    except (ValueError, TypeError):
                        pass

        except Exception as exc:
            logger.debug("OpenCTI enrichment failed for IOC lookup: %s", exc)


# Verify protocol compliance at import time
assert isinstance(OpenCTIEnricher(), SecondaryEnricherProtocol)
