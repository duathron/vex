"""Prompt-injection detection for attacker-influenced strings in vex prompts.

Pattern set + detect engine come from shipwright_kit.security.injection (shared
with sift). vex adds string-level sanitize() for prompt insertion.
"""

from __future__ import annotations

import logging

from shipwright_kit.security.injection import (
    InjectionFinding,
    SeverityLevel,
    scan,  # re-exported for callers importing scan from here
)
from shipwright_kit.security.injection import (
    PromptInjectionDetector as _CoreDetector,
)

__all__ = [
    "InjectionFinding",
    "PromptInjectionDetector",
    "SeverityLevel",
    "scan",
]

logger = logging.getLogger(__name__)


class PromptInjectionDetector(_CoreDetector):
    """Shared detector + vex's prompt-insertion sanitize()."""

    def sanitize(
        self,
        value: str,
        field_name: str = "",
        *,
        is_ioc_field: bool = False,
    ) -> str:
        findings = self.detect(value, field_name=field_name, is_ioc_field=is_ioc_field)
        if not findings:
            return value

        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        warnings = [f for f in findings if f.severity == SeverityLevel.WARNING]

        for w in warnings:
            logger.warning(
                "Prompt injection WARNING in field %r: pattern=%s preview=%r",
                field_name or "<unknown>", w.pattern_type, w.value_preview,
            )
        if critical:
            logger.warning(
                "Prompt injection CRITICAL in field %r: pattern=%s — redacting. preview=%r",
                field_name or "<unknown>", critical[0].pattern_type, critical[0].value_preview,
            )
            return critical[0].redaction
        return value
