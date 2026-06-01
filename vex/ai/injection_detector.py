"""Prompt injection detection for attacker-influenced strings in vex prompts.

Detects and optionally redacts suspicious patterns in IOC enrichment data
(sandbox behaviors, malware-family labels, tags, categories, file names, etc.)
before that data is inserted into LLM prompts, to mitigate prompt injection.

This module adapts sift's PromptInjectionDetector patterns verbatim — the
same 5 compiled patterns and NFKC normalisation — but operates on plain
strings rather than Alert objects, because vex feeds individual field values
into prompts.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SeverityLevel(str, Enum):
    """Severity of injection finding."""

    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class InjectionFinding(BaseModel):
    """A detected injection pattern in a prompt field value."""

    field: str = Field(..., description="Field name where pattern was found")
    pattern_type: str = Field(
        ..., description="Type of injection pattern (e.g., 'instruction_override')"
    )
    severity: SeverityLevel = Field(..., description="Severity level of the finding")
    redaction: str = Field(..., description="Redaction marker for the suspicious content")
    value_preview: Optional[str] = Field(
        None, description="Preview of suspicious value (truncated)"
    )


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class PromptInjectionDetector:
    """Detects prompt injection patterns in plain string values destined for LLM prompts.

    Adapts sift's PromptInjectionDetector to work on individual string values
    (malware-family labels, tags, sandbox process/mutex/DNS names, file names,
    etc.) rather than structured Alert objects.
    """

    def __init__(
        self,
        case_insensitive: bool = True,
        whitelist_patterns: list[str] | None = None,
    ):
        """Initialise detector with injection patterns.

        Args:
            case_insensitive: If True, perform case-insensitive matching.
            whitelist_patterns: Optional list of regex patterns.  Any field
                value matching one of these patterns is exempted from all
                injection checks (e.g. known-safe label templates).
        """
        self.case_insensitive = case_insensitive
        flags = re.IGNORECASE if case_insensitive else 0
        self._whitelist: list[re.Pattern] = [
            re.compile(p, flags) for p in (whitelist_patterns or [])
        ]
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for injection detection.

        Patterns are identical to sift's PromptInjectionDetector — do not
        adjust thresholds here without reflecting the change upstream.
        """
        flags = re.IGNORECASE if self.case_insensitive else 0

        # Pattern 1: "ignore previous instructions" variants.
        # re.DOTALL so . matches \n; NFKC normalisation applied before matching
        # to defeat zero-width space and Unicode lookalike bypasses.
        self.pattern_ignore_instructions = re.compile(
            r"(ignore|disregard|forget|dismiss|bypass|override)[\s\S]{0,40}?"
            r"(previous|prior|earlier|above|preceding)[\s\S]{0,40}?"
            r"(instruction|directive|prompt|command|context|system)",
            flags | re.DOTALL,
        )

        # Pattern 2: LLM-redirection via "instead" keyword (narrowed vs. original).
        # Matches "verb instead" OR "instead verb" to catch injection while
        # avoiding FP on normal log lines like "Generate report: failed".
        # Optional punctuation (,;.) after "instead" handles "Instead, output ..."
        self.pattern_instead_output = re.compile(
            r"(?:"
            r"(output|respond|return|generate|create|print|write)\s+instead"
            r"|instead[\s,;.]+(?:of\s+)?(output|respond|return|generate|create|print|write)"
            r"|rather\s+than\s+(?:summariz|analyz|triag|the\s+above)"
            r")",
            flags,
        )

        # Pattern 3: JSON escape sequences (escaped quotes, control chars).
        self.pattern_json_escapes = re.compile(
            r'\\(?:["\\/bfnrtu]|u[0-9a-fA-F]{4})',
            flags,
        )

        # Pattern 4: Base64 or hex encoded payloads.
        # Branch 1: 12+ base64 chars that contain at least one '+' or '/' — lookahead
        #   rules out plain English words (e.g. "Exfiltration", "Configuration")
        #   which are purely alphanumeric and never contain Base64 special chars.
        # Branch 2/3: padded Base64 (== or =) — padding chars cannot appear in
        #   normal prose, so any length is suspicious.
        # Branch 4: 15+ purely-alphanumeric chars — raised from 12 so that common
        #   security terms ("Exfiltration"=12, "Configuration"=13) are excluded
        #   while long random-looking Base64 without special chars is still caught.
        # Branch 5: hex-encoded bytes — 10+ two-hex-digit pairs (20+ hex chars).
        self.pattern_base64_hex = re.compile(
            r'(?:'
            r'(?=[A-Za-z0-9+/]*[+/])[A-Za-z0-9+/]{12,}'  # Branch 1: 12+ with +/
            r'|[A-Za-z0-9+/]{4,}=='                        # Branch 2: == padded
            r'|[A-Za-z0-9+/]{8,}='                         # Branch 3: = padded
            r'|(?:[0-9a-fA-F]{2}){10,}'                     # Branch 5: hex pairs
            r'|[A-Za-z0-9]{20,}'                            # Branch 4: 20+ alphanumeric
            r')',
            flags,
        )

        # Pattern 5: Shell command injection ($(...), backticks, $var).
        self.pattern_shell_commands = re.compile(
            r'(?:\$\([^)]*\)|`[^`]*`|\$\w+)',
            flags,
        )

    def detect(
        self,
        value: str,
        field_name: str = "",
        *,
        is_ioc_field: bool = False,
    ) -> list[InjectionFinding]:
        """Scan a single string value for injection patterns.

        Args:
            value: The string to scan (e.g. a malware-family label, tag,
                sandbox process name, file name, etc.).
            field_name: Logical name of the field this value came from — used
                in InjectionFinding.field for diagnostics.
            is_ioc_field: When True, skip the encoded_payload check.  IOC
                values (hashes, IP addresses, domains) legitimately look like
                base64 or long hex strings; checking them produces false
                positives.  This mirrors sift's ioc.* exemption.

        Returns:
            List of InjectionFinding objects, one per detected pattern.
            Empty list means the value is clean.
        """
        if not isinstance(value, str):
            return []

        findings: list[InjectionFinding] = []

        # NFKC normalisation defeats Unicode lookalike / zero-width bypasses.
        normalized = unicodedata.normalize("NFKC", value)

        # Skip values that match an operator-defined whitelist pattern.
        if self._whitelist and any(p.search(normalized) for p in self._whitelist):
            return []

        # Use if (not elif) to detect all patterns in the same value.
        if self.pattern_ignore_instructions.search(normalized):
            findings.append(
                InjectionFinding(
                    field=field_name,
                    pattern_type="instruction_override",
                    severity=SeverityLevel.CRITICAL,
                    redaction="[REDACTED: instruction override attempt]",
                    value_preview=self._truncate(value),
                )
            )

        if self.pattern_instead_output.search(normalized):
            findings.append(
                InjectionFinding(
                    field=field_name,
                    pattern_type="output_manipulation",
                    severity=SeverityLevel.CRITICAL,
                    redaction="[REDACTED: output manipulation attempt]",
                    value_preview=self._truncate(value),
                )
            )

        if self.pattern_json_escapes.search(normalized):
            findings.append(
                InjectionFinding(
                    field=field_name,
                    pattern_type="json_escape_sequence",
                    severity=SeverityLevel.WARNING,
                    redaction="[REDACTED: JSON escape sequences]",
                    value_preview=self._truncate(value),
                )
            )

        # IOC fields legitimately contain hashes, base64 digests, etc.;
        # skip encoded-payload check to avoid false positives.
        if not is_ioc_field and self.pattern_base64_hex.search(normalized):
            findings.append(
                InjectionFinding(
                    field=field_name,
                    pattern_type="encoded_payload",
                    severity=SeverityLevel.WARNING,
                    redaction="[REDACTED: encoded payload]",
                    value_preview=self._truncate(value),
                )
            )

        if self.pattern_shell_commands.search(normalized):
            findings.append(
                InjectionFinding(
                    field=field_name,
                    pattern_type="shell_injection",
                    severity=SeverityLevel.CRITICAL,
                    redaction="[REDACTED: shell command attempt]",
                    value_preview=self._truncate(value),
                )
            )

        return findings

    def sanitize(
        self,
        value: str,
        field_name: str = "",
        *,
        is_ioc_field: bool = False,
    ) -> str:
        """Return value or a redaction marker if any CRITICAL finding is detected.

        CRITICAL findings (instruction_override, output_manipulation,
        shell_injection) trigger redaction.  WARNING findings
        (json_escape_sequence, encoded_payload) are logged but the original
        value is returned — keeping the behaviour simple and matching sift's
        philosophy of not over-redacting encoded content that might be benign.

        Args:
            value: The string to sanitize.
            field_name: Logical field name for logging context.
            is_ioc_field: Forwarded to detect(); skips encoded_payload check.

        Returns:
            The original value if clean (or only WARNING findings);
            a ``[REDACTED: <pattern_type>]`` marker string if any CRITICAL
            finding is present.
        """
        findings = self.detect(value, field_name=field_name, is_ioc_field=is_ioc_field)
        if not findings:
            return value

        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        warnings = [f for f in findings if f.severity == SeverityLevel.WARNING]

        for w in warnings:
            logger.warning(
                "Prompt injection WARNING in field %r: pattern=%s preview=%r",
                field_name or "<unknown>",
                w.pattern_type,
                w.value_preview,
            )

        if critical:
            # Use the redaction marker from the first CRITICAL finding.
            marker = critical[0].redaction
            logger.warning(
                "Prompt injection CRITICAL in field %r: pattern=%s — redacting. preview=%r",
                field_name or "<unknown>",
                critical[0].pattern_type,
                critical[0].value_preview,
            )
            return marker

        return value

    @staticmethod
    def _truncate(value: str, max_len: int = 80) -> str:
        """Truncate string for preview display.

        Args:
            value: String to truncate.
            max_len: Maximum length of preview.

        Returns:
            Truncated string with ellipsis if needed.
        """
        if len(value) <= max_len:
            return value
        return value[:max_len] + "..."


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def scan(value: str) -> list[InjectionFinding]:
    """Scan a single string value for injection patterns.

    Args:
        value: The string to scan.

    Returns:
        List of injection findings.
    """
    detector = PromptInjectionDetector()
    return detector.detect(value)
