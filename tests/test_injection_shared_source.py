"""G12 guard: vex's detector must subclass the shared lib engine."""

from shipwright_kit.security.injection import (
    InjectionFinding as LibFinding,
)
from shipwright_kit.security.injection import (
    PromptInjectionDetector as LibDetector,
)

from vex.ai.injection_detector import InjectionFinding, PromptInjectionDetector


def test_finding_type_is_the_lib_type():
    assert InjectionFinding is LibFinding


def test_vex_detector_subclasses_lib_core():
    assert issubclass(PromptInjectionDetector, LibDetector)
