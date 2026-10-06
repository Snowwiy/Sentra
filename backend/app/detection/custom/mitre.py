"""Mapeo MITRE ATT&CK de reglas personalizadas y de tags Sigma (Fase 5A).

Mismo formato que las built-in (Mitre: táctica TAxxxx, técnica Txxxx, subtécnica
Txxxx.yyy) y las mismas columnas de la detección. Un tag Sigma solo se considera MITRE si
tiene exactamente la forma de ATT&CK ("attack.t1059.001", "attack.execution"); el resto
(attack.g0016, cve.*, detection.*) se conserva como tag genérico, nunca como mapeo.
"""

import re
from dataclasses import dataclass

TACTICS: dict[str, str] = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command_and_control": "TA0011",
    "impact": "TA0040",
}
_TACTIC_ID = re.compile(r"^TA\d{4}$")
_TECHNIQUE = re.compile(r"^T\d{4}$")
_SUBTECHNIQUE = re.compile(r"^T\d{4}\.\d{3}$")
_TAG_TECHNIQUE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$")


@dataclass(frozen=True)
class MitreMapping:
    tactic: str | None
    technique: str | None
    subtechnique: str | None


def validate(
    tactic: str | None, technique: str | None, subtechnique: str | None
) -> tuple[MitreMapping | None, str | None]:
    """(mapeo normalizado, error). Todo None es "sin mapeo" y es válido."""
    tactic = (tactic or "").strip().upper() or None
    technique = (technique or "").strip().upper() or None
    subtechnique = (subtechnique or "").strip().upper() or None
    if tactic is None and technique is None and subtechnique is None:
        return None, None
    if tactic is not None and not _TACTIC_ID.match(tactic):
        return None, "MITRE tactic must look like TA0006"
    if subtechnique is not None:
        if not _SUBTECHNIQUE.match(subtechnique):
            return None, "MITRE sub-technique must look like T1059.001"
        parent = subtechnique.split(".", 1)[0]
        if technique is None:
            technique = parent
        elif technique != parent:
            return None, "the sub-technique must belong to the technique"
    if technique is None:
        return None, "a MITRE mapping needs a technique (T1110)"
    if not _TECHNIQUE.match(technique):
        return None, "MITRE technique must look like T1110"
    return MitreMapping(tactic, technique, subtechnique), None


@dataclass(frozen=True)
class SigmaTags:
    mapping: MitreMapping | None
    other: list[str]
    extra_techniques: list[str]


def from_sigma_tags(tags: list[str]) -> SigmaTags:
    tactic: str | None = None
    technique: str | None = None
    sub: str | None = None
    extra: list[str] = []
    other: list[str] = []
    for tag in tags:
        lowered = tag.strip().lower()
        match = _TAG_TECHNIQUE.match(lowered)
        if match:
            tech = f"T{match.group(1)}"
            this_sub = f"{tech}.{match.group(2)}" if match.group(2) else None
            if technique is None:
                technique, sub = tech, this_sub
            elif tech == technique and sub is None and this_sub:
                sub = this_sub
            elif (this_sub or tech) not in (technique, sub):
                extra.append(this_sub or tech)
            continue
        if lowered.startswith("attack.") and lowered[7:] in TACTICS:
            if tactic is None:
                tactic = TACTICS[lowered[7:]]
            continue
        other.append(tag)
    mapping = MitreMapping(tactic, technique, sub) if technique else None
    return SigmaTags(mapping, other, extra)
