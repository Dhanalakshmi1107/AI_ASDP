"""Dataclass schemas for all LLM-produced output types.

Each schema class:
  - Defines the exact fields expected from a particular LLM stage
  - Provides a ``from_dict(d)`` classmethod that coerces and validates
    a raw dict, replacing invalid values with safe defaults
  - Provides a ``to_dict()`` method for easy serialisation back to JSON

Usage
-----
    from backend.schemas import ServiceFinding, AttackVector

    finding = ServiceFinding.from_dict(raw_llm_output)
    safe_dict = finding.to_dict()

Design notes
------------
- Zero external dependencies — standard-library dataclasses only
- Never raises on bad LLM output; always coerces to a valid object
- All string fields are length-capped matching the limits in _normalise_* helpers
- CVE, severity, effort, confidence, verdict fields are validated against
  explicit allowlists; bad values fall back to the specified default
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_VALID_EFFORTS = {"low", "medium", "high"}
_VALID_CONFIDENCES = {"low", "medium", "high"}
_VALID_VERDICTS = {"confirmed", "rejected", "needs_manual_check", "needs_review", "pending"}


def _str(v: Any, maxlen: int = 500, default: str = "") -> str:
    s = str(v).strip() if v is not None else ""
    return s[:maxlen] if s else default


def _severity(v: Any, default: str = "MEDIUM") -> str:
    s = str(v).upper().strip() if v else ""
    return s if s in _VALID_SEVERITIES else default


def _effort(v: Any, default: str = "medium") -> str:
    s = str(v).lower().strip() if v else ""
    return s if s in _VALID_EFFORTS else default


def _confidence(v: Any, default: str = "low") -> str:
    s = str(v).lower().strip() if v else ""
    return s if s in _VALID_CONFIDENCES else default


def _verdict(v: Any, default: str = "confirmed") -> str:
    s = str(v).lower().strip() if v else ""
    return s if s in _VALID_VERDICTS else default


def _str_list(v: Any, maxlen: int = 10, item_maxlen: int = 200) -> list[str]:
    if not isinstance(v, list):
        return []
    return [_str(i, item_maxlen) for i in v[:maxlen] if i is not None]


def _int_list(v: Any, maxlen: int = 10) -> list[int]:
    result = []
    if not isinstance(v, list):
        return result
    for item in v[:maxlen]:
        try:
            result.append(int(item))
        except (TypeError, ValueError):
            pass
    return result


def _valid_cves(v: Any) -> list[str]:
    if not isinstance(v, list):
        return []
    return [str(c)[:20] for c in v[:10] if _CVE_RE.match(str(c))]


def _safe_int(v: Any, default: int = 5) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Stage 1 — per-service CVE reasoning
# ---------------------------------------------------------------------------

@dataclass
class ServiceFinding:
    service_key: str
    severity: str
    reasoning: str
    cve_ids_referenced: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict, hostname: str = "") -> "ServiceFinding":
        if not isinstance(d, dict):
            d = {}
        return cls(
            service_key=_str(d.get("service_key") or hostname, 100, hostname),
            severity=_severity(d.get("severity")),
            reasoning=_str(d.get("reasoning"), 500),
            cve_ids_referenced=_valid_cves(d.get("cve_ids_referenced", [])),
        )

    def to_dict(self) -> dict:
        return {
            "service_key": self.service_key,
            "severity": self.severity,
            "reasoning": self.reasoning,
            "cve_ids_referenced": self.cve_ids_referenced,
        }


# ---------------------------------------------------------------------------
# Stage 2 — cross-service correlation
# ---------------------------------------------------------------------------

@dataclass
class AttackChain:
    chain_title: str
    services_involved: list[str]
    combined_risk: str
    explanation: str

    @classmethod
    def from_dict(cls, d: dict) -> "AttackChain":
        if not isinstance(d, dict):
            d = {}
        return cls(
            chain_title=_str(d.get("chain_title"), 200, "Unknown chain"),
            services_involved=_str_list(d.get("services_involved", []), maxlen=10, item_maxlen=100),
            combined_risk=_severity(d.get("combined_risk")),
            explanation=_str(d.get("explanation"), 500),
        )

    def to_dict(self) -> dict:
        return {
            "chain_title": self.chain_title,
            "services_involved": self.services_involved,
            "combined_risk": self.combined_risk,
            "explanation": self.explanation,
        }


@dataclass
class CorrelationResult:
    attack_chains: list[AttackChain]
    overall_risk_level: str

    @classmethod
    def from_dict(cls, d: dict) -> "CorrelationResult":
        if not isinstance(d, dict):
            d = {}
        chains_raw = d.get("attack_chains", [])
        if not isinstance(chains_raw, list):
            chains_raw = []
        return cls(
            attack_chains=[AttackChain.from_dict(c) for c in chains_raw],
            overall_risk_level=_severity(d.get("overall_risk_level")),
        )

    def to_dict(self) -> dict:
        return {
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "overall_risk_level": self.overall_risk_level,
        }


# ---------------------------------------------------------------------------
# Stage 3 — remediation
# ---------------------------------------------------------------------------

@dataclass
class Remediation:
    finding_ref: str
    remediation_title: str
    steps: list[str]
    effort: str
    priority: int

    @classmethod
    def from_dict(cls, d: dict) -> "Remediation":
        if not isinstance(d, dict):
            d = {}
        return cls(
            finding_ref=_str(d.get("finding_ref"), 100, "unknown"),
            remediation_title=_str(d.get("remediation_title"), 200, "Remediation required"),
            steps=_str_list(d.get("steps", []), maxlen=5, item_maxlen=300),
            effort=_effort(d.get("effort")),
            priority=_safe_int(d.get("priority"), default=5),
        )

    def to_dict(self) -> dict:
        return {
            "finding_ref": self.finding_ref,
            "remediation_title": self.remediation_title,
            "steps": self.steps,
            "effort": self.effort,
            "priority": self.priority,
        }


# ---------------------------------------------------------------------------
# Stage 4 — executive synthesis
# ---------------------------------------------------------------------------

@dataclass
class Synthesis:
    executive_summary: str
    immediate_actions: list[str]
    overall_risk: str
    confidence: str

    @classmethod
    def from_dict(cls, d: dict) -> "Synthesis":
        if not isinstance(d, dict):
            d = {}
        return cls(
            executive_summary=_str(d.get("executive_summary"), 1000, "No summary available."),
            immediate_actions=_str_list(d.get("immediate_actions", []), maxlen=5, item_maxlen=200),
            overall_risk=_severity(d.get("overall_risk")),
            confidence=_confidence(d.get("confidence")),
        )

    def to_dict(self) -> dict:
        return {
            "executive_summary": self.executive_summary,
            "immediate_actions": self.immediate_actions,
            "overall_risk": self.overall_risk,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# Pentest engine — attack vectors
# ---------------------------------------------------------------------------

@dataclass
class AttackVector:
    id: str
    service_key: str
    service: str
    ports: list[int]
    attack_name: str
    description: str
    tools: list[str]
    quick_command: str
    cve_refs: list[str]
    mitre_technique: str
    severity: str
    preconditions: list[str]
    expected_evidence: str
    critic_verdict: str = "pending"
    critic_reasons: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict, hostname: str = "") -> "AttackVector":
        if not isinstance(d, dict):
            d = {}
        severity = _severity(d.get("severity"))
        from backend.pentest_engine import _sanitize_command
        command = _sanitize_command(_str(d.get("quick_command"), 500), hostname)
        return cls(
            id=_str(d.get("id"), 50, "unknown"),
            service_key=_str(d.get("service_key") or f"{hostname}:?", 100),
            service=_str(d.get("service"), 40),
            ports=_int_list(d.get("ports", [])),
            attack_name=_str(d.get("attack_name"), 100),
            description=_str(d.get("description"), 400),
            tools=_str_list(d.get("tools", []), maxlen=5, item_maxlen=50),
            quick_command=command,
            cve_refs=_valid_cves(d.get("cve_refs", [])),
            mitre_technique=_str(d.get("mitre_technique"), 20),
            severity=severity,
            preconditions=_str_list(d.get("preconditions", []), maxlen=5, item_maxlen=100),
            expected_evidence=_str(d.get("expected_evidence"), 200),
            critic_verdict=_verdict(d.get("critic_verdict", "pending")),
            critic_reasons=_str_list(d.get("critic_reasons", []), maxlen=10, item_maxlen=300),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "service_key": self.service_key,
            "service": self.service,
            "ports": self.ports,
            "attack_name": self.attack_name,
            "description": self.description,
            "tools": self.tools,
            "quick_command": self.quick_command,
            "cve_refs": self.cve_refs,
            "mitre_technique": self.mitre_technique,
            "severity": self.severity,
            "preconditions": self.preconditions,
            "expected_evidence": self.expected_evidence,
            "critic_verdict": self.critic_verdict,
            "critic_reasons": self.critic_reasons,
        }


# ---------------------------------------------------------------------------
# Critic — LLM verdict
# ---------------------------------------------------------------------------

@dataclass
class CriticVerdict:
    id: str
    verdict: str
    reasoning: str

    @classmethod
    def from_dict(cls, d: dict) -> "CriticVerdict":
        if not isinstance(d, dict):
            d = {}
        return cls(
            id=_str(d.get("id"), 50, "unknown"),
            verdict=_verdict(d.get("verdict", "confirmed")),
            reasoning=_str(d.get("reasoning"), 300),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "verdict": self.verdict,
            "reasoning": self.reasoning,
        }
