"""Attack surface Markdown exporter — zero LLM calls, pure Python.

Converts a completed scan result (with pentest_plan and rag_analysis attached)
into a structured, human-readable `attacksurface.md` document suitable for
sharing with a penetration testing team.

Usage
-----
    from backend.export_md import build_attacksurface_md

    markdown = build_attacksurface_md(scan_result)
    with open("attacksurface.md", "w") as f:
        f.write(markdown)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_badge(severity: str) -> str:
    """Return a simple text badge for a severity level."""
    badges = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH":     "🟠 HIGH",
        "MEDIUM":   "🟡 MEDIUM",
        "LOW":      "🟢 LOW",
    }
    return badges.get(str(severity).upper(), f"⚪ {severity}")


def _safe(value: Any, fallback: str = "N/A") -> str:
    """Return a string representation of a value, or a fallback if empty."""
    s = str(value).strip() if value is not None else ""
    return s if s else fallback


def _list_lines(items: list, prefix: str = "- ") -> str:
    """Render a list as Markdown bullet points."""
    if not items:
        return "_None_\n"
    return "\n".join(f"{prefix}{_safe(i)}" for i in items) + "\n"


def _table_row(*cells: str) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_header(result: dict) -> str:
    target = _safe(result.get("target"), "Unknown Target")
    timestamp = result.get("scan_timestamp", "")
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        ts_str = dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        ts_str = timestamp or "Unknown"

    risk = result.get("risk_score")
    # risk_score is a 0-100 scale (see reasoning_chain.compute_risk_score)
    risk_str = f"{risk:.1f}/100" if isinstance(risk, (int, float)) else "N/A"
    mode = _safe(result.get("mode"), "standard")

    lines = [
        f"# Attack Surface Report — {target}",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Target** | `{target}` |",
        f"| **Scan date** | {ts_str} |",
        f"| **Scan mode** | {mode} |",
        f"| **Risk score** | {risk_str} |",
        f"| **Scan ID** | `{_safe(result.get('scan_id'), 'N/A')}` |",
        "",
        "> **⚠ Authorisation required.** This report is for authorised penetration testing only.",
        "> Run all techniques against your own systems or with written permission.",
        "",
    ]
    return "\n".join(lines)


def _section_ai_summary(result: dict) -> str:
    ai = result.get("ai_analysis") or {}
    summary = _safe(ai.get("summary"), "_No AI summary available._")

    lines = [
        "## Executive Summary",
        "",
        summary,
        "",
    ]

    risks = ai.get("risks") or []
    risk_lines = []
    for r in risks:
        if isinstance(r, dict):
            title = str(r.get("title", "")).strip()
            level = str(r.get("level", "")).strip().upper()
            details = str(r.get("details", "")).strip()
            # Skip empty placeholder entries — upstream occasionally emits {level: HIGH, title: "", details: ""}
            if not title and not details:
                continue
            badge = _severity_badge(level) if level else ""
            head = (badge + " " if badge else "") + (f"**{title}**" if title else "")
            body = f" — {details}" if details else ""
            risk_lines.append(f"- {head}{body}".strip())
        else:
            s = str(r).strip()
            if s:
                risk_lines.append(f"- {s}")
    if risk_lines:
        lines += ["**Key Risks Identified:**", ""]
        lines += risk_lines
        lines.append("")

    recs = ai.get("recommendations") or []
    rec_lines = []
    for r in recs:
        if isinstance(r, dict):
            title = str(
                r.get("recommendation") or r.get("title") or r.get("action") or ""
            ).strip()
            detail = str(
                r.get("description") or r.get("details") or r.get("detail") or ""
            ).strip()
            if not title and not detail:
                continue
            if title and detail:
                rec_lines.append(f"- **{title}** — {detail}")
            else:
                rec_lines.append(f"- {title or detail}")
        else:
            s = str(r).strip()
            if s:
                rec_lines.append(f"- {s}")
    if rec_lines:
        lines += ["**Top Recommendations:**", ""]
        lines += rec_lines
        lines.append("")

    return "\n".join(lines)


def _section_discovered_hosts(result: dict) -> str:
    hosts = result.get("hosts") or []
    lines = [
        "## Discovered Hosts & Services",
        "",
    ]

    if not hosts:
        lines += ["_No hosts discovered._", ""]
        return "\n".join(lines)

    for host in hosts:
        hostname = _safe(host.get("hostname"), "Unknown")
        lines += [f"### {hostname}", ""]

        services = host.get("services") or []
        if not services:
            lines += ["_No open services detected._", ""]
            continue

        lines += [
            _table_row("Port", "Service", "Product", "Version", "CVEs"),
            _table_row("----", "-------", "-------", "-------", "----"),
        ]
        for svc in services:
            port = _safe(svc.get("port"))
            name = _safe(svc.get("service_name"))
            product = _safe(svc.get("product"))
            version = _safe(svc.get("version"))
            cves = svc.get("cve_matches") or []
            cve_list = ", ".join(c.get("cve_id", "") for c in cves[:3]) or "None"
            if len(cves) > 3:
                cve_list += f" +{len(cves) - 3} more"
            lines.append(_table_row(f"`{port}`", name, product, version, cve_list))
        lines.append("")

    return "\n".join(lines)


def _section_attack_vectors(result: dict) -> str:
    plan = result.get("pentest_plan") or {}
    vectors = plan.get("attack_vectors") or []
    critic_summary = plan.get("critic_summary") or {}

    lines = [
        "## Attack Vectors",
        "",
    ]

    if critic_summary:
        total = critic_summary.get("total", 0)
        confirmed = critic_summary.get("confirmed", 0)
        rejected = critic_summary.get("rejected", 0)
        manual = critic_summary.get("needs_manual_check", 0)
        lines += [
            f"**Critic summary:** {total} total — "
            f"{confirmed} confirmed, {rejected} rejected, {manual} need manual review",
            "",
        ]

    if not vectors:
        lines += ["_No confirmed attack vectors identified._", ""]
        return "\n".join(lines)

    for av in vectors:
        attack_name = _safe(av.get("attack_name"), "Unnamed Attack")
        severity = _safe(av.get("severity"), "MEDIUM")
        service_key = _safe(av.get("service_key"))
        mitre = _safe(av.get("mitre_technique"))
        description = _safe(av.get("description"))
        tools = av.get("tools") or []
        command = _safe(av.get("quick_command"))
        cve_refs = av.get("cve_refs") or []
        preconditions = av.get("preconditions") or []
        expected = _safe(av.get("expected_evidence"))
        critic_verdict = _safe(av.get("critic_verdict"), "confirmed")
        critic_reasons = av.get("critic_reasons") or []

        lines += [
            f"### {_severity_badge(severity)} — {attack_name}",
            "",
            f"**Target:** `{service_key}`  ",
            f"**MITRE ATT&CK:** `{mitre}`  ",
            f"**Critic verdict:** {critic_verdict}",
            "",
            f"**Description:** {description}",
            "",
        ]

        if preconditions:
            lines += ["**Preconditions:**", ""]
            lines += [f"- {_safe(p)}" for p in preconditions]
            lines.append("")

        if tools:
            lines += [f"**Tools:** {', '.join(_safe(t) for t in tools)}", ""]

        if command and command != "N/A":
            lines += [
                "**Quick command:**",
                "```bash",
                command,
                "```",
                "",
            ]

        if cve_refs:
            lines += [f"**CVE references:** {', '.join(_safe(c) for c in cve_refs)}", ""]

        if expected and expected != "N/A":
            lines += [f"**Expected evidence:** {expected}", ""]

        if critic_reasons:
            lines += ["**Critic notes:**", ""]
            lines += [f"- {_safe(r)}" for r in critic_reasons]
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def _section_excluded(result: dict) -> str:
    plan = result.get("pentest_plan") or {}
    excluded = plan.get("excluded") or []

    if not excluded:
        return ""

    lines = [
        "## Excluded by Critic",
        "",
        "_These attack vectors were proposed but rejected by the critic agent._",
        "",
        _table_row("Attack", "Target", "Rejected by", "Reason"),
        _table_row("------", "------", "-----------", "------"),
    ]

    for ex in excluded:
        attack = _safe(ex.get("attack_name"))
        target = _safe(ex.get("service_key"))
        rejected_by = _safe(ex.get("rejected_by"))
        reasons = ex.get("reasons") or []
        reason_str = "; ".join(_safe(r) for r in reasons[:2])
        lines.append(_table_row(attack, f"`{target}`", rejected_by, reason_str))

    lines.append("")
    return "\n".join(lines)


def _section_rag_findings(result: dict) -> str:
    """Render the 4-stage reasoning-chain output.

    The reasoning chain (backend/reasoning_chain.py) emits keys
    ``stage1_service_assessments``, ``stage2_correlation``, ``stage3_remediations``,
    ``stage4_synthesis`` — older code looked for ``service_findings``/
    ``correlations``/``remediations`` which never existed and produced an
    empty section. This reader handles both the canonical stage keys and
    the legacy aliases for backward compatibility.
    """
    rag = result.get("rag_analysis") or {}

    # Stage 1 — per-service CVE assessments
    service_findings = (
        rag.get("stage1_service_assessments")
        or rag.get("service_findings")
        or []
    )

    # Stage 2 — cross-service correlation (attack chains)
    stage2 = rag.get("stage2_correlation") or {}
    if isinstance(stage2, dict):
        correlations = stage2.get("attack_chains") or rag.get("correlations") or []
    else:
        correlations = rag.get("correlations") or []

    # Stage 3 — remediations
    remediations = (
        rag.get("stage3_remediations")
        or rag.get("remediations")
        or []
    )

    # If everything is empty, suppress the section entirely
    if not service_findings and not correlations and not remediations:
        return ""

    lines = ["## RAG Reasoning Chain Findings", ""]

    # ----- Stage 1: per-service findings -----
    if service_findings:
        lines += ["### Per-Service CVE Analysis", ""]
        # Sort by severity descending for readability
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        for sf in sorted(
            service_findings,
            key=lambda x: order.get(str(x.get("severity", "UNKNOWN")).upper(), 0),
            reverse=True,
        ):
            severity = _safe(sf.get("severity"), "MEDIUM")
            service_key = _safe(sf.get("service_key"))
            reasoning = _safe(
                sf.get("reasoning") or sf.get("summary"),
                "_No reasoning recorded._",
            )
            cves = sf.get("cve_ids_referenced") or sf.get("cve_ids") or []
            cve_str = ", ".join(_safe(c) for c in cves[:5]) or "None"

            lines += [
                f"**{_severity_badge(severity)} `{service_key}`**",
                "",
                reasoning,
                "",
                f"CVEs referenced: {cve_str}",
                "",
            ]

    # ----- Stage 2: attack chains / correlations -----
    if correlations:
        lines += ["### Cross-Service Correlations", ""]
        for corr in correlations:
            title = _safe(
                corr.get("chain_title") or corr.get("title"),
                "Untitled chain",
            )
            detail = _safe(corr.get("explanation") or corr.get("detail"))
            severity = _safe(
                corr.get("combined_risk") or corr.get("severity"),
                "MEDIUM",
            )
            services_involved = corr.get("services_involved") or []
            line = f"- {_severity_badge(severity)} **{title}**"
            if detail:
                line += f" — {detail}"
            lines.append(line)
            if services_involved:
                lines.append(
                    "  - Services: " + ", ".join(f"`{_safe(s)}`" for s in services_involved[:5])
                )
        lines.append("")

    # ----- Stage 3: remediations -----
    if remediations:
        lines += ["### Recommended Remediations", ""]
        # Sort by priority ascending (1 = highest)
        def _prio(r):
            try:
                return int(r.get("priority", 5))
            except (TypeError, ValueError):
                return 5

        for rem in sorted(remediations, key=_prio):
            title = _safe(
                rem.get("remediation_title") or rem.get("title"),
                "Untitled remediation",
            )
            effort = _safe(rem.get("effort"), "medium")
            steps = rem.get("steps") or []
            detail = _safe(rem.get("detail"))
            finding_ref = _safe(rem.get("finding_ref"))

            lines.append(f"- **{title}** _(effort: {effort})_")
            if finding_ref and finding_ref != "N/A":
                lines.append(f"  - Finding: `{finding_ref}`")
            if detail and detail != "N/A":
                lines.append(f"  - {detail}")
            for step in steps[:3]:
                step_text = _safe(step)
                if step_text and step_text != "N/A":
                    lines.append(f"  - {step_text}")
        lines.append("")

    return "\n".join(lines)


def _section_tech_stack(result: dict) -> str:
    """Render the discovered tech stack grouped by category.

    Surfacing this in the report saves the pentest team a trip back to the
    dashboard. Categories with no entries are skipped.
    """
    hosts = result.get("hosts") or []

    # Aggregate across all hosts
    by_category: dict[str, list[str]] = {}
    server_lines: list[str] = []
    for host in hosts:
        web_stack = host.get("web_stack") or {}
        server = web_stack.get("server") or {}
        if server.get("name"):
            label = server["name"]
            if server.get("version"):
                label += f" {server['version']}"
            if label not in server_lines:
                server_lines.append(label)
        for tech in web_stack.get("technologies") or []:
            name = (tech.get("name") or "").strip()
            if not name:
                continue
            version = (tech.get("version") or "").strip()
            category = (tech.get("category") or "technology").strip().lower()
            label = f"{name} {version}".strip()
            by_category.setdefault(category, [])
            if label not in by_category[category]:
                by_category[category].append(label)

    if not server_lines and not by_category:
        return ""

    lines = ["## Web Tech Stack", ""]

    if server_lines:
        lines += ["**Server:** " + ", ".join(f"`{s}`" for s in server_lines), ""]

    # Render in a stable, useful order
    category_order = ["cms", "framework", "language", "library", "technology"]
    pretty = {
        "cms": "CMS",
        "framework": "Frameworks",
        "language": "Languages",
        "library": "Libraries",
        "technology": "Other Technologies",
    }
    for cat in category_order:
        items = by_category.get(cat) or []
        if not items:
            continue
        lines.append(f"**{pretty.get(cat, cat.title())}:**")
        for item in sorted(items):
            lines.append(f"- {item}")
        lines.append("")

    # Catch-all for any unknown category
    for cat, items in sorted(by_category.items()):
        if cat in category_order or not items:
            continue
        lines.append(f"**{cat.title()}:**")
        for item in sorted(items):
            lines.append(f"- {item}")
        lines.append("")

    return "\n".join(lines)


def _section_subdomains(result: dict) -> str:
    hosts = result.get("hosts") or []
    all_subdomains = []
    for host in hosts:
        subs = host.get("subdomains") or []
        all_subdomains.extend(subs)

    if not all_subdomains:
        return ""

    lines = [
        "## Discovered Subdomains",
        "",
        _list_lines([f"`{s}`" for s in sorted(set(all_subdomains))]),
    ]
    return "\n".join(lines)


def _section_footer() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"\n---\n\n"
        f"_Generated by AI_ASDP on {now}. "
        f"All findings must be validated before exploitation. "
        f"Obtain written authorisation before running any attack techniques._\n"
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_attacksurface_md(scan_result: dict) -> str:
    """Generate a full Markdown attack surface report from a completed scan result.

    Zero LLM calls — purely formats data already in the scan result dict.

    Args:
        scan_result: The dict returned by perform_scan() (with pentest_plan
                     and rag_analysis attached).

    Returns:
        A Markdown string ready to write to attacksurface.md.
    """
    sections = [
        _section_header(scan_result),
        _section_ai_summary(scan_result),
        _section_discovered_hosts(scan_result),
        _section_tech_stack(scan_result),
        _section_attack_vectors(scan_result),
        _section_excluded(scan_result),
        _section_rag_findings(scan_result),
        _section_subdomains(scan_result),
        _section_footer(),
    ]
    return "\n".join(s for s in sections if s)
