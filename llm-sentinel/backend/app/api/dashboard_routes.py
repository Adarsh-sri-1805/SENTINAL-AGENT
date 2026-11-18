"""FastAPI routes for SOC Dashboard overview, risk distribution, and unified event feeds."""

import sqlite3
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query

from app.security.mode import get_current_security_mode
from app.testing.storage import DB_PATH
from app.wazuh.models import (
    DashboardOverview,
    RecentSecurityEvent,
    RiskDistributionItem,
)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

# Known Risk Names Lookup
RISK_METADATA = {
    "LLM01": {"name": "Prompt Injection", "category": "OWASP LLM 2026"},
    "LLM02": {"name": "Sensitive Information Disclosure", "category": "OWASP LLM 2026"},
    "LLM03": {"name": "Excessive Agency", "category": "OWASP LLM 2026"},
    "LLM08": {"name": "Hidden Context Exposure", "category": "OWASP LLM 2026"},
    "LLM10": {"name": "Improper Output Handling", "category": "OWASP LLM 2026"},
    "ASI01": {"name": "Agent Goal Hijack", "category": "OWASP Agentic AI 2026"},
    "ASI02": {"name": "Tool Misuse", "category": "OWASP Agentic AI 2026"},
    "ASI03": {"name": "Identity & Privilege Abuse", "category": "OWASP Agentic AI 2026"},
    "ASI05": {"name": "Unexpected Code Execution", "category": "OWASP Agentic AI 2026"},
    "ASI06": {"name": "Memory & Context Poisoning", "category": "OWASP Agentic AI 2026"},
    "MCP-01": {"name": "Tool Description Prompt Injection", "category": "MCP Protocol Security"},
    "MCP-02": {"name": "Resource Content Prompt Injection", "category": "MCP Protocol Security"},
    "MCP-03": {"name": "Unauthorized Tool Invocation", "category": "MCP Protocol Security"},
    "MCP-04": {"name": "Tool Argument Manipulation", "category": "MCP Protocol Security"},
    "MCP-05": {"name": "Untrusted MCP Server Connection", "category": "MCP Protocol Security"},
    "MCP-06": {"name": "Tool Output Action Chaining", "category": "MCP Protocol Security"},
}


@router.get(
    "/overview",
    response_model=DashboardOverview,
    summary="Get SOC Dashboard Overview Metrics",
    description="Retrieve aggregated figures on security tests executed, blocked attacks, ASR, and mitigation effectiveness.",
)
async def get_overview() -> DashboardOverview:
    """Compute aggregated dashboard metrics from actual test execution data."""
    total_tests = 0
    blocked = 0
    partial = 0
    succeeded = 0
    total_mcp_events = 0
    mcp_improvement = 0.0

    if DB_PATH.exists():
        with sqlite3.connect(str(DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            try:
                cursor.execute(
                    """
                    SELECT result, COUNT(*) as count
                    FROM test_results
                    GROUP BY result
                    """
                )
                for row in cursor.fetchall():
                    res = row["result"]
                    cnt = row["count"]
                    if res == "BLOCKED":
                        blocked += cnt
                    elif res == "PARTIAL":
                        partial += cnt
                    elif res == "SUCCEEDED":
                        succeeded += cnt
                total_tests = blocked + partial + succeeded
            except sqlite3.OperationalError:
                pass

            # MCP events count
            try:
                cursor.execute("SELECT COUNT(*) as count FROM mcp_security_events")
                row = cursor.fetchone()
                if row:
                    total_mcp_events = row["count"]
            except sqlite3.OperationalError:
                pass

            # Latest MCP improvement
            try:
                cursor.execute(
                    """
                    SELECT overall_improvement
                    FROM mcp_comparisons
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """
                )
                row = cursor.fetchone()
                if row:
                    mcp_improvement = float(row["overall_improvement"])
            except sqlite3.OperationalError:
                pass

    asr = round(((succeeded + 0.5 * partial) / total_tests) * 100, 2) if total_tests else 0.0
    blocking_rate = round((blocked / total_tests) * 100, 2) if total_tests else 0.0
    mitigation_eff = round(((blocked + 0.5 * partial) / total_tests) * 100, 2) if total_tests else 0.0

    return DashboardOverview(
        total_tests_executed=total_tests,
        blocked=blocked,
        partial=partial,
        succeeded=succeeded,
        attack_success_rate=asr,
        blocking_rate=blocking_rate,
        mitigation_effectiveness=mitigation_eff,
        active_security_mode=get_current_security_mode(),
        total_mcp_events=total_mcp_events,
        mcp_improvement=mcp_improvement,
    )


@router.get(
    "/risk-distribution",
    response_model=List[RiskDistributionItem],
    summary="Get Risk Breakdown for Charts",
    description="Retrieve test totals, blocked counts, and ASR grouped by OWASP and MCP risk categories.",
)
async def get_risk_distribution() -> List[RiskDistributionItem]:
    """Aggregate attack metrics grouped by risk ID."""
    dist_map: Dict[str, Dict[str, int]] = {}

    # Initialize all defined risks
    for rid, meta in RISK_METADATA.items():
        dist_map[rid] = {"total": 0, "blocked": 0, "partial": 0, "succeeded": 0}

    if DB_PATH.exists():
        with sqlite3.connect(str(DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            try:
                cursor.execute(
                    """
                    SELECT risk_id, result, COUNT(*) as count
                    FROM test_results
                    GROUP BY risk_id, result
                    """
                )
                for row in cursor.fetchall():
                    rid = row["risk_id"]
                    if rid not in dist_map:
                        dist_map[rid] = {"total": 0, "blocked": 0, "partial": 0, "succeeded": 0}
                    cnt = row["count"]
                    res = row["result"]
                    dist_map[rid]["total"] += cnt
                    if res == "BLOCKED":
                        dist_map[rid]["blocked"] += cnt
                    elif res == "PARTIAL":
                        dist_map[rid]["partial"] += cnt
                    elif res == "SUCCEEDED":
                        dist_map[rid]["succeeded"] += cnt
            except sqlite3.OperationalError:
                pass

    items: List[RiskDistributionItem] = []
    for rid, stats in dist_map.items():
        meta = RISK_METADATA.get(rid, {"name": rid, "category": "Other Risks"})
        total = stats["total"]
        asr = round(((stats["succeeded"] + 0.5 * stats["partial"]) / total) * 100, 1) if total else 0.0
        items.append(
            RiskDistributionItem(
                risk_id=rid,
                risk_name=meta["name"],
                category=meta["category"],
                total=total,
                blocked=stats["blocked"],
                partial=stats["partial"],
                succeeded=stats["succeeded"],
                asr=asr,
            )
        )

    return items


@router.get(
    "/recent-events",
    response_model=List[RecentSecurityEvent],
    summary="Get Unified Security Events Feed",
    description="Retrieve chronological security events combining test runs, tool access attempts, and MCP audit logs.",
)
async def get_recent_events(limit: int = Query(default=25, ge=1, le=100)) -> List[RecentSecurityEvent]:
    """Return unified feed of recent security events."""
    events: List[RecentSecurityEvent] = []

    if DB_PATH.exists():
        with sqlite3.connect(str(DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # 1. Fetch recent test results
            try:
                cursor.execute(
                    """
                    SELECT id, test_id, risk_id, risk_name, target, mode, result, evaluation_explanation, timestamp
                    FROM test_results
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
                for row in cursor.fetchall():
                    action = "BLOCKED" if row["result"] == "BLOCKED" else ("CONTAINED" if row["result"] == "PARTIAL" else "COMPROMISED")
                    severity = "CRITICAL" if row["result"] == "SUCCEEDED" else ("MEDIUM" if row["result"] == "PARTIAL" else "LOW")
                    events.append(
                        RecentSecurityEvent(
                            event_id=f"evt-test-{row['id']}",
                            timestamp=row["timestamp"],
                            source=row["target"],
                            event_type="security_test",
                            risk_id=row["risk_id"],
                            risk_name=row["risk_name"],
                            severity=severity,
                            action_taken=action,
                            status=row["result"],
                            details=row["evaluation_explanation"] or f"Test {row['test_id']} evaluated as {row['result']}",
                        )
                    )
            except sqlite3.OperationalError:
                pass

            # 2. Fetch recent MCP events
            try:
                cursor.execute(
                    """
                    SELECT id, timestamp, event_type, server_id, tool_name, resource_uri, authorized, details
                    FROM mcp_security_events
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
                for row in cursor.fetchall():
                    action = "PERMITTED" if row["authorized"] else "DENIED_BY_POLICY"
                    status = "BLOCKED" if not row["authorized"] else "SUCCEEDED"
                    severity = "HIGH" if not row["authorized"] else "LOW"
                    target_name = row["tool_name"] or row["resource_uri"] or row["server_id"]
                    events.append(
                        RecentSecurityEvent(
                            event_id=f"evt-mcp-{row['id']}",
                            timestamp=row["timestamp"],
                            source="MCP Server",
                            event_type=row["event_type"],
                            risk_id="MCP",
                            risk_name="MCP Security",
                            severity=severity,
                            action_taken=action,
                            status=status,
                            details=f"[{target_name}] {row['details']}",
                        )
                    )
            except sqlite3.OperationalError:
                pass

    # Sort unified events descending by timestamp
    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events[:limit]
