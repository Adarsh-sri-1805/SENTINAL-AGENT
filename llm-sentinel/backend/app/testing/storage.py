"""SQLite persistence layer for LLM Sentinel security test runs and results."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import List, Optional, TYPE_CHECKING

from app.testing.models import (
    ComparisonDetail,
    ComparisonSummary,
    Evidence,
    TestResult,
    TestResultStatus,
    TestRunSummary,
)

if TYPE_CHECKING:
    from app.mcp.models import MCPComparisonDetail, MCPSecurityEvent

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "results"
DB_PATH = RESULTS_DIR / "sentinel.db"


class StorageManager:
    """Manages SQLite persistence for security test runs."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialize database schema if not present."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS test_runs (
                    run_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    model TEXT NOT NULL,
                    total_tests INTEGER NOT NULL,
                    blocked INTEGER NOT NULL,
                    partial INTEGER NOT NULL,
                    succeeded INTEGER NOT NULL,
                    status TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS test_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    test_id TEXT NOT NULL,
                    risk_id TEXT NOT NULL,
                    risk_name TEXT NOT NULL,
                    test_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    model TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    response TEXT NOT NULL,
                    tool_evidence TEXT,
                    result TEXT NOT NULL,
                    evaluation_explanation TEXT NOT NULL,
                    evidence TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES test_runs(run_id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS comparisons (
                    comparison_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    filter_risk TEXT,
                    model TEXT NOT NULL,
                    total_tests INTEGER NOT NULL,
                    baseline_run_id TEXT NOT NULL,
                    protected_run_id TEXT NOT NULL,
                    baseline_asr REAL NOT NULL,
                    protected_asr REAL NOT NULL,
                    baseline_blocking_rate REAL NOT NULL,
                    protected_blocking_rate REAL NOT NULL,
                    overall_improvement REAL NOT NULL,
                    detail_json TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS mcp_security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    server_id TEXT NOT NULL,
                    tool_name TEXT,
                    resource_uri TEXT,
                    user_id TEXT NOT NULL,
                    user_role TEXT NOT NULL,
                    security_mode TEXT NOT NULL,
                    authorized INTEGER NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS mcp_comparisons (
                    comparison_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    total_tests INTEGER NOT NULL,
                    baseline_blocked INTEGER NOT NULL,
                    baseline_partial INTEGER NOT NULL,
                    baseline_succeeded INTEGER NOT NULL,
                    protected_blocked INTEGER NOT NULL,
                    protected_partial INTEGER NOT NULL,
                    protected_succeeded INTEGER NOT NULL,
                    baseline_asr REAL NOT NULL,
                    protected_asr REAL NOT NULL,
                    baseline_blocking_rate REAL NOT NULL,
                    protected_blocking_rate REAL NOT NULL,
                    overall_improvement REAL NOT NULL,
                    detail_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def save_run(self, summary: TestRunSummary) -> None:
        """Save full test run summary and associated test results."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO test_runs
                (run_id, timestamp, mode, model, total_tests, blocked, partial, succeeded, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    summary.run_id,
                    summary.timestamp,
                    summary.mode,
                    summary.model,
                    summary.total_tests,
                    summary.blocked,
                    summary.partial,
                    summary.succeeded,
                    "completed",
                ),
            )

            for r in summary.results:
                cursor.execute(
                    """
                    INSERT INTO test_results
                    (run_id, test_id, risk_id, risk_name, test_name, target, mode, model,
                     prompt, response, tool_evidence, result, evaluation_explanation, evidence, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        r.run_id,
                        r.test_id,
                        r.risk_id,
                        r.risk_name,
                        r.test_name,
                        r.target,
                        r.mode,
                        r.model,
                        r.prompt,
                        r.response,
                        json.dumps(r.tool_evidence),
                        r.result.value,
                        r.evaluation_explanation,
                        json.dumps(r.evidence.model_dump()),
                        r.timestamp,
                    ),
                )
            conn.commit()

    def get_runs(self, limit: int = 50) -> List[TestRunSummary]:
        """Retrieve recent test runs summary without full nested results."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT run_id, timestamp, mode, model, total_tests, blocked, partial, succeeded, status
                FROM test_runs
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            summaries = []
            for row in rows:
                summaries.append(
                    TestRunSummary(
                        run_id=row["run_id"],
                        timestamp=row["timestamp"],
                        mode=row["mode"],
                        model=row["model"],
                        total_tests=row["total_tests"],
                        blocked=row["blocked"],
                        partial=row["partial"],
                        succeeded=row["succeeded"],
                        results=[],
                    )
                )
            return summaries

    def get_run(self, run_id: str) -> Optional[TestRunSummary]:
        """Retrieve complete test run summary with all individual test results."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT run_id, timestamp, mode, model, total_tests, blocked, partial, succeeded, status
                FROM test_runs
                WHERE run_id = ?
                """,
                (run_id,),
            )
            run_row = cursor.fetchone()
            if not run_row:
                return None

            cursor.execute(
                """
                SELECT run_id, test_id, risk_id, risk_name, test_name, target, mode, model,
                       prompt, response, tool_evidence, result, evaluation_explanation, evidence, timestamp
                FROM test_results
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (run_id,),
            )
            result_rows = cursor.fetchall()

            results = []
            for r in result_rows:
                tool_ev = json.loads(r["tool_evidence"]) if r["tool_evidence"] else []
                ev_data = json.loads(r["evidence"]) if r["evidence"] else {}
                results.append(
                    TestResult(
                        test_id=r["test_id"],
                        risk_id=r["risk_id"],
                        risk_name=r["risk_name"],
                        test_name=r["test_name"],
                        target=r["target"],
                        mode=r["mode"],
                        model=r["model"],
                        prompt=r["prompt"],
                        response=r["response"],
                        tool_evidence=tool_ev,
                        result=TestResultStatus(r["result"]),
                        evaluation_explanation=r["evaluation_explanation"],
                        evidence=Evidence(**ev_data) if ev_data else Evidence(),
                        timestamp=r["timestamp"],
                        run_id=r["run_id"],
                    )
                )

            return TestRunSummary(
                run_id=run_row["run_id"],
                timestamp=run_row["timestamp"],
                mode=run_row["mode"],
                model=run_row["model"],
                total_tests=run_row["total_tests"],
                blocked=run_row["blocked"],
                partial=run_row["partial"],
                succeeded=run_row["succeeded"],
                results=results,
            )

    def get_results(
        self,
        risk_id: Optional[str] = None,
        model: Optional[str] = None,
        mode: Optional[str] = None,
        run_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[TestResult]:
        """Query individual test results with filtering by risk_id, model, mode, and run_id."""
        query = """
            SELECT run_id, test_id, risk_id, risk_name, test_name, target, mode, model,
                   prompt, response, tool_evidence, result, evaluation_explanation, evidence, timestamp
            FROM test_results
            WHERE 1=1
        """
        params = []
        if risk_id:
            query += " AND risk_id = ?"
            params.append(risk_id.upper().strip())
        if model:
            query += " AND model = ?"
            params.append(model.strip())
        if mode:
            query += " AND mode = ?"
            params.append(mode.strip())
        if run_id:
            query += " AND run_id = ?"
            params.append(run_id.strip())

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()

            results = []
            for r in rows:
                tool_ev = json.loads(r["tool_evidence"]) if r["tool_evidence"] else []
                ev_data = json.loads(r["evidence"]) if r["evidence"] else {}
                results.append(
                    TestResult(
                        test_id=r["test_id"],
                        risk_id=r["risk_id"],
                        risk_name=r["risk_name"],
                        test_name=r["test_name"],
                        target=r["target"],
                        mode=r["mode"],
                        model=r["model"],
                        prompt=r["prompt"],
                        response=r["response"],
                        tool_evidence=tool_ev,
                        result=TestResultStatus(r["result"]),
                        evaluation_explanation=r["evaluation_explanation"],
                        evidence=Evidence(**ev_data) if ev_data else Evidence(),
                        timestamp=r["timestamp"],
                        run_id=r["run_id"],
                    )
                )
            return results

    def save_comparison(self, detail: ComparisonDetail) -> None:
        """Persist a Before/After comparison evaluation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO comparisons
                (comparison_id, timestamp, filter_risk, model, total_tests,
                 baseline_run_id, protected_run_id, baseline_asr, protected_asr,
                 baseline_blocking_rate, protected_blocking_rate, overall_improvement, detail_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    detail.comparison_id,
                    detail.timestamp,
                    detail.filter_risk,
                    detail.model,
                    detail.total_tests,
                    detail.baseline_run_id,
                    detail.protected_run_id,
                    detail.baseline_asr,
                    detail.protected_asr,
                    detail.baseline_blocking_rate,
                    detail.protected_blocking_rate,
                    detail.overall_improvement,
                    detail.model_dump_json(),
                ),
            )
            conn.commit()

    def get_comparisons(self, limit: int = 50) -> List[ComparisonSummary]:
        """Retrieve recent comparison evaluations without full nested test details."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT comparison_id, timestamp, filter_risk, model, total_tests,
                       baseline_run_id, protected_run_id, baseline_asr, protected_asr,
                       baseline_blocking_rate, protected_blocking_rate, overall_improvement
                FROM comparisons
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            summaries = []
            for row in rows:
                summaries.append(
                    ComparisonSummary(
                        comparison_id=row["comparison_id"],
                        timestamp=row["timestamp"],
                        model=row["model"],
                        filter_risk=row["filter_risk"],
                        total_tests=row["total_tests"],
                        baseline_run_id=row["baseline_run_id"],
                        protected_run_id=row["protected_run_id"],
                        baseline_asr=row["baseline_asr"],
                        protected_asr=row["protected_asr"],
                        baseline_blocking_rate=row["baseline_blocking_rate"],
                        protected_blocking_rate=row["protected_blocking_rate"],
                        overall_improvement=row["overall_improvement"],
                    )
                )
            return summaries

    def get_comparison(self, comparison_id: str) -> Optional[ComparisonDetail]:
        """Retrieve full comparison evaluation with detailed test results and risk breakdown."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT detail_json FROM comparisons WHERE comparison_id = ?
                """,
                (comparison_id.strip(),),
            )
            row = cursor.fetchone()
            if not row or not row["detail_json"]:
                return None
            return ComparisonDetail.model_validate_json(row["detail_json"])

    # =========================================================================
    # MCP Security Events & Comparisons
    # =========================================================================

    def save_mcp_event(self, event: MCPSecurityEvent) -> int:
        """Persist an MCP security audit log event."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO mcp_security_events
                (timestamp, event_type, server_id, tool_name, resource_uri, user_id, user_role, security_mode, authorized, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp,
                    event.event_type,
                    event.server_id,
                    event.tool_name,
                    event.resource_uri,
                    event.user_id,
                    event.user_role,
                    event.security_mode,
                    1 if event.authorized else 0,
                    event.details,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_mcp_events(
        self,
        limit: int = 50,
        event_type: Optional[str] = None,
        server_id: Optional[str] = None,
    ) -> List["MCPSecurityEvent"]:
        """Query MCP security audit events."""
        from app.mcp.models import MCPSecurityEvent
        query = """
            SELECT id, timestamp, event_type, server_id, tool_name, resource_uri, user_id, user_role, security_mode, authorized, details
            FROM mcp_security_events
            WHERE 1=1
        """
        params = []
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.strip())
        if server_id:
            query += " AND server_id = ?"
            params.append(server_id.strip())

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            events = []
            for r in rows:
                events.append(
                    MCPSecurityEvent(
                        id=r["id"],
                        timestamp=r["timestamp"],
                        event_type=r["event_type"],
                        server_id=r["server_id"],
                        tool_name=r["tool_name"],
                        resource_uri=r["resource_uri"],
                        user_id=r["user_id"],
                        user_role=r["user_role"],
                        security_mode=r["security_mode"],
                        authorized=bool(r["authorized"]),
                        details=r["details"],
                    )
                )
            return events

    def save_mcp_comparison(self, comparison: MCPComparisonDetail) -> None:
        """Persist an MCP Before/After comparative evaluation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO mcp_comparisons
                (comparison_id, timestamp, total_tests, baseline_blocked, baseline_partial, baseline_succeeded,
                 protected_blocked, protected_partial, protected_succeeded, baseline_asr, protected_asr,
                 baseline_blocking_rate, protected_blocking_rate, overall_improvement, detail_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    comparison.comparison_id,
                    comparison.timestamp,
                    comparison.total_tests,
                    comparison.baseline_blocked,
                    comparison.baseline_partial,
                    comparison.baseline_succeeded,
                    comparison.protected_blocked,
                    comparison.protected_partial,
                    comparison.protected_succeeded,
                    comparison.baseline_asr,
                    comparison.protected_asr,
                    comparison.baseline_blocking_rate,
                    comparison.protected_blocking_rate,
                    comparison.overall_improvement,
                    comparison.model_dump_json(),
                ),
            )
            conn.commit()

    def get_mcp_comparisons(self, limit: int = 50) -> List["MCPComparisonDetail"]:
        """Retrieve recent MCP comparative evaluations."""
        from app.mcp.models import MCPComparisonDetail
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT detail_json FROM mcp_comparisons
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                if r["detail_json"]:
                    results.append(MCPComparisonDetail.model_validate_json(r["detail_json"]))
            return results

    def get_mcp_comparison(self, comparison_id: str) -> Optional["MCPComparisonDetail"]:
        """Retrieve a specific MCP comparative evaluation by ID."""
        from app.mcp.models import MCPComparisonDetail
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT detail_json FROM mcp_comparisons WHERE comparison_id = ?
                """,
                (comparison_id.strip(),),
            )
            row = cursor.fetchone()
            if not row or not row["detail_json"]:
                return None
            return MCPComparisonDetail.model_validate_json(row["detail_json"])


_global_storage = StorageManager()


def get_storage_manager() -> StorageManager:
    """Return default storage manager instance."""
    return _global_storage

