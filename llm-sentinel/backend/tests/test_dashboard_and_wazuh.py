"""Unit and integration tests for SOC Dashboard endpoints and Wazuh SIEM integration."""

from fastapi.testclient import TestClient

from app.main import app
from app.wazuh.exporter import get_wazuh_service


def test_dashboard_overview():
    """Test GET /api/dashboard/overview returns real aggregated metrics."""
    client = TestClient(app)
    resp = client.get("/api/dashboard/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_tests_executed" in data
    assert "blocked" in data
    assert "partial" in data
    assert "succeeded" in data
    assert "attack_success_rate" in data
    assert "blocking_rate" in data
    assert "mitigation_effectiveness" in data
    assert "active_security_mode" in data
    assert isinstance(data["attack_success_rate"], float)


def test_dashboard_risk_distribution():
    """Test GET /api/dashboard/risk-distribution returns categorized risk statistics."""
    client = TestClient(app)
    resp = client.get("/api/dashboard/risk-distribution")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 10
    risk_ids = [item["risk_id"] for item in items]
    assert "LLM01" in risk_ids
    assert "ASI01" in risk_ids
    assert "MCP-01" in risk_ids
    assert all("risk_name" in item and "category" in item for item in items)


def test_dashboard_recent_events():
    """Test GET /api/dashboard/recent-events returns unified chronological event feed."""
    client = TestClient(app)
    resp = client.get("/api/dashboard/recent-events?limit=10")
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)
    if events:
        first = events[0]
        assert "event_id" in first
        assert "timestamp" in first
        assert "source" in first
        assert "action_taken" in first
        assert "status" in first


def test_wazuh_status_disconnected():
    """Verify Wazuh accurately reports NOT CONNECTED when no live manager/agent is installed."""
    client = TestClient(app)
    resp = client.get("/api/wazuh/status")
    assert resp.status_code == 200
    status_data = resp.json()
    assert status_data["connected"] is False
    assert status_data["status_text"] == "NOT CONNECTED"
    assert "wazuh_events.jsonl" in status_data["log_file_path"]


def test_wazuh_export_events():
    """Test POST /api/wazuh/export-events exports structured events to JSONL."""
    client = TestClient(app)
    resp = client.post("/api/wazuh/export-events")
    assert resp.status_code == 200
    export_data = resp.json()
    assert export_data["success"] is True
    assert "file_path" in export_data
    assert "wazuh_events.jsonl" in export_data["file_path"]
    assert export_data["events_exported"] >= 0


def test_wazuh_alerts():
    """Test GET /api/wazuh/alerts returns correlated security alerts."""
    client = TestClient(app)
    resp = client.get("/api/wazuh/alerts?limit=15")
    assert resp.status_code == 200
    alerts_data = resp.json()
    assert alerts_data["connected"] is False
    assert "NOT CONNECTED" in alerts_data["message"]
    assert isinstance(alerts_data["alerts"], list)
