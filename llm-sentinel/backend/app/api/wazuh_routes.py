"""FastAPI routes for Wazuh SIEM integration, status queries, and event export."""

from typing import Optional
from fastapi import APIRouter, Query

from app.wazuh.exporter import get_wazuh_service
from app.wazuh.models import (
    WazuhAlertsResponse,
    WazuhExportResponse,
    WazuhStatus,
)

router = APIRouter(prefix="/wazuh", tags=["Wazuh SIEM"])


@router.get(
    "/status",
    response_model=WazuhStatus,
    summary="Get Wazuh SIEM Integration Status",
    description="Check whether a Wazuh agent is active and retrieve event forwarding stats.",
)
async def get_wazuh_status() -> WazuhStatus:
    """Retrieve Wazuh connectivity and log forwarding status."""
    service = get_wazuh_service()
    return service.get_status()


@router.get(
    "/alerts",
    response_model=WazuhAlertsResponse,
    summary="Get Wazuh Security Alerts",
    description="Retrieve security alerts correlated against custom Wazuh detection rules (100100–100110).",
)
async def get_wazuh_alerts(
    limit: int = Query(default=50, ge=1, le=200, description="Max alerts to retrieve"),
) -> WazuhAlertsResponse:
    """Retrieve security alerts mapped to Wazuh detection rules."""
    service = get_wazuh_service()
    return service.get_alerts(limit=limit)


@router.post(
    "/export-events",
    response_model=WazuhExportResponse,
    summary="Export Security Events to Wazuh JSONL",
    description="Export all security test results and MCP audit events into structured JSONL for Wazuh Agent collection.",
)
async def export_wazuh_events() -> WazuhExportResponse:
    """Export audit events to results/wazuh_events.jsonl."""
    service = get_wazuh_service()
    return service.export_events()
