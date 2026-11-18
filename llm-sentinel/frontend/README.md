# LLM Sentinel — Frontend

This directory is designated for the LLM Sentinel UI/Dashboard.

---

## Planned Capabilities (Future Phases)

- **Target Configuration**: Chatbot endpoint and model selection
- **Vulnerability Scanner Dashboard**: Interactive runner for OWASP Top 10 for LLM Applications and OWASP Top 10 for Agentic AI
- **Real-Time Findings & Traces**: Visual payload submission, response inspection, and token consumption
- **Remediation & Mitigation Reports**: Actionable security advisories and exportable evaluation logs

---

## Backend Connection

The frontend interacts with the backend running on `http://127.0.0.1:8000`:
- `GET /health`
- `GET /api/provider/status`
- `POST /api/chat`

