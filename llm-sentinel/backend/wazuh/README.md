# Wazuh SIEM Integration for LLM Sentinel

This directory contains integration configuration, decoders, and custom detection rules for ingesting LLM Sentinel AI security events into **Wazuh SIEM**.

---

## Architecture

```
LLM Sentinel (FastAPI) 
      ↓ (Auto-Redacted Security Events)
results/wazuh_events.jsonl 
      ↓ (Localfile log collection)
Wazuh Agent 
      ↓ (Encrypted connection: Port 1514)
Wazuh Manager (Decoders & Rules 100100–100110)
      ↓
Wazuh Indexer & Dashboard (SOC Visualizations)
```

---

## 1. Configure Wazuh Agent

Add the `<localfile>` block from [wazuh_agent_localfile.xml](file:///c:/Users/adars/OneDrive/Desktop/ai%20security/llm-sentinel/backend/wazuh/wazuh_agent_localfile.xml) to your Wazuh Agent configuration file:

- **Windows Agent**: `C:\Program Files (x86)\ossec-agent\ossec.conf`
- **Linux Agent**: `/var/ossec/etc/ossec.conf`

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>C:\Users\adars\OneDrive\Desktop\ai security\llm-sentinel\backend\results\wazuh_events.jsonl</location>
  </localfile>
</ossec_config>
```

Restart the agent:
```powershell
# Windows
Restart-Service Wazuh
```
```bash
# Linux
systemctl restart wazuh-agent
```

---

## 2. Deploy Custom Decoders (Wazuh Manager)

Copy [decoders/llm_sentinel_decoders.xml](file:///c:/Users/adars/OneDrive/Desktop/ai%20security/llm-sentinel/backend/wazuh/decoders/llm_sentinel_decoders.xml) to the Wazuh Manager:

```bash
cp llm_sentinel_decoders.xml /var/ossec/etc/decoders/
chown wazuh:wazuh /var/ossec/etc/decoders/llm_sentinel_decoders.xml
chmod 660 /var/ossec/etc/decoders/llm_sentinel_decoders.xml
```

---

## 3. Deploy Custom Detection Rules (Wazuh Manager)

Copy [rules/llm_sentinel_rules.xml](file:///c:/Users/adars/OneDrive/Desktop/ai%20security/llm-sentinel/backend/wazuh/rules/llm_sentinel_rules.xml) to the Wazuh Manager:

```bash
cp llm_sentinel_rules.xml /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/rules/llm_sentinel_rules.xml
chmod 660 /var/ossec/etc/rules/llm_sentinel_rules.xml
```

Test configuration syntax on the manager:
```bash
/var/ossec/bin/wazuh-logtest
```

Restart Wazuh Manager:
```bash
systemctl restart wazuh-manager
```

---

## 4. Rule ID Reference Matrix

| Rule ID | Severity Level | Risk Category | Matching Condition |
| :--- | :--- | :--- | :--- |
| **100099** | Level 3 | Base Event | `source: LLM Sentinel` |
| **100100** | Level 12 (Critical) | OWASP LLM01 | Prompt Injection Attempt |
| **100101** | Level 11 (High) | OWASP LLM02 | Sensitive Information Disclosure Attempt |
| **100102** | Level 10 (High) | OWASP LLM03 | Excessive Agency / Unauthorized Tool Action |
| **100103** | Level 8 (Medium) | OWASP LLM08 | Hidden Context / System Prompt Extraction |
| **100104** | Level 9 (High) | OWASP LLM10 | Improper Output Handling / Code Injection |
| **100105** | Level 12 (Critical) | OWASP ASI01 | Agent Goal Hijack Directive in Context |
| **100106** | Level 11 (High) | OWASP ASI02 | Agent Tool Misuse / Exfiltration Target |
| **100107** | Level 10 (High) | OWASP ASI03 | Identity Spoofing & Privilege Escalation |
| **100108** | Level 13 (Critical) | OWASP ASI05 | Unexpected Code Execution / Sandbox Escape |
| **100109** | Level 11 (High) | OWASP ASI06 | Agent Memory & Context Poisoning |
| **100110** | Level 11 (High) | MCP Security | MCP Untrusted Server, Tool RBAC or Observation Violation |

---

## 5. Offline Operation Note

If a live Wazuh server is not running on your host, LLM Sentinel functions completely autonomously. The **Wazuh Security Monitoring** tab in the dashboard displays status as **NOT CONNECTED** and enables on-demand export to `results/wazuh_events.jsonl` for offline review.
