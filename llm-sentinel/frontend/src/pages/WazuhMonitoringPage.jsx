import React, { useState, useEffect } from 'react';
import {
  Radio,
  ShieldAlert,
  Download,
  AlertTriangle,
  CheckCircle2,
  FileCode,
  Server,
  Terminal,
  Activity,
  Layers,
  ExternalLink,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts';

import StatusBadge from '../components/common/StatusBadge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { getWazuhStatus, getWazuhAlerts, exportWazuhEvents } from '../api/client';

export const WazuhMonitoringPage = () => {
  const [status, setStatus] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [exportResult, setExportResult] = useState(null);
  const [selectedTab, setSelectedTab] = useState('alerts'); // 'alerts' or 'config'
  const [error, setError] = useState(null);

  const fetchWazuhData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [statusData, alertsData] = await Promise.all([
        getWazuhStatus(),
        getWazuhAlerts(50),
      ]);
      setStatus(statusData);
      setAlerts(alertsData.alerts || []);
    } catch (err) {
      setError(err.message || 'Failed to load Wazuh status.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchWazuhData();
  }, []);

  const handleExportEvents = async () => {
    try {
      setExporting(true);
      setError(null);
      const res = await exportWazuhEvents();
      setExportResult(res);
      await fetchWazuhData();
    } catch (err) {
      setError(`Failed to export events: ${err.message}`);
    } finally {
      setExporting(false);
    }
  };

  // Severity Distribution Chart Data
  const severityCounts = alerts.reduce((acc, a) => {
    const s = a.severity || 'MEDIUM';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  const severityChartData = [
    { name: 'CRITICAL', count: severityCounts['CRITICAL'] || 0, color: '#f43f5e' },
    { name: 'HIGH', count: severityCounts['HIGH'] || 0, color: '#ef4444' },
    { name: 'MEDIUM', count: severityCounts['MEDIUM'] || 0, color: '#f59e0b' },
    { name: 'LOW', count: severityCounts['LOW'] || 0, color: '#64748b' },
  ].filter((item) => item.count > 0);

  if (loading) return <LoadingSpinner message="Checking Wazuh SIEM connectivity and log forwarding..." />;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-soc-card border border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase mb-1">
            <Radio className="w-4 h-4" />
            <span>Security Information & Event Management (SIEM) Integration</span>
          </div>
          <h2 className="text-xl font-bold text-soc-text font-mono">
            Wazuh Security Monitoring
          </h2>
          <p className="text-xs text-soc-muted font-mono mt-1">
            Forwarding AI security telemetry to Wazuh SIEM with custom decoders and detection rules (100100–100110).
          </p>
        </div>

        {/* Action Controls */}
        <button
          onClick={handleExportEvents}
          disabled={exporting}
          className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-soc-bg font-mono font-bold text-xs flex items-center space-x-2 transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-50 shrink-0 cursor-pointer"
        >
          <Download className={`w-3.5 h-3.5 ${exporting ? 'animate-spin' : ''}`} />
          <span>{exporting ? 'Exporting JSONL...' : 'Export Events to JSONL'}</span>
        </button>
      </div>

      {/* Prominent Disconnected Status Banner */}
      <div
        className={`p-5 rounded-2xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 font-mono text-xs ${
          status?.connected
            ? 'bg-emerald-950/20 border-emerald-800/80 text-emerald-300'
            : 'bg-red-950/20 border-red-800/80 text-red-300'
        }`}
      >
        <div className="flex items-start space-x-3">
          <div
            className={`p-2 rounded-xl mt-0.5 ${
              status?.connected
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-700'
                : 'bg-red-950 text-red-400 border border-red-700'
            }`}
          >
            {status?.connected ? <CheckCircle2 className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center space-x-2 font-bold text-sm">
              <span>Wazuh Agent Status:</span>
              <StatusBadge status={status?.connected ? 'CONNECTED' : 'NOT CONNECTED'} size="sm" />
            </div>
            <p className="text-soc-muted text-xs mt-1 leading-relaxed max-w-3xl">
              {status?.details}
            </p>
            <div className="text-[11px] text-slate-400 mt-1 truncate">
              Log Forwarding Target: <span className="text-cyan-400 font-mono">{status?.log_file_path}</span>
            </div>
          </div>
        </div>

        <div className="text-right shrink-0">
          <div className="text-xs text-soc-muted">Events Forwarded</div>
          <div className="text-2xl font-bold font-mono text-soc-text mt-0.5">
            {status?.total_events_exported || 0}
          </div>
        </div>
      </div>

      {exportResult && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>
              Successfully exported {exportResult.events_exported} structured events to{' '}
              <span className="font-bold underline">{exportResult.file_path}</span>
            </span>
          </div>
          <span className="text-soc-muted text-[11px]">{exportResult.timestamp?.slice(11, 19)}</span>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-red-950/60 border border-red-800 text-red-200 text-xs font-mono flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Tabs Header */}
      <div className="flex items-center space-x-2 border-b border-soc-border pb-2 font-mono text-xs">
        <button
          onClick={() => setSelectedTab('alerts')}
          className={`px-4 py-2 rounded-xl transition-all ${
            selectedTab === 'alerts'
              ? 'bg-soc-card text-cyan-400 border border-cyan-800/80 font-bold shadow-[0_0_10px_rgba(6,182,212,0.2)]'
              : 'text-soc-muted hover:text-slate-300'
          }`}
        >
          Correlated Alerts ({alerts.length}) [Simulated / Local JSONL]
        </button>
        <button
          onClick={() => setSelectedTab('config')}
          className={`px-4 py-2 rounded-xl transition-all ${
            selectedTab === 'config'
              ? 'bg-soc-card text-cyan-400 border border-cyan-800/80 font-bold shadow-[0_0_10px_rgba(6,182,212,0.2)]'
              : 'text-soc-muted hover:text-slate-300'
          }`}
        >
          Wazuh Agent & Detection Rules Configuration
        </button>
      </div>

      {/* Tab 1: Correlated Security Alerts Feed */}
      {selectedTab === 'alerts' && (
        <div className="space-y-6">
          {/* Severity Distribution & Rule ID Matrix */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 p-5 rounded-2xl bg-soc-card border border-soc-border">
              <h3 className="text-sm font-bold text-soc-text font-mono mb-1">
                Wazuh Custom Detection Rules (100100–100110)
              </h3>
              <p className="text-xs text-soc-muted font-mono mb-4">
                Rule level thresholds mapped to OWASP LLM & Agentic AI threat vectors
              </p>

              <div className="grid grid-cols-2 md:grid-cols-3 gap-2.5 font-mono text-xs">
                <div className="p-2.5 rounded-lg bg-soc-surface border border-soc-border">
                  <div className="text-[10px] text-rose-400 font-bold">Rule 100100 (Lvl 12)</div>
                  <div className="text-slate-200 truncate">Prompt Injection</div>
                </div>
                <div className="p-2.5 rounded-lg bg-soc-surface border border-soc-border">
                  <div className="text-[10px] text-red-400 font-bold">Rule 100101 (Lvl 11)</div>
                  <div className="text-slate-200 truncate">Data Disclosure</div>
                </div>
                <div className="p-2.5 rounded-lg bg-soc-surface border border-soc-border">
                  <div className="text-[10px] text-amber-400 font-bold">Rule 100102 (Lvl 10)</div>
                  <div className="text-slate-200 truncate">Excessive Agency</div>
                </div>
                <div className="p-2.5 rounded-lg bg-soc-surface border border-soc-border">
                  <div className="text-[10px] text-rose-400 font-bold">Rule 100105 (Lvl 12)</div>
                  <div className="text-slate-200 truncate">Agent Goal Hijack</div>
                </div>
                <div className="p-2.5 rounded-lg bg-soc-surface border border-soc-border">
                  <div className="text-[10px] text-rose-400 font-bold">Rule 100108 (Lvl 13)</div>
                  <div className="text-slate-200 truncate">Sandbox Escape</div>
                </div>
                <div className="p-2.5 rounded-lg bg-soc-surface border border-soc-border">
                  <div className="text-[10px] text-red-400 font-bold">Rule 100110 (Lvl 11)</div>
                  <div className="text-slate-200 truncate">MCP Policy Breach</div>
                </div>
              </div>
            </div>

            {/* Severity Donut */}
            <div className="p-5 rounded-2xl bg-soc-card border border-soc-border flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-bold text-soc-text font-mono">Alert Severity Split</h3>
                <p className="text-xs text-soc-muted font-mono mt-0.5">Correlated from exported telemetry</p>
              </div>

              <div className="h-44 w-full my-auto">
                {severityChartData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityChartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={35}
                        outerRadius={65}
                        paddingAngle={5}
                        dataKey="count"
                      >
                        {severityChartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#111827',
                          borderColor: '#243247',
                          borderRadius: '0.75rem',
                          fontFamily: 'monospace',
                          fontSize: '11px',
                        }}
                      />
                      <Legend
                        formatter={(val) => <span className="font-mono text-xs text-slate-300">{val}</span>}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-xs font-mono text-soc-muted">
                    No alert telemetry available.
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Alerts Feed Table */}
          <div className="p-5 rounded-2xl bg-soc-card border border-soc-border">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
              <div>
                <h3 className="text-sm font-bold text-soc-text font-mono flex items-center gap-2">
                  <span>Security Alerts Feed</span>
                  <span className="px-2 py-0.5 rounded-md bg-amber-950/60 text-amber-300 border border-amber-800 text-[10px]">
                    SIMULATED SIEM INGESTION
                  </span>
                </h3>
                <p className="text-xs text-soc-muted font-mono mt-0.5">
                  Alerts correlated against local detection rules from exported JSONL events. Host Wazuh agent is NOT CONNECTED.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-soc-border text-soc-muted text-[10px] uppercase bg-soc-surface/50">
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Rule ID</th>
                    <th className="py-2.5 px-3">Level</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Action Taken</th>
                    <th className="py-2.5 px-3">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border/50">
                  {alerts.map((alt) => (
                    <tr key={alt.alert_id} className="hover:bg-soc-hover/50 transition-colors">
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap text-[11px]">
                        {alt.timestamp ? alt.timestamp.replace('T', ' ').slice(0, 19) : '-'}
                      </td>
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{alt.rule_id}</td>
                      <td className="py-2.5 px-3 text-slate-300">Lvl {alt.rule_level}</td>
                      <td className="py-2.5 px-3">
                        <StatusBadge status={alt.severity} size="sm" />
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{alt.category}</td>
                      <td className="py-2.5 px-3">
                        <span className="text-[11px] text-slate-300">{alt.action_taken}</span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 truncate max-w-xs" title={alt.rule_description}>
                        {alt.rule_description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Agent Configuration & Rules Deployment Guide */}
      {selectedTab === 'config' && (
        <div className="space-y-6 font-mono text-xs">
          {/* Step 1: Agent ossec.conf */}
          <div className="p-5 rounded-2xl bg-soc-card border border-soc-border space-y-3">
            <div className="flex items-center space-x-2 font-bold text-soc-text text-sm">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>1. Wazuh Agent Configuration Snippet (ossec.conf)</span>
            </div>
            <p className="text-soc-muted">
              Add this &lt;localfile&gt; definition to your agent's configuration file (e.g. C:\Program Files (x86)\ossec-agent\ossec.conf):
            </p>
            <pre className="p-4 rounded-xl bg-soc-bg border border-soc-border text-cyan-300 overflow-x-auto whitespace-pre">
{`<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>C:\\Users\\adars\\OneDrive\\Desktop\\ai security\\llm-sentinel\\backend\\results\\wazuh_events.jsonl</location>
  </localfile>
</ossec_config>`}
            </pre>
          </div>

          {/* Step 2: Custom Rules */}
          <div className="p-5 rounded-2xl bg-soc-card border border-soc-border space-y-3">
            <div className="flex items-center space-x-2 font-bold text-soc-text text-sm">
              <Layers className="w-4 h-4 text-amber-400" />
              <span>2. Custom Wazuh Detection Rules XML (llm_sentinel_rules.xml)</span>
            </div>
            <p className="text-soc-muted">
              Save in /var/ossec/etc/rules/llm_sentinel_rules.xml on your Wazuh Manager:
            </p>
            <pre className="p-4 rounded-xl bg-soc-bg border border-soc-border text-amber-300 overflow-x-auto whitespace-pre max-h-64">
{`<group name="llm_sentinel,ai_security,owasp_llm,">

  <rule id="100099" level="3">
    <decoded_as>llm_sentinel_json</decoded_as>
    <field name="source">LLM Sentinel</field>
    <description>LLM Sentinel security event observed</description>
  </rule>

  <rule id="100100" level="12">
    <if_sid>100099</if_sid>
    <field name="risk_id">^LLM01</field>
    <description>LLM Sentinel: Prompt Injection Attack Detected</description>
  </rule>

  <rule id="100101" level="11">
    <if_sid>100099</if_sid>
    <field name="risk_id">^LLM02</field>
    <description>LLM Sentinel: Sensitive Information Disclosure Attempt</description>
  </rule>

  <rule id="100105" level="12">
    <if_sid>100099</if_sid>
    <field name="risk_id">^ASI01</field>
    <description>LLM Sentinel: Agent Goal Hijack Directive in Context</description>
  </rule>

  <rule id="100108" level="13">
    <if_sid>100099</if_sid>
    <field name="risk_id">^ASI05</field>
    <description>LLM Sentinel: Unexpected Code Execution / Sandbox Escape</description>
  </rule>

  <rule id="100110" level="11">
    <if_sid>100099</if_sid>
    <field name="risk_id">^MCP</field>
    <description>LLM Sentinel: MCP Security & Policy Violation</description>
  </rule>

</group>`}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default WazuhMonitoringPage;
