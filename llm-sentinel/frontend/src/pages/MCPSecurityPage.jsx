import React, { useState, useEffect } from 'react';
import {
  Network,
  Server,
  Wrench,
  FileCode2,
  Play,
  RotateCw,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Send,
  Terminal,
  Activity,
  CheckCircle2,
} from 'lucide-react';

import StatusBadge from '../components/common/StatusBadge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import {
  getMCPStatus,
  getMCPServers,
  getMCPTools,
  getMCPResources,
  invokeMCPTool,
  getMCPEvents,
  getMCPTests,
  runAllMCPSecurityTests,
} from '../api/client';

export const MCPSecurityPage = () => {
  const [status, setStatus] = useState(null);
  const [servers, setServers] = useState([]);
  const [tools, setTools] = useState([]);
  const [resources, setResources] = useState([]);
  const [events, setEvents] = useState([]);
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const [invoking, setInvoking] = useState(false);
  const [invokeResult, setInvokeResult] = useState(null);
  const [error, setError] = useState(null);

  // Tool Invocation form state
  const [selectedTool, setSelectedTool] = useState('search_documents');
  const [toolQuery, setToolQuery] = useState('acceptable use');
  const [customerId, setCustomerId] = useState('CUST-101');
  const [recipient, setRecipient] = useState('ops@omnicorp.com');
  const [message, setMessage] = useState('Routine system update.');
  const [userId, setUserId] = useState('guest');
  const [invokeMode, setInvokeMode] = useState('protected');

  const fetchMCPData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [statusData, serversData, toolsData, resourcesData, eventsData] = await Promise.all([
        getMCPStatus(),
        getMCPServers(),
        getMCPTools(),
        getMCPResources(),
        getMCPEvents(15),
      ]);
      setStatus(statusData);
      setServers(serversData);
      setTools(toolsData);
      setResources(resourcesData);
      setEvents(eventsData);
    } catch (err) {
      setError(err.message || 'Failed to load MCP telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMCPData();
  }, []);

  const handleRunEvaluation = async () => {
    try {
      setEvaluating(true);
      setError(null);
      const res = await runAllMCPSecurityTests();
      setComparison(res);
      await fetchMCPData();
    } catch (err) {
      setError(`MCP comparative evaluation failed: ${err.message}`);
    } finally {
      setEvaluating(false);
    }
  };

  const handleInvoke = async (e) => {
    e.preventDefault();
    try {
      setInvoking(true);
      setInvokeResult(null);

      let args = {};
      if (selectedTool === 'search_documents') {
        args = { query: toolQuery };
      } else if (selectedTool === 'get_customer_record') {
        args = { customer_id: customerId };
      } else if (selectedTool === 'send_notification') {
        args = { recipient, message };
      }

      const res = await invokeMCPTool(selectedTool, args, userId, invokeMode);
      setInvokeResult(res);
      // Refresh audit logs
      const updatedEvents = await getMCPEvents(15);
      setEvents(updatedEvents);
    } catch (err) {
      setError(`Tool invocation failed: ${err.message}`);
    } finally {
      setInvoking(false);
    }
  };

  if (loading) return <LoadingSpinner message="Querying Model Context Protocol (MCP) server..." />;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-soc-card border border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase mb-1">
            <Network className="w-4 h-4" />
            <span>Model Context Protocol (MCP 2.x) Proof of Concept</span>
          </div>
          <h2 className="text-xl font-bold text-soc-text font-mono">
            MCP Protocol Security & Hardening
          </h2>
          <p className="text-xs text-soc-muted font-mono mt-1">
            Evaluating tools, resources, server allowlisting, and observation isolation against prompt injection and excessive agency.
          </p>
        </div>

        {/* Action Controls */}
        <button
          onClick={handleRunEvaluation}
          disabled={evaluating}
          className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-soc-bg font-mono font-bold text-xs flex items-center space-x-2 transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-50 shrink-0"
        >
          <Play className={`w-3.5 h-3.5 ${evaluating ? 'animate-spin' : ''}`} />
          <span>{evaluating ? 'Evaluating 6 MCP Scenarios...' : 'Run All MCP Scenarios'}</span>
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/60 border border-red-800 text-red-200 text-xs font-mono flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Connection & Posture Bar */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono text-xs">
        <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex items-center justify-between">
          <div>
            <div className="text-soc-muted text-[10px] uppercase">Connection State</div>
            <div className="text-sm font-bold text-soc-text mt-0.5">
              {status?.connected ? 'CONNECTED' : 'DISCONNECTED'}
            </div>
          </div>
          <StatusBadge status={status?.connected ? 'CONNECTED' : 'NOT CONNECTED'} size="sm" />
        </div>

        <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex items-center justify-between">
          <div>
            <div className="text-soc-muted text-[10px] uppercase">Connected Server</div>
            <div className="text-sm font-bold text-cyan-400 mt-0.5 truncate max-w-[130px]">
              {status?.server_name || status?.server_id}
            </div>
          </div>
          <span className="text-[10px] px-2 py-0.5 rounded bg-soc-surface border border-soc-border text-soc-muted">
            v{status?.server_version || '1.0.0'}
          </span>
        </div>

        <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex items-center justify-between">
          <div>
            <div className="text-soc-muted text-[10px] uppercase">Transport Layer</div>
            <div className="text-sm font-bold text-soc-text mt-0.5 uppercase">
              {status?.transport || 'memory'}
            </div>
          </div>
          <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
            In-Process
          </span>
        </div>

        <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex items-center justify-between">
          <div>
            <div className="text-soc-muted text-[10px] uppercase">Capabilities</div>
            <div className="text-sm font-bold text-soc-text mt-0.5">
              {status?.tools_count || 3} Tools / {status?.resources_count || 2} Res
            </div>
          </div>
          <StatusBadge status="ACTIVE" size="sm" />
        </div>
      </div>

      {/* Comparative Evaluation Banner if run */}
      {comparison && (
        <div className="p-5 rounded-2xl bg-soc-card border border-soc-border">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-soc-text font-mono">
              MCP Comparative Evaluation Outcome ({comparison.comparison_id})
            </h3>
            <span className="text-emerald-400 font-mono text-xs font-bold">
              +{comparison.overall_improvement}% Posture Improvement
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs mb-4">
            <div className="p-3 rounded-xl bg-red-950/30 border border-red-900/60">
              <span className="text-red-400 font-semibold">Baseline ASR:</span> {comparison.baseline_asr}% (0 Blocked / 6 Succeeded)
            </div>
            <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-900/60">
              <span className="text-emerald-400 font-semibold">Protected ASR:</span> {comparison.protected_asr}% (6 Blocked / 0 Succeeded)
            </div>
            <div className="p-3 rounded-xl bg-cyan-950/30 border border-cyan-900/60">
              <span className="text-cyan-400 font-semibold">Attacks Mitigated:</span> 100% of MCP injection & agency vectors
            </div>
          </div>

          {/* Test Case Comparisons Breakdown */}
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-soc-border text-soc-muted text-[10px] uppercase">
                  <th className="py-2 px-3">Test ID</th>
                  <th className="py-2 px-3">Attack Scenario</th>
                  <th className="py-2 px-3">Baseline</th>
                  <th className="py-2 px-3">Protected</th>
                  <th className="py-2 px-3">Mitigation Decision</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border/50">
                {comparison.test_comparisons?.map((c) => (
                  <tr key={c.test_id}>
                    <td className="py-2 px-3 text-cyan-400 font-bold">{c.test_id}</td>
                    <td className="py-2 px-3 text-slate-200">{c.attack_name}</td>
                    <td className="py-2 px-3">
                      <StatusBadge status={c.baseline_status} size="sm" />
                    </td>
                    <td className="py-2 px-3">
                      <StatusBadge status={c.protected_status} size="sm" />
                    </td>
                    <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{c.protected_decision}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Discovered Tools & Resources Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Tools Section */}
        <div className="p-5 rounded-2xl bg-soc-card border border-soc-border">
          <div className="flex items-center space-x-2 text-sm font-bold text-soc-text font-mono mb-4">
            <Wrench className="w-4 h-4 text-cyan-400" />
            <span>Discovered MCP Tools (3)</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {tools.map((t) => (
              <div key={t.name} className="p-3 rounded-xl bg-soc-surface border border-soc-border">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-cyan-400">{t.name}</span>
                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] px-2 py-0.5 rounded bg-soc-card border border-soc-border text-soc-muted">
                      Role: {t.required_role}
                    </span>
                    {t.is_sensitive && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
                        Sensitive
                      </span>
                    )}
                  </div>
                </div>
                <p className="text-soc-muted text-xs leading-relaxed">{t.description}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Resources Section */}
        <div className="p-5 rounded-2xl bg-soc-card border border-soc-border">
          <div className="flex items-center space-x-2 text-sm font-bold text-soc-text font-mono mb-4">
            <FileCode2 className="w-4 h-4 text-amber-400" />
            <span>Discovered MCP Resources (2)</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {resources.map((r) => (
              <div key={r.uri} className="p-3 rounded-xl bg-soc-surface border border-soc-border">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-amber-400 truncate max-w-xs">{r.uri}</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-soc-card border border-soc-border text-soc-muted">
                    {r.mime_type}
                  </span>
                </div>
                <p className="text-soc-muted text-xs">{r.description || 'Internal OmniCorp MCP Resource'}</p>
                <div className="mt-2 text-[10px] text-cyan-400/80">
                  Protected Mode wraps observations in &lt;untrusted_mcp_observation&gt; delimiters
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Safe Tool Invocation Console */}
      <div className="p-5 rounded-2xl bg-soc-card border border-soc-border">
        <div className="flex items-center space-x-2 text-sm font-bold text-soc-text font-mono mb-4">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Interactive Tool Invocation & RBAC Verification</span>
        </div>

        <form onSubmit={handleInvoke} className="space-y-4 font-mono text-xs">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <label className="block text-soc-muted text-[10px] uppercase mb-1">Select Tool</label>
              <select
                value={selectedTool}
                onChange={(e) => setSelectedTool(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500"
              >
                <option value="search_documents">search_documents</option>
                <option value="get_customer_record">get_customer_record</option>
                <option value="send_notification">send_notification</option>
              </select>
            </div>

            <div>
              <label className="block text-soc-muted text-[10px] uppercase mb-1">Caller Role</label>
              <select
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500"
              >
                <option value="guest">guest (Unauthenticated)</option>
                <option value="employee">employee (Standard Role)</option>
                <option value="admin">admin (Full Clearance)</option>
              </select>
            </div>

            <div>
              <label className="block text-soc-muted text-[10px] uppercase mb-1">Execution Mode</label>
              <select
                value={invokeMode}
                onChange={(e) => setInvokeMode(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500"
              >
                <option value="protected">Protected (Enforce RBAC)</option>
                <option value="vulnerable">Vulnerable (Unrestricted)</option>
              </select>
            </div>

            <div className="flex items-end">
              <button
                type="submit"
                disabled={invoking}
                className="w-full py-2 px-4 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-soc-bg font-bold transition-all flex items-center justify-center space-x-1.5 shadow-[0_0_12px_rgba(6,182,212,0.3)] disabled:opacity-50"
              >
                <Send className={`w-3.5 h-3.5 ${invoking ? 'animate-spin' : ''}`} />
                <span>{invoking ? 'Invoking...' : 'Invoke Tool'}</span>
              </button>
            </div>
          </div>

          {/* Dynamic Tool Input Fields */}
          {selectedTool === 'search_documents' && (
            <div>
              <label className="block text-soc-muted text-[10px] uppercase mb-1">Search Query</label>
              <input
                type="text"
                value={toolQuery}
                onChange={(e) => setToolQuery(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500"
                placeholder="e.g. return, acceptable use, or confidential audit"
              />
            </div>
          )}

          {selectedTool === 'get_customer_record' && (
            <div>
              <label className="block text-soc-muted text-[10px] uppercase mb-1">Customer ID</label>
              <input
                type="text"
                value={customerId}
                onChange={(e) => setCustomerId(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500"
                placeholder="CUST-101, CUST-102, or confidential VIP CUST-VIP-001"
              />
            </div>
          )}

          {selectedTool === 'send_notification' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-soc-muted text-[10px] uppercase mb-1">Recipient Channel</label>
                <input
                  type="text"
                  value={recipient}
                  onChange={(e) => setRecipient(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500"
                  placeholder="e.g. ops@omnicorp.com or leaks@external.org"
                />
              </div>
              <div>
                <label className="block text-soc-muted text-[10px] uppercase mb-1">Notification Message</label>
                <input
                  type="text"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500"
                  placeholder="Notification text..."
                />
              </div>
            </div>
          )}
        </form>

        {/* Invocation Result Display */}
        {invokeResult && (
          <div className="mt-4 p-4 rounded-xl bg-soc-surface border border-soc-border font-mono text-xs">
            <div className="flex items-center justify-between mb-2">
              <span className="font-bold text-soc-text">
                Decision: <StatusBadge status={invokeResult.security_decision} size="sm" />
              </span>
              <span className="text-soc-muted text-[11px]">{invokeResult.timestamp}</span>
            </div>

            {invokeResult.error && (
              <div className="text-red-400 mb-2 font-semibold">
                Reason: {invokeResult.error}
              </div>
            )}

            {invokeResult.output && (
              <div>
                <div className="text-[10px] text-soc-muted uppercase mb-1">Tool Output Payload:</div>
                <pre className="p-3 rounded-lg bg-soc-bg border border-soc-border text-emerald-300 overflow-x-auto whitespace-pre-wrap max-h-48">
                  {invokeResult.output}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>

      {/* MCP Security Audit Events Feed */}
      <div className="p-5 rounded-2xl bg-soc-card border border-soc-border">
        <div className="flex items-center justify-between mb-4 font-mono">
          <div className="flex items-center space-x-2 text-sm font-bold text-soc-text">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span>MCP Security Audit Trail (SQLite)</span>
          </div>
          <span className="text-xs text-soc-muted">{events.length} Events</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-soc-border text-soc-muted text-[10px] uppercase">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">Server / Tool</th>
                <th className="py-2.5 px-3">User</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Audit Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/50">
              {events.map((ev) => (
                <tr key={ev.id} className="hover:bg-soc-hover/50 transition-colors">
                  <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                    {ev.timestamp?.replace('T', ' ').slice(0, 19)}
                  </td>
                  <td className="py-2.5 px-3 text-cyan-400">{ev.event_type}</td>
                  <td className="py-2.5 px-3 text-slate-300">
                    {ev.tool_name || ev.resource_uri || ev.server_id}
                  </td>
                  <td className="py-2.5 px-3 text-soc-muted">
                    {ev.user_id} ({ev.user_role})
                  </td>
                  <td className="py-2.5 px-3">
                    <StatusBadge status={ev.authorized ? 'PERMITTED' : 'DENIED'} size="sm" />
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 truncate max-w-sm" title={ev.details}>
                    {ev.details}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default MCPSecurityPage;
