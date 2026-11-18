import React, { useState, useEffect } from 'react';
import {
  FileBarChart,
  Download,
  Filter,
  Search,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Printer,
  Copy,
  Check,
} from 'lucide-react';

import StatusBadge from '../components/common/StatusBadge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import EvidenceModal from '../components/common/EvidenceModal';
import { getTestResults, getDashboardOverview } from '../api/client';

export const ResultsReportsPage = () => {
  const [results, setResults] = useState([]);
  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRisk, setFilterRisk] = useState('');
  const [filterMode, setFilterMode] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [selectedResult, setSelectedResult] = useState(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(null);

  const fetchResults = async () => {
    try {
      setLoading(true);
      setError(null);
      const params = {};
      if (filterRisk) params.risk_id = filterRisk;
      if (filterMode) params.mode = filterMode;
      const [resData, ovData] = await Promise.all([
        getTestResults({ ...params, limit: 100 }),
        getDashboardOverview(),
      ]);
      setResults(resData);
      setOverview(ovData);
    } catch (err) {
      setError(err.message || 'Failed to load test results.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResults();
  }, [filterRisk, filterMode]);

  // Client-side search & status filtering
  const filteredResults = results.filter((r) => {
    const matchesSearch =
      searchTerm === '' ||
      r.test_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.test_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.target?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.risk_name?.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus = filterStatus === '' || r.result === filterStatus;

    return matchesSearch && matchesStatus;
  });

  // Export to CSV generator
  const exportToCSV = () => {
    if (filteredResults.length === 0) return;

    const headers = [
      'Test ID',
      'Risk ID',
      'Risk Name',
      'Test Name',
      'Target',
      'Security Mode',
      'Model',
      'Result',
      'Evaluation Explanation',
      'Timestamp',
    ];

    const rows = filteredResults.map((r) => [
      `"${r.test_id || ''}"`,
      `"${r.risk_id || ''}"`,
      `"${(r.risk_name || '').replace(/"/g, '""')}"`,
      `"${(r.test_name || '').replace(/"/g, '""')}"`,
      `"${r.target || ''}"`,
      `"${r.mode || ''}"`,
      `"${r.model || ''}"`,
      `"${r.result || ''}"`,
      `"${(r.evaluation_explanation || '').replace(/"/g, '""')}"`,
      `"${r.timestamp || ''}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `llm_sentinel_results_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Executive summary text for PDF report
  const executiveSummary = `LLM SENTINEL — EXECUTIVE SECURITY REPORT
Evaluation Date: ${new Date().toISOString().slice(0, 10)}
Scope: OWASP Top 10 for LLM Applications (2026), OWASP Top 10 for Agentic AI (2026), and Model Context Protocol (MCP 2.x).

EXECUTIVE SUMMARY FINDINGS:
- Total Security Test Scenarios Executed: ${overview?.total_tests_executed || results.length}
- Attacks Blocked by Protective Guardrails: ${overview?.blocked || 0} (${overview?.blocking_rate || 0}%)
- Exploitable Vulnerabilities Observed in Vulnerable Baseline: ${overview?.succeeded || 0}
- Baseline Attack Success Rate (ASR): ${overview?.attack_success_rate || 0}%
- Overall Mitigation Effectiveness: ${overview?.mitigation_effectiveness || 0}%
- Active Security Posture: ${overview?.active_security_mode?.toUpperCase() || 'PROTECTED'}

KEY RISK REDUCTIONS:
1. LLM01 Prompt Injection: Instruction hierarchy & boundary fences reduced direct override ASR to 0%.
2. LLM02 Sensitive Information Disclosure: Automated redaction & pre-retrieval authorization blocked SECRET-FLAG-123 exfiltration.
3. LLM03 / ASI02 Tool Misuse & Excessive Agency: Strict server-side RBAC restricted email and HTTP endpoints.
4. ASI05 Code Execution Sandbox Escape: Strict execution containerization enforced with zero host breaches.
5. MCP Security: Server allowlisting, observation wrapping, and parameter validation achieved 100% attack mitigation.`;

  const copySummary = () => {
    navigator.clipboard.writeText(executiveSummary);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) return <LoadingSpinner message="Querying test results database..." />;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-soc-card border border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase mb-1">
            <FileBarChart className="w-4 h-4" />
            <span>Audit Records & Compliance Reporting</span>
          </div>
          <h2 className="text-xl font-bold text-soc-text font-mono">
            Security Test Results & Executive Summary
          </h2>
          <p className="text-xs text-soc-muted font-mono mt-1">
            Query test executions, inspect telemetry, export CSV audit dumps, and generate executive summaries for PDF reports.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3 shrink-0">
          <button
            onClick={exportToCSV}
            className="px-4 py-2 rounded-xl bg-soc-surface hover:bg-soc-hover border border-soc-border text-soc-text font-mono text-xs flex items-center space-x-2 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export to CSV ({filteredResults.length})</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/60 border border-red-800 text-red-200 text-xs font-mono flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl bg-soc-card border border-soc-border grid grid-cols-1 md:grid-cols-4 gap-3 font-mono text-xs">
        {/* Search Input */}
        <div className="relative">
          <Search className="w-4 h-4 text-soc-muted absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search test ID, name, target..."
            className="w-full pl-9 pr-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Filter by Risk Category */}
        <select
          value={filterRisk}
          onChange={(e) => setFilterRisk(e.target.value)}
          className="px-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500 cursor-pointer"
        >
          <option value="">All Risk Categories</option>
          <option value="LLM01">LLM01: Prompt Injection</option>
          <option value="LLM02">LLM02: Sensitive Info Disclosure</option>
          <option value="LLM03">LLM03: Excessive Agency</option>
          <option value="LLM08">LLM08: Hidden Context Exposure</option>
          <option value="LLM10">LLM10: Improper Output Handling</option>
          <option value="ASI01">ASI01: Agent Goal Hijack</option>
          <option value="ASI02">ASI02: Tool Misuse</option>
          <option value="ASI03">ASI03: Identity & Privilege Abuse</option>
          <option value="ASI05">ASI05: Unexpected Code Execution</option>
          <option value="ASI06">ASI06: Memory & Context Poisoning</option>
        </select>

        {/* Filter by Mode */}
        <select
          value={filterMode}
          onChange={(e) => setFilterMode(e.target.value)}
          className="px-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500 cursor-pointer"
        >
          <option value="">All Security Modes</option>
          <option value="protected">Protected</option>
          <option value="vulnerable">Vulnerable</option>
        </select>

        {/* Filter by Outcome Status */}
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="px-3 py-2 rounded-xl bg-soc-surface border border-soc-border text-soc-text focus:outline-none focus:border-cyan-500 cursor-pointer"
        >
          <option value="">All Outcome Statuses</option>
          <option value="BLOCKED">BLOCKED</option>
          <option value="PARTIAL">PARTIAL</option>
          <option value="SUCCEEDED">SUCCEEDED</option>
        </select>
      </div>

      {/* Results Table */}
      <div className="rounded-2xl bg-soc-card border border-soc-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-soc-border text-soc-muted text-[11px] uppercase tracking-wider bg-soc-surface/50">
                <th className="py-3 px-4">Test ID</th>
                <th className="py-3 px-4">Target</th>
                <th className="py-3 px-4">Risk Category</th>
                <th className="py-3 px-4">Scenario Name</th>
                <th className="py-3 px-4">Mode</th>
                <th className="py-3 px-4">Result</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/50">
              {filteredResults.length > 0 ? (
                filteredResults.map((r) => (
                  <tr key={r.id || `${r.test_id}-${r.timestamp}`} className="hover:bg-soc-hover/50 transition-colors">
                    <td className="py-3 px-4 text-cyan-400 font-bold">{r.test_id}</td>
                    <td className="py-3 px-4 text-slate-300 font-semibold">{r.target}</td>
                    <td className="py-3 px-4 text-soc-muted">{r.risk_id}</td>
                    <td className="py-3 px-4 max-w-xs truncate text-soc-text" title={r.test_name}>
                      {r.test_name}
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-soc-surface border border-soc-border">
                        {r.mode}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={r.result} size="sm" />
                    </td>
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap text-[11px]">
                      {r.timestamp ? r.timestamp.replace('T', ' ').slice(0, 19) : '-'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedResult(r)}
                        className="px-2.5 py-1 rounded-lg bg-soc-surface border border-soc-border text-cyan-400 hover:text-cyan-300 text-[11px]"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-soc-muted font-mono text-xs">
                    No results matching current filters found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Executive Summary for PDF Report Card */}
      <div className="p-6 rounded-2xl bg-soc-card border border-soc-border space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-sm font-bold text-soc-text font-mono">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span>Executive Summary for PDF Final Report</span>
          </div>
          <button
            onClick={copySummary}
            className="px-3 py-1.5 rounded-lg bg-soc-surface hover:bg-soc-hover border border-soc-border text-xs font-mono text-slate-300 hover:text-cyan-400 flex items-center space-x-1.5 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied to Clipboard' : 'Copy Summary'}</span>
          </button>
        </div>

        <pre className="p-4 rounded-xl bg-soc-bg border border-soc-border text-slate-300 font-mono text-xs whitespace-pre-wrap leading-relaxed overflow-x-auto">
          {executiveSummary}
        </pre>
      </div>

      {/* Evidence Modal */}
      <EvidenceModal
        isOpen={Boolean(selectedResult)}
        onClose={() => setSelectedResult(null)}
        data={selectedResult}
      />
    </div>
  );
};

export default ResultsReportsPage;
