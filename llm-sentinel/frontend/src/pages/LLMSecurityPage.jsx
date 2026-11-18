import React, { useState, useEffect } from 'react';
import {
  BrainCircuit,
  Play,
  RotateCw,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileCode,
  ShieldAlert,
  ShieldCheck,
  ChevronDown,
} from 'lucide-react';

import StatusBadge from '../components/common/StatusBadge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import EvidenceModal from '../components/common/EvidenceModal';
import { getTestCases, runSingleTest, runAllTests, getSecurityMode, getTestResults } from '../api/client';

const LLM_RISKS = [
  { id: 'ALL', name: 'All LLM Risks' },
  { id: 'LLM01', name: 'LLM01: Prompt Injection' },
  { id: 'LLM02', name: 'LLM02: Sensitive Info Disclosure' },
  { id: 'LLM03', name: 'LLM03: Excessive Agency' },
  { id: 'LLM08', name: 'LLM08: Hidden Context Exposure' },
  { id: 'LLM10', name: 'LLM10: Improper Output Handling' },
];

export const LLMSecurityPage = () => {
  const [testCases, setTestCases] = useState([]);
  const [selectedRisk, setSelectedRisk] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [runningId, setRunningId] = useState(null);
  const [runningAll, setRunningAll] = useState(false);
  const [selectedResult, setSelectedResult] = useState(null);
  const [testResults, setTestResults] = useState({});
  const [activeMode, setActiveMode] = useState('protected');
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);

  const fetchCases = async () => {
    try {
      setLoading(true);
      setError(null);
      const [cases, modeData, latestResults] = await Promise.all([
        getTestCases(),
        getSecurityMode(),
        getTestResults({ limit: 150 }).catch(() => []),
      ]);
      // Filter for LLM risks only
      const llmCases = cases.filter((c) => c.risk_id?.startsWith('LLM'));
      setTestCases(llmCases);
      if (modeData?.mode) setActiveMode(modeData.mode);

      // Populate test results map from SQLite history (in reverse so newest prevails)
      if (Array.isArray(latestResults) && latestResults.length > 0) {
        const map = {};
        [...latestResults].reverse().forEach((r) => {
          if (r.test_id && r.test_id.startsWith('PI') || r.test_id?.startsWith('SD') || r.test_id?.startsWith('EA') || r.test_id?.startsWith('HC') || r.test_id?.startsWith('OH')) {
            map[r.test_id] = r;
          }
        });
        setTestResults(map);
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch test cases.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleRunSingle = async (testId) => {
    try {
      setRunningId(testId);
      setError(null);
      const res = await runSingleTest(testId, activeMode);
      setTestResults((prev) => ({ ...prev, [testId]: res }));
    } catch (err) {
      setError(`Test ${testId} execution failed: ${err.message}`);
    } finally {
      setRunningId(null);
    }
  };

  const handleRunAll = async () => {
    try {
      setRunningAll(true);
      setError(null);
      const filter = selectedRisk === 'ALL' ? null : selectedRisk;
      const res = await runAllTests(filter, activeMode);
      setSummary(res);
      // Map results into local lookup
      const map = {};
      if (res.results) {
        res.results.forEach((r) => {
          map[r.test_id] = r;
        });
      }
      setTestResults((prev) => ({ ...prev, ...map }));
    } catch (err) {
      setError(`Batch evaluation failed: ${err.message}`);
    } finally {
      setRunningAll(false);
    }
  };

  const filteredCases =
    selectedRisk === 'ALL'
      ? testCases
      : testCases.filter((c) => c.risk_id === selectedRisk);

  if (loading) return <LoadingSpinner message="Loading OWASP LLM 2026 test registry..." />;

  return (
    <div className="space-y-6">
      {/* Page Header Banner */}
      <div className="p-6 rounded-2xl bg-soc-card border border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase mb-1">
            <BrainCircuit className="w-4 h-4" />
            <span>Target: Customer Support Chatbot (OmniCorpChatbot)</span>
          </div>
          <h2 className="text-xl font-bold text-soc-text font-mono">
            OWASP Top 10 for LLM Applications (2026)
          </h2>
          <p className="text-xs text-soc-muted font-mono mt-1">
            15 automated attack scenarios across 5 mandatory categories: Prompt Injection, Information Disclosure, Agency, Context Exposure, and Output Handling.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3 shrink-0">
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-soc-surface border border-soc-border font-mono text-xs">
            <span className="text-soc-muted">Mode:</span>
            <select
              value={activeMode}
              onChange={(e) => setActiveMode(e.target.value)}
              className="bg-transparent text-soc-text font-semibold focus:outline-none cursor-pointer"
            >
              <option value="protected" className="bg-soc-surface text-emerald-400">Protected</option>
              <option value="vulnerable" className="bg-soc-surface text-red-400">Vulnerable</option>
            </select>
          </div>

          <button
            onClick={handleRunAll}
            disabled={runningAll}
            className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-soc-bg font-mono font-bold text-xs flex items-center space-x-2 transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${runningAll ? 'animate-spin' : ''}`} />
            <span>{runningAll ? 'Evaluating...' : 'Run All Filtered'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/60 border border-red-800 text-red-200 text-xs font-mono flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Batch Run Summary Banner */}
      {summary && (
        <div className="p-4 rounded-xl bg-soc-surface border border-cyan-800/60 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-4">
            <span className="text-cyan-400 font-bold">Run Completed:</span>
            <span>Total: {summary.total_tests}</span>
            <span className="text-emerald-400">Blocked: {summary.blocked}</span>
            <span className="text-amber-400">Partial: {summary.partial}</span>
            <span className="text-red-400">Succeeded: {summary.succeeded}</span>
          </div>
          <span className="text-soc-muted text-[11px]">ID: {summary.run_id}</span>
        </div>
      )}

      {/* Risk Filter Tabs */}
      <div className="flex items-center space-x-2 overflow-x-auto pb-2">
        {LLM_RISKS.map((r) => (
          <button
            key={r.id}
            onClick={() => setSelectedRisk(r.id)}
            className={`px-3 py-1.5 rounded-xl font-mono text-xs whitespace-nowrap transition-all ${
              selectedRisk === r.id
                ? 'bg-soc-card text-cyan-400 border border-cyan-700/80 font-bold shadow-[0_0_10px_rgba(6,182,212,0.2)]'
                : 'text-soc-muted hover:text-slate-200 hover:bg-soc-hover border border-transparent'
            }`}
          >
            {r.name}
          </button>
        ))}
      </div>

      {/* Test Cases Table */}
      <div className="rounded-2xl bg-soc-card border border-soc-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-soc-border text-soc-muted text-[11px] uppercase tracking-wider bg-soc-surface/50">
                <th className="py-3 px-4">Test ID</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4">Attack Scenario</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Latest Result</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/50">
              {filteredCases.map((tc) => {
                const result = testResults[tc.test_id];
                const isRunning = runningId === tc.test_id;

                return (
                  <tr key={tc.test_id} className="hover:bg-soc-hover/50 transition-colors">
                    <td className="py-3.5 px-4 text-cyan-400 font-bold">{tc.test_id}</td>
                    <td className="py-3.5 px-4 text-slate-300">
                      <span className="text-[11px] px-2 py-0.5 rounded bg-soc-surface border border-soc-border">
                        {tc.risk_id}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 max-w-md">
                      <div className="font-semibold text-soc-text">{tc.test_name}</div>
                      <div className="text-[11px] text-soc-muted truncate mt-0.5" title={tc.attack_objective}>
                        {tc.attack_objective}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <StatusBadge status={tc.severity} size="sm" />
                    </td>
                    <td className="py-3.5 px-4">
                      {result ? (
                        <StatusBadge status={result.result} size="sm" />
                      ) : (
                        <span className="text-soc-muted text-[11px]">NOT RUN</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end space-x-2">
                        {result && (
                          <button
                            onClick={() => setSelectedResult(result)}
                            className="px-2.5 py-1 rounded-lg bg-soc-surface border border-soc-border text-cyan-400 hover:text-cyan-300 text-[11px]"
                          >
                            Inspect
                          </button>
                        )}
                        <button
                          onClick={() => handleRunSingle(tc.test_id)}
                          disabled={isRunning || runningAll}
                          className="px-3 py-1 rounded-lg bg-soc-surface hover:bg-soc-hover border border-soc-border text-soc-text hover:text-cyan-400 transition-colors flex items-center space-x-1 disabled:opacity-50 text-[11px]"
                        >
                          <Play className={`w-3 h-3 ${isRunning ? 'animate-spin' : ''}`} />
                          <span>{isRunning ? 'Running...' : 'Execute'}</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
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

export default LLMSecurityPage;
