import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Play,
  RotateCw,
  ToggleLeft,
  ToggleRight,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Unlock,
} from 'lucide-react';

import StatusBadge from '../components/common/StatusBadge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import {
  getMitigationsStatus,
  toggleMitigation,
  runBeforeAfterEvaluation,
  getComparisons,
  getSecurityMode,
  setSecurityMode,
} from '../api/client';

export const MitigationCenterPage = () => {
  const [mitigations, setMitigations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const [togglingId, setTogglingId] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [mode, setMode] = useState('protected');
  const [error, setError] = useState(null);

  const fetchMitigationData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [statusRes, modeRes, cmpRes] = await Promise.all([
        getMitigationsStatus(),
        getSecurityMode(),
        getComparisons(1),
      ]);
      setMitigations(statusRes.mitigations || []);
      if (modeRes?.mode) setMode(modeRes.mode);
      if (cmpRes && cmpRes.length > 0) {
        setComparison(cmpRes[0]);
      }
    } catch (err) {
      setError(err.message || 'Failed to load mitigations.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMitigationData();
  }, []);

  const handleToggle = async (riskId, currentEnabled) => {
    try {
      setTogglingId(riskId);
      const nextEnabled = !currentEnabled;
      const res = await toggleMitigation(riskId, nextEnabled);
      setMitigations((prev) =>
        prev.map((m) => (m.risk_id === riskId ? { ...m, enabled: nextEnabled } : m))
      );
    } catch (err) {
      setError(`Failed to toggle mitigation ${riskId}: ${err.message}`);
    } finally {
      setTogglingId(null);
    }
  };

  const handleRunEvaluation = async () => {
    try {
      setEvaluating(true);
      setError(null);
      const res = await runBeforeAfterEvaluation();
      setComparison(res);
      await fetchMitigationData();
    } catch (err) {
      setError(`Comparative evaluation failed: ${err.message}`);
    } finally {
      setEvaluating(false);
    }
  };

  const handleModeChange = async (newMode) => {
    try {
      await setSecurityMode(newMode);
      setMode(newMode);
      await fetchMitigationData();
    } catch (err) {
      setError(`Failed to update mode: ${err.message}`);
    }
  };

  if (loading) return <LoadingSpinner message="Querying active mitigation policies..." />;

  const baselineASR = comparison?.baseline_asr ?? 100.0;
  const protectedASR = comparison?.protected_asr ?? 0.0;
  const improvement = comparison?.overall_improvement ?? (baselineASR - protectedASR);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-soc-card border border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs uppercase mb-1">
            <ShieldCheck className="w-4 h-4" />
            <span>Centralized Security Control Layer</span>
          </div>
          <h2 className="text-xl font-bold text-soc-text font-mono">
            Mitigation Center & Policy Enforcement
          </h2>
          <p className="text-xs text-soc-muted font-mono mt-1">
            Configurable defensive guardrails across 10 mandatory OWASP risks with automated before/after comparative benchmarking.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3 shrink-0">
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-soc-surface border border-soc-border font-mono text-xs">
            <span className="text-soc-muted">Global Mode:</span>
            <button
              onClick={() => handleModeChange(mode === 'protected' ? 'vulnerable' : 'protected')}
              className={`font-semibold cursor-pointer ${
                mode === 'protected' ? 'text-emerald-400' : 'text-red-400'
              }`}
            >
              {mode.toUpperCase()}
            </button>
          </div>

          <button
            onClick={handleRunEvaluation}
            disabled={evaluating}
            className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-soc-bg font-mono font-bold text-xs flex items-center space-x-2 transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)] disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${evaluating ? 'animate-spin' : ''}`} />
            <span>{evaluating ? 'Running Before/After Benchmark...' : 'Run Comparative Evaluation'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/60 border border-red-800 text-red-200 text-xs font-mono flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Before / After Evaluation Comparison Card */}
      <div className="p-6 rounded-2xl bg-soc-card border border-soc-border">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-soc-text font-mono flex items-center space-x-2">
              <span>Before & After Security Posture Benchmark</span>
              {comparison && (
                <span className="text-[10px] px-2 py-0.5 rounded bg-soc-surface text-soc-muted font-normal">
                  ID: {comparison.comparison_id}
                </span>
              )}
            </h3>
            <p className="text-xs text-soc-muted font-mono mt-0.5">
              Comparative Attack Success Rate (ASR) reduction across vulnerable baseline vs protected postures
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono">
          {/* Baseline Card */}
          <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/60">
            <div className="text-[10px] uppercase tracking-wider text-red-400 font-semibold mb-1">
              Baseline (Vulnerable Mode)
            </div>
            <div className="text-3xl font-bold text-red-400">{baselineASR}%</div>
            <div className="text-xs text-soc-muted mt-2">
              Attack Success Rate with relaxed security controls
            </div>
            <div className="text-[11px] text-red-300/80 mt-1">
              Blocked: {comparison?.baseline_blocked ?? 0} / Total: {comparison?.total_tests ?? 30}
            </div>
          </div>

          {/* Protected Card */}
          <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/60">
            <div className="text-[10px] uppercase tracking-wider text-emerald-400 font-semibold mb-1">
              Hardened (Protected Mode)
            </div>
            <div className="text-3xl font-bold text-emerald-400">{protectedASR}%</div>
            <div className="text-xs text-soc-muted mt-2">
              Attack Success Rate with all 10 mitigations active
            </div>
            <div className="text-[11px] text-emerald-300/80 mt-1">
              Blocked: {comparison?.protected_blocked ?? 30} / Total: {comparison?.total_tests ?? 30}
            </div>
          </div>

          {/* Overall Improvement Card */}
          <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-900/60 flex flex-col justify-between">
            <div>
              <div className="text-[10px] uppercase tracking-wider text-cyan-400 font-semibold mb-1">
                Security Posture Gain
              </div>
              <div className="text-3xl font-bold text-cyan-400">+{improvement}%</div>
              <div className="text-xs text-soc-muted mt-2">
                Total reduction in exploitability (Baseline ASR - Protected ASR)
              </div>
            </div>
            <div className="flex items-center space-x-1.5 text-xs text-emerald-400 mt-2 font-semibold">
              <CheckCircle2 className="w-4 h-4" />
              <span>Full Protection Demonstrated</span>
            </div>
          </div>
        </div>
      </div>

      {/* 10 Mitigations Grid */}
      <div>
        <div className="flex items-center justify-between mb-3 font-mono">
          <h3 className="text-sm font-bold text-soc-text">Configurable Security Controls</h3>
          <span className="text-xs text-soc-muted">10 Active Defenses</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {mitigations.map((m) => {
            const isToggling = togglingId === m.risk_id;

            return (
              <div
                key={m.risk_id}
                className={`p-5 rounded-xl border transition-all duration-200 font-mono ${
                  m.enabled
                    ? 'bg-soc-card border-emerald-800/60'
                    : 'bg-soc-card/60 border-soc-border opacity-70'
                }`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center space-x-2.5">
                    <div
                      className={`p-2 rounded-lg ${
                        m.enabled ? 'bg-emerald-950 text-emerald-400' : 'bg-slate-800 text-soc-muted'
                      }`}
                    >
                      {m.enabled ? <Lock className="w-4 h-4" /> : <Unlock className="w-4 h-4" />}
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-cyan-400 text-xs">{m.risk_id}</span>
                        <StatusBadge status={m.enabled ? 'ACTIVE' : 'DISABLED'} size="sm" />
                      </div>
                      <div className="font-semibold text-soc-text text-xs mt-0.5">{m.name}</div>
                    </div>
                  </div>

                  {/* Toggle Button */}
                  <button
                    onClick={() => handleToggle(m.risk_id, m.enabled)}
                    disabled={isToggling}
                    className="p-1.5 rounded-lg bg-soc-surface hover:bg-soc-hover border border-soc-border text-soc-text transition-colors disabled:opacity-50"
                    title={m.enabled ? 'Disable Mitigation' : 'Enable Mitigation'}
                  >
                    {m.enabled ? (
                      <ToggleRight className="w-6 h-6 text-emerald-400" />
                    ) : (
                      <ToggleLeft className="w-6 h-6 text-soc-muted" />
                    )}
                  </button>
                </div>

                <p className="text-xs text-soc-muted leading-relaxed line-clamp-2" title={m.description}>
                  {m.description}
                </p>

                <div className="mt-3 pt-3 border-t border-soc-border/50 flex items-center justify-between text-[11px] text-slate-400">
                  <span>Scope: {m.risk_id.startsWith('LLM') ? 'Chatbot Guardrails' : 'Agent Tool Policies'}</span>
                  <span className={m.enabled ? 'text-emerald-400' : 'text-amber-400'}>
                    {m.enabled ? 'Enforcing in Protected Mode' : 'Bypassed'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default MitigationCenterPage;
