import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  AlertTriangle,
  Zap,
  TrendingDown,
  ChevronRight,
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

import MetricCard from '../components/common/MetricCard';
import StatusBadge from '../components/common/StatusBadge';
import LoadingSpinner from '../components/common/LoadingSpinner';
import EvidenceModal from '../components/common/EvidenceModal';
import {
  getDashboardOverview,
  getRiskDistribution,
  getRecentEvents,
} from '../api/client';

export const OverviewPage = () => {
  const [loading, setLoading] = useState(true);
  const [overview, setOverview] = useState(null);
  const [distribution, setDistribution] = useState([]);
  const [recentEvents, setRecentEvents] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [error, setError] = useState(null);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [ovData, distData, eventsData] = await Promise.all([
        getDashboardOverview(),
        getRiskDistribution(),
        getRecentEvents(12),
      ]);
      setOverview(ovData);
      setDistribution(distData);
      setRecentEvents(eventsData);
    } catch (err) {
      setError(err.message || 'Failed to load dashboard telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  if (loading) return <LoadingSpinner message="Querying SOC dashboard metrics from SQLite..." />;

  // Chart data preparation
  const outcomeData = [
    { name: 'Blocked', value: overview?.blocked || 0, color: '#10b981' },
    { name: 'Partial', value: overview?.partial || 0, color: '#f59e0b' },
    { name: 'Succeeded', value: overview?.succeeded || 0, color: '#ef4444' },
  ].filter((item) => item.value > 0);

  // Group distribution by primary categories for clearer bar chart
  const topRisks = distribution.filter((d) => d.total > 0).slice(0, 10);

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-4 rounded-xl bg-red-950/60 border border-red-800 text-red-200 text-xs font-mono">
          <AlertTriangle className="w-4 h-4 inline mr-2 text-red-400" />
          {error}
        </div>
      )}

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Tests Run"
          value={overview?.total_tests_executed || 0}
          subtitle="Automated security evaluations across targets"
          icon={Activity}
          variant="default"
        />
        <MetricCard
          title="Attacks Blocked"
          value={overview?.blocked || 0}
          subtitle={`Blocking Rate: ${overview?.blocking_rate || 0}%`}
          icon={ShieldCheck}
          variant="success"
        />
        <MetricCard
          title="Attack Success Rate (ASR)"
          value={`${overview?.attack_success_rate || 0}%`}
          subtitle="Lower indicates stronger security posture"
          icon={ShieldAlert}
          variant={overview?.attack_success_rate > 30 ? 'danger' : 'accent'}
        />
        <MetricCard
          title="Mitigation Effectiveness"
          value={`${overview?.mitigation_effectiveness || 0}%`}
          subtitle="Evaluated across 10 OWASP risk controls"
          icon={TrendingDown}
          variant="accent"
        />
      </div>

      {/* Secondary Status Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex items-center justify-between font-mono text-xs">
          <div>
            <div className="text-soc-muted uppercase text-[10px]">Active Security Mode</div>
            <div className="text-base font-bold text-soc-text capitalize mt-0.5">
              {overview?.active_security_mode}
            </div>
          </div>
          <StatusBadge status={overview?.active_security_mode} size="sm" />
        </div>

        <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex items-center justify-between font-mono text-xs">
          <div>
            <div className="text-soc-muted uppercase text-[10px]">MCP Telemetry Events</div>
            <div className="text-base font-bold text-cyan-400 mt-0.5">
              {overview?.total_mcp_events || 0} Events Logged
            </div>
          </div>
          <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
            STDIO / Memory
          </span>
        </div>

        <div className="p-4 rounded-xl bg-soc-card border border-soc-border flex items-center justify-between font-mono text-xs">
          <div>
            <div className="text-soc-muted uppercase text-[10px]">MCP Security Gain</div>
            <div className="text-base font-bold text-emerald-400 mt-0.5">
              +{overview?.mcp_improvement || 0}% Reduction
            </div>
          </div>
          <StatusBadge status="ACTIVE" size="sm" />
        </div>
      </div>

      {/* Visual Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Chart */}
        <div className="lg:col-span-2 p-5 rounded-2xl bg-soc-card border border-soc-border">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-soc-text font-mono">Risk Distribution & Attack Outcomes</h3>
              <p className="text-xs text-soc-muted font-mono mt-0.5">
                Breakdown of attacks blocked vs succeeded by risk identifier
              </p>
            </div>
          </div>

          <div className="h-72 w-full">
            {topRisks.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topRisks} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="risk_id" stroke="#64748b" fontSize={11} fontFamily="monospace" />
                  <YAxis stroke="#64748b" fontSize={11} fontFamily="monospace" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#111827',
                      borderColor: '#243247',
                      borderRadius: '0.75rem',
                      fontFamily: 'monospace',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="blocked" name="Blocked" fill="#10b981" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="partial" name="Partial" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="succeeded" name="Succeeded" fill="#ef4444" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs font-mono text-soc-muted">
                No attack test results found in SQLite. Run tests from LLM or Agentic modules.
              </div>
            )}
          </div>
        </div>

        {/* Attack Outcome Pie */}
        <div className="p-5 rounded-2xl bg-soc-card border border-soc-border flex flex-col">
          <div>
            <h3 className="text-sm font-bold text-soc-text font-mono">Overall Outcome Split</h3>
            <p className="text-xs text-soc-muted font-mono mt-0.5">Aggregated attack test ratios</p>
          </div>

          <div className="h-56 w-full my-auto">
            {outcomeData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={outcomeData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {outcomeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#111827',
                      borderColor: '#243247',
                      borderRadius: '0.75rem',
                      fontFamily: 'monospace',
                      fontSize: '12px',
                    }}
                  />
                  <Legend
                    formatter={(val) => <span className="font-mono text-xs text-slate-300">{val}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs font-mono text-soc-muted">
                No test data recorded yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Security Events Table */}
      <div className="p-5 rounded-2xl bg-soc-card border border-soc-border">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-soc-text font-mono">Recent Security Events & Audit Feed</h3>
            <p className="text-xs text-soc-muted font-mono mt-0.5">
              Live audit stream of attack evaluations, tool invocations, and MCP policy decisions
            </p>
          </div>
          <button
            onClick={fetchDashboardData}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            Refresh Feed
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-soc-border text-soc-muted text-[11px] uppercase tracking-wider">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">Risk ID</th>
                <th className="py-2.5 px-3">Outcome</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Details</th>
                <th className="py-2.5 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/50">
              {recentEvents.length > 0 ? (
                recentEvents.map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-soc-hover/50 transition-colors">
                    <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                      {ev.timestamp ? ev.timestamp.replace('T', ' ').slice(0, 19) : '-'}
                    </td>
                    <td className="py-3 px-3 text-slate-300 font-semibold">{ev.source}</td>
                    <td className="py-3 px-3 text-cyan-400">{ev.risk_id || '-'}</td>
                    <td className="py-3 px-3">
                      <StatusBadge status={ev.status} size="sm" />
                    </td>
                    <td className="py-3 px-3">
                      <span className="text-[11px] text-slate-300 font-mono">{ev.action_taken}</span>
                    </td>
                    <td className="py-3 px-3 text-slate-400 truncate max-w-xs" title={ev.details}>
                      {ev.details}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => setSelectedEvent(ev)}
                        className="px-2.5 py-1 rounded-lg bg-soc-surface border border-soc-border text-cyan-400 hover:text-cyan-300 hover:border-cyan-700 transition-colors text-[11px]"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-soc-muted font-mono text-xs">
                    No security events logged yet. Execute tests in LLM, Agentic, or MCP modules.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Evidence Modal */}
      <EvidenceModal
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        data={selectedEvent}
      />
    </div>
  );
};

export default OverviewPage;
