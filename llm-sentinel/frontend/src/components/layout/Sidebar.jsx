import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  LayoutDashboard,
  BrainCircuit,
  Bot,
  ShieldCheck,
  Network,
  FileBarChart,
  Radio,
  Lock,
} from 'lucide-react';

const NAV_ITEMS = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/llm-security', label: 'LLM Security Testing', icon: BrainCircuit, badge: '15' },
  { path: '/agentic-ai', label: 'Agentic AI Security', icon: Bot, badge: '15' },
  { path: '/mitigations', label: 'Mitigation Center', icon: ShieldCheck, badge: '10' },
  { path: '/mcp-security', label: 'MCP Security', icon: Network, badge: 'POC' },
  { path: '/reports', label: 'Results & Reports', icon: FileBarChart },
  { path: '/wazuh', label: 'Wazuh SIEM', icon: Radio, alert: true },
];

export const Sidebar = ({ securityMode, wazuhConnected }) => {
  return (
    <aside className="w-64 bg-soc-surface border-r border-soc-border flex flex-col h-screen select-none sticky top-0">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-6 border-b border-soc-border space-x-3 bg-soc-card">
        <div className="p-2 rounded-xl bg-cyan-950/80 border border-cyan-800/80 text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.3)]">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div>
          <h1 className="text-sm font-bold tracking-wider text-soc-text font-mono flex items-center space-x-1">
            <span>LLM</span>
            <span className="text-cyan-400">SENTINEL</span>
          </h1>
          <p className="text-[10px] font-mono text-soc-muted tracking-tight">AI SECURITY SOC POC</p>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-wider text-soc-muted">
          Security Modules
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-mono transition-all duration-150 ${
                  isActive
                    ? 'bg-cyan-950/60 text-cyan-400 border border-cyan-800/80 shadow-[0_0_12px_rgba(6,182,212,0.15)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-soc-hover border border-transparent'
                }`
              }
            >
              <div className="flex items-center space-x-3">
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-soc-card border border-soc-border text-soc-muted font-mono">
                  {item.badge}
                </span>
              )}
              {item.alert && (
                <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" title="SIEM Integration" />
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Security Posture Footer */}
      <div className="p-4 border-t border-soc-border bg-soc-card/70 space-y-2.5">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-soc-muted">Active Posture:</span>
          <span
            className={`font-semibold px-2 py-0.5 rounded text-[11px] ${
              securityMode === 'protected'
                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                : 'bg-red-950 text-red-400 border border-red-800'
            }`}
          >
            {securityMode ? securityMode.toUpperCase() : 'LOADING...'}
          </span>
        </div>

        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-soc-muted">Wazuh SIEM:</span>
          <span className="flex items-center space-x-1.5 text-soc-muted text-[11px]">
            <span
              className={`w-2 h-2 rounded-full ${
                wazuhConnected ? 'bg-emerald-500 shadow-[0_0_6px_#10b981]' : 'bg-red-500'
              }`}
            />
            <span>{wazuhConnected ? 'CONNECTED' : 'NOT CONNECTED'}</span>
          </span>
        </div>

        <div className="pt-2 text-[10px] font-mono text-slate-500 text-center border-t border-soc-border/50">
          OWASP LLM & Agentic AI 2026
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
