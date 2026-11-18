import React from 'react';
import { Shield, ShieldAlert, RefreshCw, Activity, Terminal } from 'lucide-react';

export const Header = ({
  title,
  subtitle,
  securityMode,
  onToggleMode,
  onRefresh,
  isRefreshing,
}) => {
  return (
    <header className="h-16 px-8 border-b border-soc-border bg-soc-surface/80 backdrop-blur-md flex items-center justify-between sticky top-0 z-30">
      {/* Title & Context */}
      <div>
        <h2 className="text-base font-bold text-soc-text tracking-tight font-mono flex items-center space-x-2">
          <span>{title}</span>
        </h2>
        {subtitle && <p className="text-xs text-soc-muted font-mono">{subtitle}</p>}
      </div>

      {/* Controls & Badges */}
      <div className="flex items-center space-x-4">
        {/* Security Posture Switch */}
        <div className="flex items-center space-x-2 p-1 rounded-xl bg-soc-card border border-soc-border text-xs font-mono">
          <button
            onClick={() => onToggleMode && onToggleMode('vulnerable')}
            className={`px-3 py-1.5 rounded-lg transition-all flex items-center space-x-1.5 ${
              securityMode === 'vulnerable'
                ? 'bg-red-950/80 text-red-300 border border-red-700/80 shadow-[0_0_8px_rgba(239,68,68,0.3)] font-semibold'
                : 'text-soc-muted hover:text-slate-300'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Vulnerable</span>
          </button>
          <button
            onClick={() => onToggleMode && onToggleMode('protected')}
            className={`px-3 py-1.5 rounded-lg transition-all flex items-center space-x-1.5 ${
              securityMode === 'protected'
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 shadow-[0_0_8px_rgba(16,185,129,0.3)] font-semibold'
                : 'text-soc-muted hover:text-slate-300'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Protected</span>
          </button>
        </div>

        {/* Engine Status Indicator */}
        <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-soc-card border border-soc-border text-xs font-mono text-soc-muted">
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>Engine: <span className="text-emerald-400 font-semibold">ONLINE</span></span>
        </div>

        {/* Refresh Button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-xl bg-soc-card border border-soc-border text-soc-muted hover:text-soc-text hover:bg-soc-hover transition-colors disabled:opacity-50"
            title="Refresh Telemetry"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        )}
      </div>
    </header>
  );
};

export default Header;
