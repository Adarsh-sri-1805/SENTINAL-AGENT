import React from 'react';

export const StatusBadge = ({ status, size = 'md' }) => {
  const norm = String(status || '').toUpperCase();

  const styles = {
    BLOCKED: 'bg-emerald-950/70 text-emerald-400 border-emerald-700/60 shadow-[0_0_8px_rgba(16,185,129,0.2)]',
    PARTIAL: 'bg-amber-950/70 text-amber-400 border-amber-700/60 shadow-[0_0_8px_rgba(245,158,11,0.2)]',
    SUCCEEDED: 'bg-red-950/70 text-red-400 border-red-700/60 shadow-[0_0_8px_rgba(239,68,68,0.2)]',
    PERMITTED: 'bg-blue-950/70 text-blue-400 border-blue-700/60',
    DENIED: 'bg-red-950/70 text-red-400 border-red-700/60',
    PROTECTED: 'bg-cyan-950/70 text-cyan-400 border-cyan-700/60',
    VULNERABLE: 'bg-orange-950/70 text-orange-400 border-orange-700/60',
    ACTIVE: 'bg-emerald-950/70 text-emerald-400 border-emerald-700/60',
    CONNECTED: 'bg-emerald-950/70 text-emerald-400 border-emerald-700/60',
    'NOT CONNECTED': 'bg-red-950/70 text-red-400 border-red-700/60',
    HIGH: 'bg-red-950/70 text-red-400 border-red-700/60',
    CRITICAL: 'bg-rose-950/80 text-rose-300 border-rose-600/80 shadow-[0_0_10px_rgba(244,63,94,0.3)]',
    MEDIUM: 'bg-amber-950/70 text-amber-400 border-amber-700/60',
    LOW: 'bg-slate-900 text-slate-300 border-slate-700',
  };

  const currentStyle = styles[norm] || 'bg-slate-900 text-slate-300 border-slate-700';

  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-xs' : size === 'lg' ? 'px-3.5 py-1 text-sm' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center font-mono font-medium rounded-full border transition-all ${sizeClass} ${currentStyle}`}
    >
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current opacity-80" />
      {norm}
    </span>
  );
};

export default StatusBadge;
