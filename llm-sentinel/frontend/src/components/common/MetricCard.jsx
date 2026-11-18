import React from 'react';

export const MetricCard = ({ title, value, subtitle, icon: Icon, trend, variant = 'default' }) => {
  const borderVariants = {
    default: 'border-soc-border hover:border-slate-600',
    accent: 'border-cyan-800/60 bg-gradient-to-br from-soc-card to-cyan-950/20 hover:border-cyan-600/80',
    success: 'border-emerald-800/60 bg-gradient-to-br from-soc-card to-emerald-950/20 hover:border-emerald-600/80',
    danger: 'border-red-800/60 bg-gradient-to-br from-soc-card to-red-950/20 hover:border-red-600/80',
    warning: 'border-amber-800/60 bg-gradient-to-br from-soc-card to-amber-950/20 hover:border-amber-600/80',
  };

  const iconColors = {
    default: 'text-soc-muted bg-slate-800/60',
    accent: 'text-cyan-400 bg-cyan-950/50 border border-cyan-800/50',
    success: 'text-emerald-400 bg-emerald-950/50 border border-emerald-800/50',
    danger: 'text-red-400 bg-red-950/50 border border-red-800/50',
    warning: 'text-amber-400 bg-amber-950/50 border border-amber-800/50',
  };

  return (
    <div
      className={`relative p-5 rounded-xl bg-soc-card border transition-all duration-200 ${
        borderVariants[variant] || borderVariants.default
      }`}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium uppercase tracking-wider text-soc-muted font-mono">{title}</span>
        {Icon && (
          <div className={`p-2 rounded-lg ${iconColors[variant] || iconColors.default}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>

      <div className="flex items-baseline space-x-2">
        <span className="text-3xl font-bold font-mono tracking-tight text-soc-text">{value}</span>
        {trend && (
          <span
            className={`text-xs font-mono font-medium ${
              trend.positive ? 'text-emerald-400' : 'text-red-400'
            }`}
          >
            {trend.text}
          </span>
        )}
      </div>

      {subtitle && <p className="mt-2 text-xs text-soc-muted truncate">{subtitle}</p>}
    </div>
  );
};

export default MetricCard;
