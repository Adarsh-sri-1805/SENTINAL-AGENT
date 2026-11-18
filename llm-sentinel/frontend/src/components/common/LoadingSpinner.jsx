import React from 'react';
import { Loader2 } from 'lucide-react';

export const LoadingSpinner = ({ message = 'Loading security telemetry...' }) => {
  return (
    <div className="flex flex-col items-center justify-center py-16 space-y-4">
      <div className="relative">
        <Loader2 className="w-10 h-10 text-cyan-400 animate-spin" />
        <div className="absolute inset-0 rounded-full blur-md bg-cyan-500/20" />
      </div>
      <p className="text-sm font-mono text-soc-muted tracking-wide animate-pulse">{message}</p>
    </div>
  );
};

export default LoadingSpinner;
