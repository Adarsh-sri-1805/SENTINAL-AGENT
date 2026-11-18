import React from 'react';
import { X, ShieldAlert, Terminal, FileText, CheckCircle2 } from 'lucide-react';
import StatusBadge from './StatusBadge';

export const EvidenceModal = ({ isOpen, onClose, data }) => {
  if (!isOpen || !data) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-hidden rounded-2xl bg-soc-surface border border-soc-border shadow-2xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-soc-border bg-soc-card">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-800/60 text-cyan-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-mono text-xs text-soc-muted">{data.test_id || data.event_id}</span>
                <StatusBadge status={data.result || data.classification || data.status} size="sm" />
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-soc-muted font-mono">
                  {data.mode || data.security_mode}
                </span>
              </div>
              <h3 className="text-base font-semibold text-soc-text mt-0.5">
                {data.test_name || data.event_type || 'Security Event Evidence'}
              </h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-soc-muted hover:text-soc-text hover:bg-soc-hover transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-sm">
          {/* Rationale / Explanation */}
          <div>
            <h4 className="text-xs font-mono uppercase tracking-wider text-soc-muted mb-2 flex items-center space-x-1.5">
              <CheckCircle2 className="w-4 h-4 text-cyan-400" />
              <span>Evaluation Rationale & Decision</span>
            </h4>
            <div className="p-3.5 rounded-xl bg-soc-card border border-soc-border text-soc-text font-mono text-xs leading-relaxed">
              {data.evaluation_explanation || data.details || 'No additional rationale provided.'}
            </div>
          </div>

          {/* Attack Input / Prompt */}
          {data.prompt && (
            <div>
              <h4 className="text-xs font-mono uppercase tracking-wider text-soc-muted mb-2 flex items-center space-x-1.5">
                <Terminal className="w-4 h-4 text-red-400" />
                <span>Adversarial Attack Input / Prompt</span>
              </h4>
              <div className="p-3.5 rounded-xl bg-soc-card border border-soc-border text-red-300 font-mono text-xs whitespace-pre-wrap overflow-x-auto max-h-48">
                {data.prompt}
              </div>
            </div>
          )}

          {/* Model or Target Response */}
          {data.response && (
            <div>
              <h4 className="text-xs font-mono uppercase tracking-wider text-soc-muted mb-2 flex items-center space-x-1.5">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span>Model Output / Agent Response</span>
              </h4>
              <div className="p-3.5 rounded-xl bg-soc-card border border-soc-border text-slate-300 font-mono text-xs whitespace-pre-wrap overflow-x-auto max-h-56">
                {data.response}
              </div>
            </div>
          )}

          {/* Tool Invocations Evidence */}
          {data.tool_evidence && data.tool_evidence.length > 0 && (
            <div>
              <h4 className="text-xs font-mono uppercase tracking-wider text-soc-muted mb-2 flex items-center space-x-1.5">
                <Terminal className="w-4 h-4 text-amber-400" />
                <span>Tool Calling Trace & Arguments</span>
              </h4>
              <div className="p-3.5 rounded-xl bg-soc-card border border-soc-border space-y-2">
                {data.tool_evidence.map((tool, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-soc-bg border border-soc-border font-mono text-xs">
                    <div className="flex items-center justify-between text-amber-400 font-semibold mb-1">
                      <span>Tool: {tool.tool_name || tool.name}</span>
                      <span className="text-soc-muted text-[10px]">Call #{idx + 1}</span>
                    </div>
                    <pre className="text-slate-400 text-[11px] overflow-x-auto">
                      {JSON.stringify(tool.arguments || tool.args, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Structured Evidence Payload */}
          {data.evidence && Object.keys(data.evidence).length > 0 && (
            <div>
              <h4 className="text-xs font-mono uppercase tracking-wider text-soc-muted mb-2 flex items-center space-x-1.5">
                <FileText className="w-4 h-4 text-emerald-400" />
                <span>Evidence Collector Telemetry</span>
              </h4>
              <div className="p-3.5 rounded-xl bg-soc-card border border-soc-border">
                <pre className="font-mono text-xs text-emerald-300 overflow-x-auto max-h-48">
                  {typeof data.evidence === 'string'
                    ? data.evidence
                    : JSON.stringify(data.evidence, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end px-6 py-3 border-t border-soc-border bg-soc-card">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-mono font-medium rounded-lg bg-soc-hover text-soc-text hover:bg-slate-700 transition-colors"
          >
            Close Evidence Inspector
          </button>
        </div>
      </div>
    </div>
  );
};

export default EvidenceModal;
