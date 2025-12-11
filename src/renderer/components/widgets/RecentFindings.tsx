import { useState } from 'react';
import { formatDistanceToNow } from 'date-fns';
import { AlertTriangle, AlertCircle, Info, ShieldCheck, Wrench, ChevronDown, ChevronUp, ExternalLink, Sparkles } from 'lucide-react';

interface Finding {
  id: string;
  title: string;
  severity: string;
  tool: string;
  timestamp: string;
  description?: string;
  remediation?: string;
  file?: string;
  line?: number;
}

interface RecentFindingsProps {
  findings: Finding[];
  onFix?: (finding: Finding) => void;
}

export default function RecentFindings({ findings, onFix }: RecentFindingsProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [fixingId, setFixingId] = useState<string | null>(null);

  const getSeverityConfig = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return {
          icon: AlertTriangle,
          color: 'text-alert-critical',
          bg: 'bg-alert-critical/10',
          border: 'border-alert-critical/30'
        };
      case 'high':
        return {
          icon: AlertCircle,
          color: 'text-alert-high',
          bg: 'bg-alert-high/10',
          border: 'border-alert-high/30'
        };
      case 'medium':
        return {
          icon: AlertCircle,
          color: 'text-alert-warning',
          bg: 'bg-alert-warning/10',
          border: 'border-alert-warning/30'
        };
      case 'low':
        return {
          icon: Info,
          color: 'text-dws-green',
          bg: 'bg-dws-green/10',
          border: 'border-dws-green/30'
        };
      default:
        return {
          icon: ShieldCheck,
          color: 'text-gray-400',
          bg: 'bg-gray-500/10',
          border: 'border-gray-500/30'
        };
    }
  };

  const handleFix = async (finding: Finding) => {
    setFixingId(finding.id);
    try {
      if (onFix) {
        await onFix(finding);
      }
    } finally {
      setFixingId(null);
    }
  };

  if (findings.length === 0) {
    return (
      <div className="text-center py-8">
        <ShieldCheck className="w-12 h-12 text-dws-green mx-auto mb-3" />
        <p className="text-gray-400">No findings detected</p>
        <p className="text-gray-500 text-sm">Your codebase is secure!</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {findings.map((finding) => {
        const config = getSeverityConfig(finding.severity);
        const Icon = config.icon;
        const isExpanded = expandedId === finding.id;
        const isFixing = fixingId === finding.id;

        return (
          <div
            key={finding.id}
            className={`
              rounded-lg overflow-hidden
              ${config.bg} border ${config.border}
              transition-all
            `}
          >
            {/* Main Row - Clickable to expand */}
            <div
              onClick={() => setExpandedId(isExpanded ? null : finding.id)}
              className="flex items-center gap-4 p-3 hover:bg-dws-card/50 transition-colors cursor-pointer"
            >
              {/* Severity Icon */}
              <div className={`p-2 rounded-lg ${config.bg}`}>
                <Icon size={18} className={config.color} />
              </div>

              {/* Finding Details */}
              <div className="flex-1 min-w-0">
                <p className="text-white font-medium truncate">{finding.title}</p>
                <div className="flex items-center gap-3 mt-1">
                  <span className={`text-xs font-medium uppercase ${config.color}`}>
                    {finding.severity}
                  </span>
                  <span className="text-xs text-gray-500">
                    {finding.tool}
                  </span>
                  {finding.file && (
                    <span className="text-xs text-joe-blue truncate max-w-[150px]">
                      {finding.file}
                    </span>
                  )}
                </div>
              </div>

              {/* Fix Button - Stop propagation to prevent expand/collapse */}
              {onFix && (finding.severity === 'critical' || finding.severity === 'high' || finding.severity === 'medium') && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleFix(finding);
                  }}
                  disabled={isFixing}
                  className="flex items-center gap-1 px-3 py-1.5 bg-gradient-to-r from-dws-green to-joe-blue text-white text-xs font-medium rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50"
                >
                  {isFixing ? (
                    <>
                      <Sparkles size={14} className="animate-pulse" />
                      Fixing...
                    </>
                  ) : (
                    <>
                      <Wrench size={14} />
                      Fix
                    </>
                  )}
                </button>
              )}

              {/* Expand/Collapse */}
              <div className="text-gray-500">
                {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
              </div>

              {/* Timestamp */}
              <div className="text-right min-w-[80px]">
                <p className="text-xs text-gray-500">
                  {formatDistanceToNow(new Date(finding.timestamp), { addSuffix: true })}
                </p>
              </div>
            </div>

            {/* Expanded Details */}
            {isExpanded && (
              <div className="px-4 pb-4 pt-2 border-t border-dws-border/30 space-y-3">
                {finding.description && (
                  <div>
                    <p className="text-xs text-gray-500 uppercase mb-1">Description</p>
                    <p className="text-sm text-gray-300">{finding.description}</p>
                  </div>
                )}

                {finding.file && (
                  <div>
                    <p className="text-xs text-gray-500 uppercase mb-1">Location</p>
                    <p className="text-sm text-joe-blue font-mono">
                      {finding.file}{finding.line ? `:${finding.line}` : ''}
                    </p>
                  </div>
                )}

                {finding.remediation && (
                  <div>
                    <p className="text-xs text-gray-500 uppercase mb-1">Remediation</p>
                    <div className="bg-dws-dark p-3 rounded-lg">
                      <p className="text-sm text-dws-green font-mono">{finding.remediation}</p>
                    </div>
                  </div>
                )}

                <div className="flex gap-2 pt-2">
                  {onFix && (
                    <button
                      type="button"
                      onClick={() => handleFix(finding)}
                      disabled={isFixing}
                      className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-dws-green to-joe-blue text-white text-sm font-medium rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50"
                    >
                      {isFixing ? (
                        <>
                          <Sparkles size={16} className="animate-pulse" />
                          Applying Fix...
                        </>
                      ) : (
                        <>
                          <Wrench size={16} />
                          Apply Fix
                        </>
                      )}
                    </button>
                  )}
                  {finding.file && (
                    <button type="button" className="flex items-center gap-2 px-4 py-2 bg-dws-card text-gray-300 text-sm rounded-lg hover:bg-dws-border transition-colors">
                      <ExternalLink size={16} />
                      View File
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
