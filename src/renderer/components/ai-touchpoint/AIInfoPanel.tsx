/**
 * J.O.E. DevSecOps Arsenal - AI Info Panel
 * ES6+ Deep-dive analysis panel with streaming AI, attack paths, and remediation
 *
 * @module components/ai-touchpoint/AIInfoPanel
 * @version 1.0.0
 */

import React, { useState, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X,
  Brain,
  Shield,
  Target,
  Wrench,
  BookOpen,
  Loader2,
  AlertCircle,
  ChevronRight,
  Copy,
  Check,
  Star,
  StarOff,
  ExternalLink,
  Play,
  Code,
  GitBranch,
  Zap
} from 'lucide-react';
import { CitationList } from './SourceCitationBadge';
import type {
  AITouchpointResponse,
  AIStreamController,
  RemediationStep,
  MermaidDiagram
} from '../../../types/ai-touchpoint';

// =============================================================================
// TYPES
// =============================================================================

export interface AIInfoPanelProps {
  /** Element ID this panel is for */
  elementId: string;

  /** AI response data */
  response: AITouchpointResponse | null;

  /** Loading state */
  isLoading: boolean;

  /** Stream controller for live updates */
  streamController?: AIStreamController;

  /** Error state */
  error: Error | null;

  /** Close handler */
  onClose: () => void;

  /** Rate response handler */
  onRate: (rating: number) => void;

  /** Apply fix handler */
  onApplyFix?: (step: RemediationStep) => void;
}

// =============================================================================
// TABS
// =============================================================================

type TabId = 'overview' | 'attackPath' | 'remediation' | 'sources';

interface Tab {
  id: TabId;
  label: string;
  icon: React.ElementType;
}

const TABS: Tab[] = [
  { id: 'overview', label: 'Overview', icon: Brain },
  { id: 'attackPath', label: 'Attack Path', icon: Target },
  { id: 'remediation', label: 'Remediation', icon: Wrench },
  { id: 'sources', label: 'Sources', icon: BookOpen }
];

// =============================================================================
// ANIMATIONS
// =============================================================================

const panelVariants = {
  hidden: {
    x: '100%',
    opacity: 0
  },
  visible: {
    x: 0,
    opacity: 1,
    transition: {
      type: 'spring',
      damping: 30,
      stiffness: 300
    }
  },
  exit: {
    x: '100%',
    opacity: 0,
    transition: { duration: 0.2 }
  }
};

const backdropVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1 },
  exit: { opacity: 0 }
};

// =============================================================================
// COMPONENT
// =============================================================================

export const AIInfoPanel: React.FC<AIInfoPanelProps> = ({
  elementId,
  response,
  isLoading,
  streamController,
  error,
  onClose,
  onRate,
  onApplyFix
}) => {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [userRating, setUserRating] = useState<number>(0);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [streamedText, setStreamedText] = useState('');

  // ==========================================================================
  // STREAMING HANDLER
  // ==========================================================================

  useEffect(() => {
    if (streamController) {
      streamController.onChunk((chunk) => {
        setStreamedText(prev => prev + chunk.content);
      });
    }
  }, [streamController]);

  // ==========================================================================
  // KEYBOARD HANDLER
  // ==========================================================================

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // ==========================================================================
  // HANDLERS
  // ==========================================================================

  const handleRate = useCallback((rating: number) => {
    setUserRating(rating);
    onRate(rating);
  }, [onRate]);

  const handleCopyCode = useCallback(async (code: string, id: string) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedCode(id);
      setTimeout(() => setCopiedCode(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  }, []);

  // ==========================================================================
  // RENDER TAB CONTENT
  // ==========================================================================

  const renderOverview = () => (
    <div className="space-y-6">
      {/* Summary */}
      <div className="space-y-3">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
          <Brain className="w-5 h-5 text-joe-blue" />
          Analysis Summary
        </h3>
        <div className="text-gray-300 leading-relaxed">
          {isLoading && !response ? (
            <div className="flex items-center gap-3">
              <Loader2 className="w-5 h-5 text-joe-blue animate-spin" />
              <span className="text-gray-400">Analyzing security context...</span>
            </div>
          ) : (
            <p>{response?.summary}</p>
          )}
        </div>
      </div>

      {/* Detailed Analysis */}
      {response?.detailedAnalysis && (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-dws-green" />
            Detailed Analysis
          </h3>
          <div
            className="text-gray-300 leading-relaxed prose prose-invert prose-sm max-w-none"
            dangerouslySetInnerHTML={{
              __html: formatMarkdown(streamedText || response.detailedAnalysis)
            }}
          />
        </div>
      )}

      {/* Confidence & Metrics */}
      {response && (
        <div className="grid grid-cols-3 gap-4">
          <div className="p-4 rounded-lg bg-dws-elevated border border-dws-border">
            <p className="text-xs text-gray-500 mb-1">Confidence</p>
            <p className="text-2xl font-bold text-joe-blue">{response.confidence}%</p>
          </div>
          <div className="p-4 rounded-lg bg-dws-elevated border border-dws-border">
            <p className="text-xs text-gray-500 mb-1">Citations</p>
            <p className="text-2xl font-bold text-dws-green">{response.citations.length}</p>
          </div>
          <div className="p-4 rounded-lg bg-dws-elevated border border-dws-border">
            <p className="text-xs text-gray-500 mb-1">Response Time</p>
            <p className="text-2xl font-bold text-gray-300">{response.responseTime}ms</p>
          </div>
        </div>
      )}

      {/* Top Citations */}
      {response?.citations && response.citations.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-gray-400">Key Framework References</h4>
          <CitationList
            citations={response.citations.slice(0, 6)}
            size="md"
          />
        </div>
      )}
    </div>
  );

  const renderAttackPath = () => (
    <div className="space-y-6">
      <h3 className="text-lg font-semibold text-white flex items-center gap-2">
        <Target className="w-5 h-5 text-alert-critical" />
        Attack Path Analysis
      </h3>

      {response?.attackPath ? (
        <div className="space-y-4">
          {/* Mermaid Diagram */}
          <div className="p-4 rounded-lg bg-dws-dark border border-dws-border">
            <MermaidRenderer diagram={response.attackPath} />
          </div>

          {/* Attack Path Steps */}
          <div className="space-y-3">
            {response.attackPath.nodes.map((node, index) => (
              <motion.div
                key={node.id}
                className="flex items-start gap-3 p-3 rounded-lg bg-dws-elevated border border-dws-border"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <div className={`
                  w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0
                  ${node.severity === 'critical' ? 'bg-alert-critical/20 text-alert-critical' :
                    node.severity === 'high' ? 'bg-alert-high/20 text-alert-high' :
                    node.severity === 'medium' ? 'bg-alert-warning/20 text-alert-warning' :
                    'bg-gray-500/20 text-gray-400'}
                `}>
                  {index + 1}
                </div>
                <div className="flex-1">
                  <p className="font-medium text-white">{node.label}</p>
                  {node.mitreTechnique && (
                    <p className="text-xs text-gray-500 mt-1">
                      MITRE ATT&CK: {node.mitreTechnique}
                    </p>
                  )}
                </div>
                {index < response.attackPath!.nodes.length - 1 && (
                  <ChevronRight className="w-5 h-5 text-gray-600" />
                )}
              </motion.div>
            ))}
          </div>
        </div>
      ) : (
        <div className="text-center py-12 text-gray-500">
          <Target className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>Attack path analysis not available for this element.</p>
          <p className="text-sm mt-1">Try a deeper analysis on a specific vulnerability.</p>
        </div>
      )}
    </div>
  );

  const renderRemediation = () => (
    <div className="space-y-6">
      <h3 className="text-lg font-semibold text-white flex items-center gap-2">
        <Wrench className="w-5 h-5 text-dws-green" />
        Remediation Steps
      </h3>

      {response?.remediationSteps && response.remediationSteps.length > 0 ? (
        <div className="space-y-4">
          {response.remediationSteps.map((step, index) => (
            <motion.div
              key={step.order}
              className="p-4 rounded-lg bg-dws-elevated border border-dws-border"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              {/* Step Header */}
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-joe-blue/20 text-joe-blue flex items-center justify-center font-bold">
                    {step.order}
                  </div>
                  <div>
                    <h4 className="font-medium text-white">{step.title}</h4>
                    <div className="flex items-center gap-2 mt-1">
                      <span className={`
                        text-xs px-2 py-0.5 rounded-full
                        ${step.difficulty === 'trivial' ? 'bg-green-500/20 text-green-400' :
                          step.difficulty === 'easy' ? 'bg-blue-500/20 text-blue-400' :
                          step.difficulty === 'moderate' ? 'bg-yellow-500/20 text-yellow-400' :
                          step.difficulty === 'complex' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-red-500/20 text-red-400'}
                      `}>
                        {step.difficulty}
                      </span>
                      <span className="text-xs text-gray-500">{step.estimatedTime}</span>
                    </div>
                  </div>
                </div>

                {onApplyFix && (
                  <button
                    onClick={() => onApplyFix(step)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-dws-green/20 text-dws-green hover:bg-dws-green/30 transition-colors text-sm"
                  >
                    <Play className="w-4 h-4" />
                    Apply
                  </button>
                )}
              </div>

              {/* Description */}
              <p className="text-sm text-gray-300 mb-3">{step.description}</p>

              {/* Code Snippet */}
              {step.codeSnippet && (
                <div className="space-y-2">
                  {step.codeSnippet.before && (
                    <div className="relative">
                      <div className="flex items-center justify-between px-3 py-1.5 bg-alert-critical/20 rounded-t-lg border-b border-dws-border">
                        <span className="text-xs text-alert-critical font-medium">Before</span>
                        <button
                          onClick={() => handleCopyCode(step.codeSnippet!.before!, `before-${step.order}`)}
                          className="text-gray-500 hover:text-gray-300"
                        >
                          {copiedCode === `before-${step.order}` ? (
                            <Check className="w-4 h-4 text-dws-green" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                      <pre className="p-3 bg-dws-dark rounded-b-lg overflow-x-auto text-sm text-gray-300">
                        <code>{step.codeSnippet.before}</code>
                      </pre>
                    </div>
                  )}

                  <div className="relative">
                    <div className="flex items-center justify-between px-3 py-1.5 bg-dws-green/20 rounded-t-lg border-b border-dws-border">
                      <span className="text-xs text-dws-green font-medium">
                        {step.codeSnippet.before ? 'After' : step.codeSnippet.language}
                      </span>
                      <button
                        onClick={() => handleCopyCode(step.codeSnippet!.after, `after-${step.order}`)}
                        className="text-gray-500 hover:text-gray-300"
                      >
                        {copiedCode === `after-${step.order}` ? (
                          <Check className="w-4 h-4 text-dws-green" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                    <pre className="p-3 bg-dws-dark rounded-b-lg overflow-x-auto text-sm text-gray-300">
                      <code>{step.codeSnippet.after}</code>
                    </pre>
                  </div>
                </div>
              )}

              {/* Command */}
              {step.command && (
                <div className="mt-3 flex items-center gap-2 p-2 rounded-lg bg-dws-dark border border-dws-border">
                  <Code className="w-4 h-4 text-gray-500" />
                  <code className="text-sm text-gray-300 flex-1">{step.command}</code>
                  <button
                    onClick={() => handleCopyCode(step.command!, `cmd-${step.order}`)}
                    className="text-gray-500 hover:text-gray-300"
                  >
                    {copiedCode === `cmd-${step.order}` ? (
                      <Check className="w-4 h-4 text-dws-green" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </div>
              )}
            </motion.div>
          ))}
        </div>
      ) : (
        <div className="text-center py-12 text-gray-500">
          <Wrench className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>No specific remediation steps available.</p>
          <p className="text-sm mt-1">Review the analysis for general guidance.</p>
        </div>
      )}
    </div>
  );

  const renderSources = () => (
    <div className="space-y-6">
      <h3 className="text-lg font-semibold text-white flex items-center gap-2">
        <BookOpen className="w-5 h-5 text-joe-blue" />
        Framework Sources & Citations
      </h3>

      {response?.citations && response.citations.length > 0 ? (
        <div className="space-y-3">
          {response.citations.map((citation, index) => (
            <motion.div
              key={`${citation.framework}-${citation.controlId}-${index}`}
              className="p-4 rounded-lg bg-dws-elevated border border-dws-border hover:border-joe-blue/50 transition-colors"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold text-white">{citation.framework}</span>
                    <span className="text-joe-blue font-mono text-sm">{citation.controlId}</span>
                    <span className={`
                      text-xs px-1.5 py-0.5 rounded
                      ${citation.relevance === 'direct' ? 'bg-green-500/20 text-green-400' :
                        citation.relevance === 'related' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-gray-500/20 text-gray-400'}
                    `}>
                      {citation.relevance}
                    </span>
                  </div>
                  <p className="text-sm text-gray-300">{citation.title}</p>
                  {citation.description && (
                    <p className="text-xs text-gray-500 mt-1">{citation.description}</p>
                  )}
                </div>
                {citation.url && (
                  <a
                    href={citation.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 rounded-lg hover:bg-dws-border transition-colors"
                  >
                    <ExternalLink className="w-4 h-4 text-gray-500" />
                  </a>
                )}
              </div>
            </motion.div>
          ))}
        </div>
      ) : (
        <div className="text-center py-12 text-gray-500">
          <BookOpen className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>No framework citations available.</p>
        </div>
      )}
    </div>
  );

  // ==========================================================================
  // RENDER
  // ==========================================================================

  return (
    <>
      {/* Backdrop */}
      <motion.div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40"
        variants={backdropVariants}
        initial="hidden"
        animate="visible"
        exit="exit"
        onClick={onClose}
      />

      {/* Panel */}
      <motion.div
        className="
          fixed right-0 top-0 bottom-0 z-50
          w-full max-w-2xl
          bg-gradient-to-br from-dws-card to-dws-elevated
          border-l border-dws-border
          shadow-2xl shadow-black/50
          flex flex-col
        "
        variants={panelVariants}
        initial="hidden"
        animate="visible"
        exit="exit"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-dws-border">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-joe-blue/20">
              <Brain className="w-5 h-5 text-joe-blue" />
            </div>
            <div>
              <h2 className="font-semibold text-white">J.O.E. Security Intelligence</h2>
              <p className="text-xs text-gray-500">Deep-dive analysis for {elementId}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-dws-border transition-colors"
            aria-label="Close panel"
          >
            <X className="w-5 h-5 text-gray-400" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 px-6 py-3 border-b border-dws-border bg-dws-dark/50">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`
                flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium
                transition-colors
                ${activeTab === tab.id
                  ? 'bg-joe-blue/20 text-joe-blue'
                  : 'text-gray-400 hover:text-gray-300 hover:bg-dws-border/50'}
              `}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {error ? (
            <div className="flex flex-col items-center justify-center h-full text-center">
              <AlertCircle className="w-12 h-12 text-alert-critical mb-4" />
              <h3 className="text-lg font-semibold text-white mb-2">Analysis Failed</h3>
              <p className="text-gray-400 mb-4">{error.message}</p>
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-lg bg-dws-border text-gray-300 hover:bg-dws-elevated transition-colors"
              >
                Close
              </button>
            </div>
          ) : (
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.2 }}
              >
                {activeTab === 'overview' && renderOverview()}
                {activeTab === 'attackPath' && renderAttackPath()}
                {activeTab === 'remediation' && renderRemediation()}
                {activeTab === 'sources' && renderSources()}
              </motion.div>
            </AnimatePresence>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-dws-border bg-dws-dark/50">
          {/* Rating */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500">Rate this analysis:</span>
            <div className="flex gap-1">
              {[1, 2, 3, 4, 5].map((star) => (
                <button
                  key={star}
                  onClick={() => handleRate(star)}
                  className="p-1 hover:scale-110 transition-transform"
                >
                  {star <= userRating ? (
                    <Star className="w-4 h-4 text-yellow-400 fill-yellow-400" />
                  ) : (
                    <StarOff className="w-4 h-4 text-gray-600" />
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Meta */}
          <div className="flex items-center gap-4 text-xs text-gray-500">
            {response?.cached && (
              <span className="flex items-center gap-1">
                <Zap className="w-3 h-3" />
                Cached
              </span>
            )}
            <span>{response?.responseTime}ms</span>
          </div>
        </div>
      </motion.div>
    </>
  );
};

// =============================================================================
// HELPER COMPONENTS
// =============================================================================

const MermaidRenderer: React.FC<{ diagram: MermaidDiagram }> = ({ diagram }) => {
  // In production, this would use the Mermaid library to render
  // For now, return a placeholder with the raw syntax
  return (
    <div className="text-center py-8">
      <GitBranch className="w-12 h-12 text-joe-blue mx-auto mb-4 opacity-50" />
      <p className="text-sm text-gray-400">Attack Path Visualization</p>
      {diagram.raw && (
        <pre className="mt-4 text-xs text-gray-600 text-left overflow-x-auto">
          {diagram.raw}
        </pre>
      )}
    </div>
  );
};

// Simple markdown formatter
const formatMarkdown = (text: string): string => {
  return text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code class="px-1 py-0.5 bg-dws-dark rounded text-joe-blue">$1</code>')
    .replace(/\n/g, '<br />');
};

export default AIInfoPanel;
