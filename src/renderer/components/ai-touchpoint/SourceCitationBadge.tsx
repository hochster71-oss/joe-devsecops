/**
 * J.O.E. DevSecOps Arsenal - Source Citation Badge
 * ES6+ Badge component for security framework citations
 *
 * @module components/ai-touchpoint/SourceCitationBadge
 * @version 1.0.0
 */

import React, { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ExternalLink, Copy, Check } from 'lucide-react';
import type { Citation, Framework } from '../../../types/ai-touchpoint';
import { FRAMEWORK_METADATA, getFrameworkColor } from '../../../core/security-frameworks';

// =============================================================================
// TYPES
// =============================================================================

export interface SourceCitationBadgeProps {
  /** Citation data */
  citation: Citation;

  /** Badge size */
  size?: 'sm' | 'md' | 'lg';

  /** Show description on hover */
  showDescription?: boolean;

  /** Click handler */
  onClick?: () => void;

  /** Custom class name */
  className?: string;
}

// =============================================================================
// SIZE STYLES
// =============================================================================

const sizeStyles = {
  sm: {
    badge: 'px-2 py-0.5 text-xs gap-1',
    icon: 'w-3 h-3',
    popup: 'w-64'
  },
  md: {
    badge: 'px-2.5 py-1 text-sm gap-1.5',
    icon: 'w-4 h-4',
    popup: 'w-72'
  },
  lg: {
    badge: 'px-3 py-1.5 text-sm gap-2',
    icon: 'w-4 h-4',
    popup: 'w-80'
  }
};

// =============================================================================
// FRAMEWORK COLORS
// =============================================================================

const frameworkColors: Record<Framework, { bg: string; text: string; border: string }> = {
  'NIST-CSF-2.0': { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/30' },
  'NIST-800-53': { bg: 'bg-blue-600/20', text: 'text-blue-300', border: 'border-blue-600/30' },
  'NIST-800-171': { bg: 'bg-blue-700/20', text: 'text-blue-200', border: 'border-blue-700/30' },
  'MITRE-ATTACK': { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30' },
  'MITRE-DEFEND': { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30' },
  'CIS-CONTROLS': { bg: 'bg-emerald-500/20', text: 'text-emerald-400', border: 'border-emerald-500/30' },
  'OWASP-TOP-10': { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30' },
  'OWASP-ASVS': { bg: 'bg-orange-600/20', text: 'text-orange-300', border: 'border-orange-600/30' },
  'OWASP-SAMM': { bg: 'bg-orange-700/20', text: 'text-orange-200', border: 'border-orange-700/30' },
  'NASA-STD-8719': { bg: 'bg-purple-500/20', text: 'text-purple-400', border: 'border-purple-500/30' },
  'DO-178C': { bg: 'bg-purple-600/20', text: 'text-purple-300', border: 'border-purple-600/30' },
  'CMMC-2.0': { bg: 'bg-indigo-500/20', text: 'text-indigo-400', border: 'border-indigo-500/30' },
  'COMMON-CRITERIA': { bg: 'bg-violet-500/20', text: 'text-violet-400', border: 'border-violet-500/30' },
  'ISO-27001': { bg: 'bg-cyan-500/20', text: 'text-cyan-400', border: 'border-cyan-500/30' },
  'SOC-2': { bg: 'bg-teal-500/20', text: 'text-teal-400', border: 'border-teal-500/30' },
  'SLSA': { bg: 'bg-lime-500/20', text: 'text-lime-400', border: 'border-lime-500/30' }
};

// =============================================================================
// RELEVANCE INDICATORS
// =============================================================================

const relevanceStyles = {
  direct: { dot: 'bg-green-400', label: 'Direct match' },
  related: { dot: 'bg-yellow-400', label: 'Related' },
  contextual: { dot: 'bg-gray-400', label: 'Contextual' }
};

// =============================================================================
// COMPONENT
// =============================================================================

export const SourceCitationBadge: React.FC<SourceCitationBadgeProps> = ({
  citation,
  size = 'sm',
  showDescription = true,
  onClick,
  className = ''
}) => {
  const [showPopup, setShowPopup] = useState(false);
  const [copied, setCopied] = useState(false);

  const styles = sizeStyles[size];
  const colors = frameworkColors[citation.framework] ?? frameworkColors['NIST-800-53'];
  const relevance = relevanceStyles[citation.relevance];
  const metadata = FRAMEWORK_METADATA.get(citation.framework);

  // ==========================================================================
  // HANDLERS
  // ==========================================================================

  const handleCopy = useCallback(async (e: React.MouseEvent) => {
    e.stopPropagation();
    const text = `${citation.framework} ${citation.controlId}: ${citation.title}`;

    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  }, [citation]);

  const handleOpenLink = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    if (citation.url) {
      window.open(citation.url, '_blank', 'noopener,noreferrer');
    }
  }, [citation.url]);

  // ==========================================================================
  // RENDER
  // ==========================================================================

  return (
    <div className="relative inline-block">
      <motion.button
        className={`
          inline-flex items-center rounded-full
          font-medium cursor-pointer
          border transition-all duration-200
          ${styles.badge}
          ${colors.bg} ${colors.text} ${colors.border}
          hover:scale-105 active:scale-95
          ${className}
        `}
        onClick={onClick}
        onMouseEnter={() => showDescription && setShowPopup(true)}
        onMouseLeave={() => setShowPopup(false)}
        whileHover={{ boxShadow: `0 0 12px ${getFrameworkColor(citation.framework)}40` }}
      >
        {/* Relevance dot */}
        <span className={`w-1.5 h-1.5 rounded-full ${relevance.dot}`} />

        {/* Framework short name */}
        <span className="font-semibold">
          {metadata?.name ?? citation.framework}
        </span>

        {/* Control ID */}
        {citation.controlId && (
          <span className="opacity-80">{citation.controlId}</span>
        )}
      </motion.button>

      {/* Popup */}
      <AnimatePresence>
        {showPopup && (
          <motion.div
            className={`
              absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2
              ${styles.popup}
              p-3 rounded-lg
              bg-dws-card/95 backdrop-blur-xl
              border border-dws-border
              shadow-xl shadow-black/50
            `}
            initial={{ opacity: 0, y: 5, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 5, scale: 0.95 }}
            transition={{ duration: 0.15 }}
          >
            {/* Header */}
            <div className="flex items-start justify-between gap-2 mb-2">
              <div className="flex items-center gap-2">
                <div
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: getFrameworkColor(citation.framework) }}
                />
                <span className={`text-sm font-semibold ${colors.text}`}>
                  {metadata?.name ?? citation.framework}
                </span>
              </div>
              <span className={`text-xs px-1.5 py-0.5 rounded ${colors.bg} ${colors.text}`}>
                {citation.controlId}
              </span>
            </div>

            {/* Title */}
            <p className="text-sm text-gray-200 mb-2 font-medium">
              {citation.title}
            </p>

            {/* Description */}
            {citation.description && (
              <p className="text-xs text-gray-400 mb-3">
                {citation.description}
              </p>
            )}

            {/* Relevance */}
            <div className="flex items-center gap-2 mb-3">
              <span className={`w-2 h-2 rounded-full ${relevance.dot}`} />
              <span className="text-xs text-gray-500">{relevance.label}</span>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                className="
                  flex items-center gap-1.5 px-2 py-1 rounded
                  text-xs text-gray-400
                  bg-dws-elevated hover:bg-dws-border
                  transition-colors
                "
              >
                {copied ? (
                  <>
                    <Check className="w-3 h-3 text-dws-green" />
                    <span className="text-dws-green">Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copy</span>
                  </>
                )}
              </button>

              {citation.url && (
                <button
                  onClick={handleOpenLink}
                  className="
                    flex items-center gap-1.5 px-2 py-1 rounded
                    text-xs text-gray-400
                    bg-dws-elevated hover:bg-dws-border
                    transition-colors
                  "
                >
                  <ExternalLink className="w-3 h-3" />
                  <span>View Source</span>
                </button>
              )}
            </div>

            {/* Organization */}
            {metadata?.organization && (
              <p className="text-xs text-gray-600 mt-2 pt-2 border-t border-dws-border">
                {metadata.organization}
              </p>
            )}

            {/* Arrow */}
            <div
              className="
                absolute -bottom-1.5 left-1/2 -translate-x-1/2
                w-3 h-3 rotate-45
                bg-dws-card border-r border-b border-dws-border
              "
            />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

// =============================================================================
// CITATION LIST COMPONENT
// =============================================================================

export interface CitationListProps {
  citations: Citation[];
  maxVisible?: number;
  size?: 'sm' | 'md' | 'lg';
  onCitationClick?: (citation: Citation) => void;
}

export const CitationList: React.FC<CitationListProps> = ({
  citations,
  maxVisible = 5,
  size = 'sm',
  onCitationClick
}) => {
  const [showAll, setShowAll] = useState(false);
  const visibleCitations = showAll ? citations : citations.slice(0, maxVisible);
  const hiddenCount = citations.length - maxVisible;

  return (
    <div className="flex flex-wrap gap-1.5 items-center">
      {visibleCitations.map((citation, index) => (
        <SourceCitationBadge
          key={`${citation.framework}-${citation.controlId}-${index}`}
          citation={citation}
          size={size}
          onClick={() => onCitationClick?.(citation)}
        />
      ))}

      {!showAll && hiddenCount > 0 && (
        <button
          onClick={() => setShowAll(true)}
          className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
        >
          +{hiddenCount} more
        </button>
      )}

      {showAll && citations.length > maxVisible && (
        <button
          onClick={() => setShowAll(false)}
          className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
        >
          Show less
        </button>
      )}
    </div>
  );
};

export default SourceCitationBadge;
