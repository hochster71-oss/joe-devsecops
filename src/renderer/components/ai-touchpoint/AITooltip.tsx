/**
 * J.O.E. DevSecOps Arsenal - AI Tooltip Component
 * ES6+ Smart tooltip with streaming AI content and framework citations
 *
 * @module components/ai-touchpoint/AITooltip
 * @version 1.0.0
 */

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Brain,
  Loader2,
  AlertCircle,
  ChevronRight,
  ExternalLink,
  Sparkles,
  Shield,
  X
} from 'lucide-react';
import { SourceCitationBadge } from './SourceCitationBadge';
import type { AITouchpointResponse, Citation } from '../../../types/ai-touchpoint';

// =============================================================================
// TYPES
// =============================================================================

export interface AITooltipProps {
  /** Element this tooltip is attached to */
  elementId: string;

  /** AI response data */
  response: AITouchpointResponse | null;

  /** Loading state */
  isLoading: boolean;

  /** Error state */
  error: Error | null;

  /** Position for the tooltip */
  position: { x: number; y: number };

  /** Close handler */
  onClose: () => void;

  /** Expand to full panel handler */
  onExpand: () => void;
}

// =============================================================================
// ANIMATIONS
// =============================================================================

const tooltipVariants = {
  hidden: {
    opacity: 0,
    y: 10,
    scale: 0.95
  },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 300
    }
  },
  exit: {
    opacity: 0,
    y: 5,
    scale: 0.98,
    transition: { duration: 0.15 }
  }
};

// =============================================================================
// COMPONENT
// =============================================================================

export const AITooltip: React.FC<AITooltipProps> = ({
  elementId,
  response,
  isLoading,
  error,
  position,
  onClose,
  onExpand
}) => {
  const tooltipRef = useRef<HTMLDivElement>(null);
  const [adjustedPosition, setAdjustedPosition] = useState(position);

  // ==========================================================================
  // POSITION ADJUSTMENT
  // ==========================================================================

  useEffect(() => {
    if (tooltipRef.current) {
      const rect = tooltipRef.current.getBoundingClientRect();
      const viewportWidth = window.innerWidth;
      const viewportHeight = window.innerHeight;

      let newX = position.x - rect.width / 2;
      let newY = position.y - rect.height - 10;

      // Adjust for right edge
      if (newX + rect.width > viewportWidth - 20) {
        newX = viewportWidth - rect.width - 20;
      }

      // Adjust for left edge
      if (newX < 20) {
        newX = 20;
      }

      // Flip below if no room above
      if (newY < 20) {
        newY = position.y + 40;
      }

      setAdjustedPosition({ x: newX, y: newY });
    }
  }, [position, response]);

  // ==========================================================================
  // CLICK OUTSIDE
  // ==========================================================================

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (tooltipRef.current && !tooltipRef.current.contains(e.target as Node)) {
        onClose();
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [onClose]);

  // ==========================================================================
  // ESCAPE KEY
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
  // RENDER CONTENT
  // ==========================================================================

  const renderContent = () => {
    // Loading state
    if (isLoading && !response) {
      return (
        <div className="flex items-center gap-3 p-4">
          <div className="relative">
            <Loader2 className="w-5 h-5 text-joe-blue animate-spin" />
            <div className="absolute inset-0 animate-ping">
              <Sparkles className="w-5 h-5 text-joe-blue opacity-30" />
            </div>
          </div>
          <div>
            <p className="text-sm text-gray-300">J.O.E. analyzing...</p>
            <p className="text-xs text-gray-500">Fetching security intelligence</p>
          </div>
        </div>
      );
    }

    // Error state
    if (error) {
      return (
        <div className="flex items-center gap-3 p-4 text-alert-critical">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <div>
            <p className="text-sm font-medium">Analysis Failed</p>
            <p className="text-xs text-gray-400">{error.message}</p>
          </div>
        </div>
      );
    }

    // Response content
    if (response) {
      return (
        <div className="p-4 space-y-3">
          {/* Header */}
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-joe-blue/20">
                <Brain className="w-4 h-4 text-joe-blue" />
              </div>
              <div>
                <p className="text-xs text-gray-400">J.O.E. Security Intelligence</p>
                <p className="text-xs text-gray-500">
                  {response.confidence}% confidence
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1 rounded hover:bg-dws-card transition-colors"
              aria-label="Close tooltip"
            >
              <X className="w-3 h-3 text-gray-500" />
            </button>
          </div>

          {/* Summary */}
          <div className="text-sm text-gray-300 leading-relaxed">
            {response.summary}
          </div>

          {/* Citations */}
          {response.citations.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {response.citations.slice(0, 4).map((citation, index) => (
                <SourceCitationBadge
                  key={`${citation.framework}-${citation.controlId}-${index}`}
                  citation={citation}
                  size="sm"
                />
              ))}
              {response.citations.length > 4 && (
                <span className="text-xs text-gray-500 self-center">
                  +{response.citations.length - 4} more
                </span>
              )}
            </div>
          )}

          {/* Expand button */}
          <button
            onClick={onExpand}
            className="
              w-full flex items-center justify-center gap-2
              py-2 px-3 rounded-lg
              bg-gradient-to-r from-joe-blue/20 to-dws-green/20
              border border-joe-blue/30
              text-sm text-joe-blue
              hover:from-joe-blue/30 hover:to-dws-green/30
              transition-all duration-200
              group
            "
          >
            <Shield className="w-4 h-4" />
            <span>Deep Dive Analysis</span>
            <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </button>

          {/* Footer */}
          <div className="flex items-center justify-between text-xs text-gray-500 pt-1 border-t border-dws-border">
            <span>{response.cached ? 'Cached' : 'Live'} response</span>
            <span>{response.responseTime}ms</span>
          </div>
        </div>
      );
    }

    return null;
  };

  // ==========================================================================
  // RENDER
  // ==========================================================================

  return (
    <motion.div
      ref={tooltipRef}
      className="
        fixed z-50
        min-w-[280px] max-w-[400px]
        rounded-xl
        bg-gradient-to-br from-dws-card/95 to-dws-elevated/95
        backdrop-blur-xl
        border border-dws-border/50
        shadow-2xl shadow-black/50
      "
      style={{
        left: adjustedPosition.x,
        top: adjustedPosition.y
      }}
      variants={tooltipVariants}
      initial="hidden"
      animate="visible"
      exit="exit"
      onMouseEnter={(e) => e.stopPropagation()}
      role="tooltip"
      aria-live="polite"
    >
      {/* Glow effect */}
      <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-joe-blue/10 to-transparent pointer-events-none" />

      {/* Arrow indicator */}
      <div
        className="
          absolute -bottom-2 left-1/2 -translate-x-1/2
          w-4 h-4 rotate-45
          bg-dws-card border-r border-b border-dws-border/50
        "
      />

      {/* Content */}
      <div className="relative">
        {renderContent()}
      </div>

      {/* Animated border */}
      <div className="absolute inset-0 rounded-xl overflow-hidden pointer-events-none">
        <motion.div
          className="absolute inset-0 bg-gradient-to-r from-transparent via-joe-blue/20 to-transparent"
          animate={{
            x: ['-100%', '100%']
          }}
          transition={{
            duration: 3,
            repeat: Infinity,
            ease: 'linear'
          }}
        />
      </div>
    </motion.div>
  );
};

export default AITooltip;
