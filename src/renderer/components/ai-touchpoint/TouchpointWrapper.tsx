/**
 * J.O.E. DevSecOps Arsenal - Touchpoint Wrapper
 * ES6+ HOC that adds AI touchpoint capabilities to any interactive element
 *
 * @module components/ai-touchpoint/TouchpointWrapper
 * @version 1.0.0
 */

import React, {
  useCallback,
  useRef,
  useState,
  useEffect,
  type ReactNode,
  type MouseEvent,
  type FocusEvent,
  type KeyboardEvent
} from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAITouchpointContext } from './AITouchpointProvider';
import { AITooltip } from './AITooltip';
import { AIInfoPanel } from './AIInfoPanel';
import type {
  AITouchpointContext,
  AITouchpointResponse,
  Framework,
  ElementType,
  RequestPriority
} from '../../../types/ai-touchpoint';

// =============================================================================
// TYPES
// =============================================================================

export interface TouchpointWrapperProps {
  /** Child elements to wrap */
  children: ReactNode;

  /** Unique identifier for this touchpoint */
  elementId: string;

  /** Type of element being wrapped */
  elementType: ElementType;

  /** Data context for AI analysis */
  data: Record<string, unknown>;

  /** Security frameworks to cite */
  frameworks?: Framework[];

  /** Enable tooltip on hover */
  enableHover?: boolean;

  /** Enable panel on click */
  enableClick?: boolean;

  /** Enable keyboard interaction */
  enableKeyboard?: boolean;

  /** Request priority */
  priority?: RequestPriority;

  /** Hover delay before fetching */
  hoverDelay?: number;

  /** Additional CSS classes */
  className?: string;

  /** Callback when response received */
  onResponse?: (response: AITouchpointResponse) => void;

  /** Callback on error */
  onError?: (error: Error) => void;

  /** Glow color for active state */
  glowColor?: 'blue' | 'green' | 'red' | 'yellow' | 'purple';

  /** Show loading indicator */
  showLoadingIndicator?: boolean;

  /** Disable the touchpoint */
  disabled?: boolean;
}

// =============================================================================
// GLOW STYLES
// =============================================================================

const glowStyles: Record<string, string> = {
  blue: 'hover:shadow-[0_0_15px_rgba(0,168,232,0.3)] focus:shadow-[0_0_20px_rgba(0,168,232,0.4)]',
  green: 'hover:shadow-[0_0_15px_rgba(135,197,73,0.3)] focus:shadow-[0_0_20px_rgba(135,197,73,0.4)]',
  red: 'hover:shadow-[0_0_15px_rgba(255,51,102,0.3)] focus:shadow-[0_0_20px_rgba(255,51,102,0.4)]',
  yellow: 'hover:shadow-[0_0_15px_rgba(255,176,0,0.3)] focus:shadow-[0_0_20px_rgba(255,176,0,0.4)]',
  purple: 'hover:shadow-[0_0_15px_rgba(123,31,162,0.3)] focus:shadow-[0_0_20px_rgba(123,31,162,0.4)]'
};

// =============================================================================
// COMPONENT
// =============================================================================

export const TouchpointWrapper: React.FC<TouchpointWrapperProps> = ({
  children,
  elementId,
  elementType,
  data,
  frameworks = ['NIST-800-53', 'MITRE-ATTACK', 'OWASP-TOP-10'],
  enableHover = true,
  enableClick = true,
  enableKeyboard = true,
  priority = 'medium',
  hoverDelay = 300,
  className = '',
  onResponse,
  onError,
  glowColor = 'blue',
  showLoadingIndicator = true,
  disabled = false
}) => {
  // Context
  const { state, actions, sessionId } = useAITouchpointContext();

  // State
  const [showTooltip, setShowTooltip] = useState(false);
  const [showPanel, setShowPanel] = useState(false);
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });
  const [response, setResponse] = useState<AITouchpointResponse | null>(null);
  const [error, setError] = useState<Error | null>(null);

  // Refs
  const wrapperRef = useRef<HTMLDivElement>(null);
  const hoverTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const isHoveringRef = useRef(false);

  // Computed
  const isLoading = state.loadingElements.has(elementId);
  const isActive = state.activeTooltip === elementId || state.activePanel === elementId;

  // ==========================================================================
  // BUILD CONTEXT
  // ==========================================================================

  const buildContext = useCallback((depth: 'tooltip' | 'panel' | 'deepdive'): AITouchpointContext => ({
    elementType,
    elementId,
    dataContext: {
      primaryValue: String(data.value ?? data.title ?? data.name ?? ''),
      metadata: data,
      relatedEntities: (data.relatedEntities as string[]) ?? []
    },
    requestedFrameworks: frameworks,
    depth,
    sessionId,
    timestamp: Date.now(),
    userProfile: state.userProfile ?? undefined
  }), [elementType, elementId, data, frameworks, sessionId, state.userProfile]);

  // ==========================================================================
  // FETCH HANDLERS
  // ==========================================================================

  const fetchTooltip = useCallback(async () => {
    if (disabled || !state.settings.enabled) return;

    try {
      const context = buildContext('tooltip');
      const result = await actions.queryTooltip(context);
      setResponse(result);
      setError(null);
      onResponse?.(result);
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      onError?.(error);
    }
  }, [disabled, state.settings.enabled, buildContext, actions, onResponse, onError]);

  const fetchPanel = useCallback(async () => {
    if (disabled || !state.settings.enabled) return;

    try {
      const context = buildContext('panel');
      const result = await actions.queryPanel(context);
      setResponse(result);
      setError(null);
      onResponse?.(result);
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      onError?.(error);
    }
  }, [disabled, state.settings.enabled, buildContext, actions, onResponse, onError]);

  // ==========================================================================
  // EVENT HANDLERS
  // ==========================================================================

  const handleMouseEnter = useCallback((e: MouseEvent<HTMLDivElement>) => {
    if (disabled || !enableHover) return;

    isHoveringRef.current = true;

    // Update tooltip position
    const rect = wrapperRef.current?.getBoundingClientRect();
    if (rect) {
      setTooltipPosition({
        x: rect.left + rect.width / 2,
        y: rect.top
      });
    }

    // Start hover timer
    hoverTimeoutRef.current = setTimeout(() => {
      if (isHoveringRef.current) {
        setShowTooltip(true);
        actions.showTooltip(elementId);
        fetchTooltip();

        // Track interaction
        actions.trackInteraction({
          sessionId,
          userId: 'current-user',
          type: 'hover',
          elementType,
          elementId,
          durationMs: 0,
          context: data
        });
      }
    }, hoverDelay);
  }, [disabled, enableHover, elementId, hoverDelay, fetchTooltip, actions, sessionId, elementType, data]);

  const handleMouseLeave = useCallback(() => {
    isHoveringRef.current = false;

    // Clear hover timer
    if (hoverTimeoutRef.current) {
      clearTimeout(hoverTimeoutRef.current);
      hoverTimeoutRef.current = null;
    }

    // Hide tooltip after delay
    setTimeout(() => {
      if (!isHoveringRef.current) {
        setShowTooltip(false);
        actions.hideTooltip();
      }
    }, 100);
  }, [actions]);

  const handleClick = useCallback((e: MouseEvent<HTMLDivElement>) => {
    if (disabled || !enableClick) return;

    e.stopPropagation();

    setShowPanel(true);
    actions.showPanel(elementId);
    fetchPanel();

    // Track interaction
    actions.trackInteraction({
      sessionId,
      userId: 'current-user',
      type: 'click',
      elementType,
      elementId,
      durationMs: 0,
      context: data
    });
  }, [disabled, enableClick, elementId, fetchPanel, actions, sessionId, elementType, data]);

  const handleKeyDown = useCallback((e: KeyboardEvent<HTMLDivElement>) => {
    if (disabled || !enableKeyboard) return;

    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleClick(e as unknown as MouseEvent<HTMLDivElement>);
    }

    if (e.key === 'Escape') {
      setShowTooltip(false);
      setShowPanel(false);
      actions.hideTooltip();
      actions.hidePanel();
    }
  }, [disabled, enableKeyboard, handleClick, actions]);

  const handleFocus = useCallback((e: FocusEvent<HTMLDivElement>) => {
    if (disabled || !enableHover) return;

    setShowTooltip(true);
    actions.showTooltip(elementId);
    fetchTooltip();
  }, [disabled, enableHover, elementId, fetchTooltip, actions]);

  const handleBlur = useCallback(() => {
    setShowTooltip(false);
    actions.hideTooltip();
  }, [actions]);

  // Panel handlers
  const handlePanelClose = useCallback(() => {
    setShowPanel(false);
    actions.hidePanel();

    // Track dismiss
    actions.trackInteraction({
      sessionId,
      userId: 'current-user',
      type: 'dismiss',
      elementType,
      elementId,
      durationMs: 0,
      context: data
    });
  }, [actions, sessionId, elementType, elementId, data]);

  const handleRate = useCallback((rating: number) => {
    if (response?.id) {
      actions.rateResponse(response.id, rating);
    }
  }, [response, actions]);

  // Tooltip handlers
  const handleTooltipClose = useCallback(() => {
    setShowTooltip(false);
    actions.hideTooltip();
  }, [actions]);

  const handleTooltipExpand = useCallback(() => {
    setShowTooltip(false);
    setShowPanel(true);
    actions.hideTooltip();
    actions.showPanel(elementId);
    fetchPanel();

    // Track deep dive
    actions.trackInteraction({
      sessionId,
      userId: 'current-user',
      type: 'deepdive',
      elementType,
      elementId,
      durationMs: 0,
      context: data
    });
  }, [elementId, fetchPanel, actions, sessionId, elementType, data]);

  // ==========================================================================
  // CLEANUP
  // ==========================================================================

  useEffect(() => {
    return () => {
      if (hoverTimeoutRef.current) {
        clearTimeout(hoverTimeoutRef.current);
      }
    };
  }, []);

  // ==========================================================================
  // RENDER
  // ==========================================================================

  return (
    <>
      <motion.div
        ref={wrapperRef}
        className={`
          relative cursor-pointer transition-all duration-200
          ${glowStyles[glowColor]}
          ${isActive ? 'ring-1 ring-joe-blue/30' : ''}
          ${isLoading && showLoadingIndicator ? 'animate-pulse' : ''}
          ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
          ${className}
        `}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        onClick={handleClick}
        onKeyDown={handleKeyDown}
        onFocus={handleFocus}
        onBlur={handleBlur}
        tabIndex={enableKeyboard ? 0 : -1}
        role="button"
        aria-label={`AI analysis for ${elementType}: ${data.title ?? elementId}`}
        aria-expanded={showPanel}
        aria-busy={isLoading}
        whileHover={{ scale: disabled ? 1 : 1.01 }}
        whileTap={{ scale: disabled ? 1 : 0.99 }}
      >
        {/* Loading indicator */}
        {isLoading && showLoadingIndicator && (
          <motion.div
            className="absolute top-0 right-0 w-2 h-2"
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0 }}
          >
            <span className="absolute inline-flex h-full w-full rounded-full bg-joe-blue opacity-75 animate-ping" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-joe-blue" />
          </motion.div>
        )}

        {/* AI indicator badge */}
        {state.settings.enabled && !disabled && (
          <div className="absolute -top-1 -right-1 w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity">
            <div className="w-full h-full rounded-full bg-gradient-to-br from-joe-blue to-dws-green" />
          </div>
        )}

        {children}
      </motion.div>

      {/* Tooltip */}
      <AnimatePresence>
        {showTooltip && (
          <AITooltip
            elementId={elementId}
            response={response}
            isLoading={isLoading}
            error={error}
            position={tooltipPosition}
            onClose={handleTooltipClose}
            onExpand={handleTooltipExpand}
          />
        )}
      </AnimatePresence>

      {/* Info Panel */}
      <AnimatePresence>
        {showPanel && (
          <AIInfoPanel
            elementId={elementId}
            response={response}
            isLoading={isLoading}
            error={error}
            onClose={handlePanelClose}
            onRate={handleRate}
          />
        )}
      </AnimatePresence>
    </>
  );
};

// =============================================================================
// HOC VERSION
// =============================================================================

export interface WithAITouchpointProps {
  elementId: string;
  elementType: ElementType;
  data: Record<string, unknown>;
  frameworks?: Framework[];
}

/**
 * Higher-Order Component to add AI touchpoint to any component
 */
export const withAITouchpoint = <P extends object>(
  WrappedComponent: React.ComponentType<P>,
  defaultProps?: Partial<TouchpointWrapperProps>
) => {
  const WithAITouchpoint: React.FC<P & WithAITouchpointProps> = (props) => {
    const { elementId, elementType, data, frameworks, ...rest } = props;

    return (
      <TouchpointWrapper
        elementId={elementId}
        elementType={elementType}
        data={data}
        frameworks={frameworks}
        {...defaultProps}
      >
        <WrappedComponent {...(rest as P)} />
      </TouchpointWrapper>
    );
  };

  WithAITouchpoint.displayName = `WithAITouchpoint(${WrappedComponent.displayName ?? WrappedComponent.name ?? 'Component'})`;

  return WithAITouchpoint;
};

export default TouchpointWrapper;
