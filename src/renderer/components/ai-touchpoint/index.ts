/**
 * J.O.E. DevSecOps Arsenal - AI Touchpoint Components
 * ES6+ Export barrel for AI touchpoint system
 *
 * @module components/ai-touchpoint
 * @version 1.0.0
 */

// Provider & Context
export {
  AITouchpointProvider,
  useAITouchpointContext,
  default as AITouchpointProviderDefault
} from './AITouchpointProvider';

// Wrapper HOC
export {
  TouchpointWrapper,
  withAITouchpoint,
  default as TouchpointWrapperDefault
} from './TouchpointWrapper';
export type { TouchpointWrapperProps } from './TouchpointWrapper';

// UI Components
export {
  AITooltip,
  default as AITooltipDefault
} from './AITooltip';
export type { AITooltipProps } from './AITooltip';

export {
  AIInfoPanel,
  default as AIInfoPanelDefault
} from './AIInfoPanel';
export type { AIInfoPanelProps } from './AIInfoPanel';

export {
  SourceCitationBadge,
  CitationList,
  default as SourceCitationBadgeDefault
} from './SourceCitationBadge';
export type { SourceCitationBadgeProps, CitationListProps } from './SourceCitationBadge';
