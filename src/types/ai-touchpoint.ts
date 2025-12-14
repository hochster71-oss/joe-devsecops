/**
 * J.O.E. DevSecOps Arsenal - AI Touchpoint Type Definitions
 * ES6+ TypeScript interfaces for the AI-powered touchpoint system
 *
 * @module types/ai-touchpoint
 * @version 1.0.0
 * @license MIT
 */

// =============================================================================
// FRAMEWORK DEFINITIONS
// =============================================================================

/** Supported security frameworks for source citations */
export type Framework =
  | 'NIST-CSF-2.0'
  | 'NIST-800-53'
  | 'NIST-800-171'
  | 'MITRE-ATTACK'
  | 'MITRE-DEFEND'
  | 'CIS-CONTROLS'
  | 'OWASP-TOP-10'
  | 'OWASP-ASVS'
  | 'OWASP-SAMM'
  | 'NASA-STD-8719'
  | 'DO-178C'
  | 'CMMC-2.0'
  | 'COMMON-CRITERIA'
  | 'ISO-27001'
  | 'SOC-2'
  | 'SLSA';

/** Element types that can have touchpoints */
export type ElementType =
  | 'metric'
  | 'finding'
  | 'control'
  | 'component'
  | 'chart'
  | 'asset'
  | 'vulnerability'
  | 'compliance'
  | 'threat'
  | 'kpi';

/** Depth levels for AI responses */
export type ResponseDepth = 'tooltip' | 'panel' | 'deepdive';

/** Relevance levels for citations */
export type CitationRelevance = 'direct' | 'related' | 'contextual';

/** Priority levels for request queue */
export type RequestPriority = 'low' | 'medium' | 'high' | 'critical';

/** Interaction types for analytics */
export type InteractionType = 'hover' | 'click' | 'deepdive' | 'dismiss' | 'copy' | 'apply' | 'rate';

// =============================================================================
// AI TOUCHPOINT CONTEXT
// =============================================================================

/** Data context passed to AI for analysis */
export interface AIDataContext {
  readonly primaryValue: string | number;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly relatedEntities: readonly string[];
  readonly historicalValues?: readonly number[];
  readonly thresholds?: {
    readonly warning: number;
    readonly critical: number;
  };
}

/** Full context for AI touchpoint requests */
export interface AITouchpointContext {
  readonly elementType: ElementType;
  readonly elementId: string;
  readonly dataContext: AIDataContext;
  readonly requestedFrameworks: readonly Framework[];
  readonly depth: ResponseDepth;
  readonly userProfile?: UserBehaviorProfile;
  readonly sessionId: string;
  readonly timestamp: number;
}

// =============================================================================
// AI TOUCHPOINT RESPONSE
// =============================================================================

/** Citation from a security framework */
export interface Citation {
  readonly framework: Framework;
  readonly controlId: string;
  readonly title: string;
  readonly description: string;
  readonly url: string;
  readonly relevance: CitationRelevance;
  readonly section?: string;
}

/** Related item suggestion */
export interface RelatedItem {
  readonly type: ElementType;
  readonly id: string;
  readonly title: string;
  readonly relevance: number; // 0-100
  readonly reason: string;
}

/** Remediation step */
export interface RemediationStep {
  readonly order: number;
  readonly title: string;
  readonly description: string;
  readonly codeSnippet?: {
    readonly language: string;
    readonly before?: string;
    readonly after: string;
  };
  readonly command?: string;
  readonly estimatedTime: string;
  readonly difficulty: 'trivial' | 'easy' | 'moderate' | 'complex' | 'expert';
}

/** Attack path node for Mermaid diagrams */
export interface AttackPathNode {
  readonly id: string;
  readonly label: string;
  readonly type: 'threat-actor' | 'technique' | 'vulnerability' | 'asset' | 'impact';
  readonly mitreTechnique?: string;
  readonly severity?: 'low' | 'medium' | 'high' | 'critical';
}

/** Attack path edge */
export interface AttackPathEdge {
  readonly from: string;
  readonly to: string;
  readonly label?: string;
  readonly style?: 'solid' | 'dashed' | 'dotted';
}

/** Mermaid diagram data */
export interface MermaidDiagram {
  readonly type: 'flowchart' | 'sequence' | 'mindmap';
  readonly direction: 'TB' | 'LR' | 'BT' | 'RL';
  readonly nodes: readonly AttackPathNode[];
  readonly edges: readonly AttackPathEdge[];
  readonly raw?: string; // Pre-rendered Mermaid syntax
}

/** Complete AI touchpoint response */
export interface AITouchpointResponse {
  readonly id: string;
  readonly requestContext: AITouchpointContext;
  readonly summary: string;
  readonly detailedAnalysis: string;
  readonly citations: readonly Citation[];
  readonly relatedItems: readonly RelatedItem[];
  readonly attackPath?: MermaidDiagram;
  readonly remediationSteps: readonly RemediationStep[];
  readonly confidence: number; // 0-100
  readonly responseTime: number; // ms
  readonly cached: boolean;
  readonly timestamp: number;
}

// =============================================================================
// STREAMING SUPPORT
// =============================================================================

/** Chunk types for streaming responses */
export type StreamChunkType = 'summary' | 'analysis' | 'citation' | 'remediation' | 'complete' | 'error';

/** Streaming chunk */
export interface StreamChunk {
  readonly type: StreamChunkType;
  readonly content: string;
  readonly index: number;
  readonly total?: number;
}

/** Stream controller interface */
export interface AIStreamController {
  readonly onChunk: (callback: (chunk: StreamChunk) => void) => void;
  readonly onComplete: (callback: (response: AITouchpointResponse) => void) => void;
  readonly onError: (callback: (error: Error) => void) => void;
  readonly cancel: () => void;
  readonly isPaused: boolean;
  readonly pause: () => void;
  readonly resume: () => void;
}

// =============================================================================
// CACHING
// =============================================================================

/** Cache entry */
export interface CacheEntry<T> {
  readonly data: T;
  readonly timestamp: number;
  readonly ttl: number;
  readonly hits: number;
}

/** Cache configuration */
export interface CacheConfig {
  readonly maxSize: number;
  readonly defaultTTL: number;
  readonly cleanupInterval: number;
}

// =============================================================================
// QUEUE MANAGEMENT
// =============================================================================

/** Queued request */
export interface QueuedRequest {
  readonly id: string;
  readonly context: AITouchpointContext;
  readonly priority: RequestPriority;
  readonly timestamp: number;
  readonly retryCount: number;
  readonly abortController: AbortController;
  readonly resolve: (response: AITouchpointResponse) => void;
  readonly reject: (error: Error) => void;
}

/** Queue statistics */
export interface QueueStats {
  readonly pending: number;
  readonly processing: number;
  readonly completed: number;
  readonly failed: number;
  readonly avgResponseTime: number;
}

// =============================================================================
// ANALYTICS
// =============================================================================

/** User interaction event */
export interface UserInteraction {
  readonly id: string;
  readonly sessionId: string;
  readonly userId: string;
  readonly timestamp: number;
  readonly type: InteractionType;
  readonly elementType: ElementType;
  readonly elementId: string;
  readonly durationMs: number;
  readonly context: Readonly<Record<string, unknown>>;
  readonly aiQueryId?: string;
}

/** AI query record for learning */
export interface AIQueryRecord {
  readonly id: string;
  readonly timestamp: number;
  readonly prompt: string;
  readonly contextHash: string;
  readonly response: string;
  readonly responseTimeMs: number;
  readonly userRating?: number; // 1-5
  readonly wasExpanded: boolean;
  readonly ledToAction: boolean;
  readonly frameworks: readonly Framework[];
}

/** User behavior profile */
export interface UserBehaviorProfile {
  readonly userId: string;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly totalSessions: number;
  readonly totalInteractions: number;
  readonly expertiseLevel: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  readonly preferredFrameworks: readonly Framework[];
  readonly commonQueryPatterns: readonly string[];
  readonly interactionHeatmap: Readonly<Record<ElementType, number>>;
  readonly avgSessionDuration: number;
  readonly peakActivityHours: readonly number[];
}

/** Security pattern detected */
export interface SecurityPattern {
  readonly id: string;
  readonly detectedAt: number;
  readonly patternType: 'anomaly' | 'trend' | 'correlation' | 'prediction';
  readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  readonly description: string;
  readonly affectedElements: readonly string[];
  readonly recommendedActions: readonly string[];
  readonly confidence: number;
  readonly wasActioned: boolean;
}

// =============================================================================
// PROVIDER STATE
// =============================================================================

/** AI Touchpoint Provider state */
export interface AITouchpointState {
  // Connection status
  readonly isConnected: boolean;
  readonly connectionError: string | null;

  // Active elements
  readonly activeTooltip: string | null;
  readonly activePanel: string | null;
  readonly loadingElements: ReadonlySet<string>;

  // Cache
  readonly cache: ReadonlyMap<string, CacheEntry<AITouchpointResponse>>;
  readonly cacheStats: {
    readonly hits: number;
    readonly misses: number;
    readonly size: number;
  };

  // Queue
  readonly queue: readonly QueuedRequest[];
  readonly queueStats: QueueStats;

  // User profile
  readonly userProfile: UserBehaviorProfile | null;

  // Settings
  readonly settings: AITouchpointSettings;
}

/** AI Touchpoint settings */
export interface AITouchpointSettings {
  readonly enabled: boolean;
  readonly hoverDelay: number; // ms
  readonly maxConcurrent: number;
  readonly cacheTTL: number; // ms
  readonly defaultFrameworks: readonly Framework[];
  readonly streamingEnabled: boolean;
  readonly analyticsEnabled: boolean;
  readonly autoExpandPanels: boolean;
}

// =============================================================================
// PROVIDER ACTIONS
// =============================================================================

/** Actions available on the AI Touchpoint context */
export interface AITouchpointActions {
  // Queries
  readonly queryTooltip: (context: AITouchpointContext) => Promise<AITouchpointResponse>;
  readonly queryPanel: (context: AITouchpointContext) => Promise<AITouchpointResponse>;
  readonly streamQuery: (context: AITouchpointContext) => AIStreamController;
  readonly cancelQuery: (requestId: string) => void;
  readonly cancelAll: () => void;

  // UI State
  readonly showTooltip: (elementId: string) => void;
  readonly hideTooltip: () => void;
  readonly showPanel: (elementId: string) => void;
  readonly hidePanel: () => void;

  // Cache
  readonly clearCache: () => void;
  readonly prefetch: (contexts: readonly AITouchpointContext[]) => void;

  // Analytics
  readonly trackInteraction: (interaction: Omit<UserInteraction, 'id' | 'timestamp'>) => void;
  readonly rateResponse: (queryId: string, rating: number) => void;

  // Settings
  readonly updateSettings: (settings: Partial<AITouchpointSettings>) => void;
}

// =============================================================================
// COMPONENT PROPS
// =============================================================================

/** Props for TouchpointWrapper component */
export interface TouchpointWrapperProps {
  readonly children: React.ReactNode;
  readonly context: Omit<AITouchpointContext, 'sessionId' | 'timestamp' | 'userProfile'>;
  readonly frameworks?: readonly Framework[];
  readonly enableHover?: boolean;
  readonly enableClick?: boolean;
  readonly priority?: RequestPriority;
  readonly className?: string;
  readonly onResponse?: (response: AITouchpointResponse) => void;
  readonly onError?: (error: Error) => void;
}

/** Props for AITooltip component */
export interface AITooltipProps {
  readonly elementId: string;
  readonly response: AITouchpointResponse | null;
  readonly isLoading: boolean;
  readonly error: Error | null;
  readonly position: { x: number; y: number };
  readonly onClose: () => void;
  readonly onExpand: () => void;
}

/** Props for AIInfoPanel component */
export interface AIInfoPanelProps {
  readonly elementId: string;
  readonly response: AITouchpointResponse | null;
  readonly isLoading: boolean;
  readonly streamController?: AIStreamController;
  readonly error: Error | null;
  readonly onClose: () => void;
  readonly onRate: (rating: number) => void;
  readonly onApplyFix?: (step: RemediationStep) => void;
}

/** Props for SourceCitationBadge component */
export interface SourceCitationBadgeProps {
  readonly citation: Citation;
  readonly size?: 'sm' | 'md' | 'lg';
  readonly showDescription?: boolean;
  readonly onClick?: () => void;
}

/** Props for AIStreamingText component */
export interface AIStreamingTextProps {
  readonly text: string;
  readonly isStreaming: boolean;
  readonly className?: string;
  readonly speed?: 'slow' | 'normal' | 'fast';
  readonly showCursor?: boolean;
}

// =============================================================================
// HOOK TYPES
// =============================================================================

/** Return type for useAITouchpoint hook */
export interface UseAITouchpointReturn {
  readonly state: AITouchpointState;
  readonly actions: AITouchpointActions;
  readonly isReady: boolean;
}

/** Options for useAITouchpoint hook */
export interface UseAITouchpointOptions {
  readonly elementId: string;
  readonly context: Omit<AITouchpointContext, 'sessionId' | 'timestamp' | 'userProfile' | 'elementId'>;
  readonly autoFetch?: boolean;
  readonly frameworks?: readonly Framework[];
}

// =============================================================================
// IPC TYPES
// =============================================================================

/** IPC request payload */
export interface AITouchpointIPCRequest {
  readonly type: 'query' | 'stream' | 'cancel' | 'prefetch';
  readonly context: AITouchpointContext;
  readonly requestId: string;
}

/** IPC response payload */
export interface AITouchpointIPCResponse {
  readonly success: boolean;
  readonly requestId: string;
  readonly data?: AITouchpointResponse;
  readonly error?: string;
  readonly chunk?: StreamChunk;
}

// =============================================================================
// UTILITY TYPES
// =============================================================================

/** Deep readonly utility */
export type DeepReadonly<T> = {
  readonly [P in keyof T]: T[P] extends object ? DeepReadonly<T[P]> : T[P];
};

/** Extract framework from citation */
export type FrameworkFromCitation<C extends Citation> = C['framework'];

/** Create context builder */
export type ContextBuilder = (
  elementType: ElementType,
  elementId: string,
  data: Record<string, unknown>
) => AITouchpointContext;
