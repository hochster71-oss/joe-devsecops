/**
 * J.O.E. DevSecOps Arsenal - useAITouchpoint Hook
 * ES6+ React hook for AI touchpoint interactions
 *
 * @module hooks/useAITouchpoint
 * @version 1.0.0
 */

import { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { v4 as uuidv4 } from 'uuid';
import type {
  AITouchpointContext,
  AITouchpointResponse,
  AIStreamController,
  StreamChunk,
  Framework,
  ElementType,
  ResponseDepth,
  RequestPriority,
  CacheEntry,
  UserInteraction
} from '../../types/ai-touchpoint';

// =============================================================================
// ELECTRON API HELPER
// Type-safe access to getElectronAPI()
// =============================================================================

const getElectronAPI = (): any => (window as any).electronAPI;

// =============================================================================
// CONSTANTS
// =============================================================================

const DEFAULT_HOVER_DELAY = 300;
const DEFAULT_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const MAX_CONCURRENT_REQUESTS = 3;
const REQUEST_TIMEOUT = 30000; // 30 seconds

// =============================================================================
// CACHE UTILITIES
// =============================================================================

/**
 * Generate cache key from context
 */
const generateCacheKey = (context: AITouchpointContext): string => {
  const { elementType, elementId, depth, requestedFrameworks } = context;
  const dataHash = JSON.stringify(context.dataContext);
  return `${elementType}:${elementId}:${depth}:${requestedFrameworks.join(',')}:${btoa(dataHash).slice(0, 32)}`;
};

/**
 * Check if cache entry is valid
 */
const isCacheValid = <T>(entry: CacheEntry<T> | undefined): entry is CacheEntry<T> => {
  if (!entry) return false;
  return Date.now() - entry.timestamp < entry.ttl;
};

// =============================================================================
// REQUEST QUEUE
// =============================================================================

interface QueuedRequest {
  id: string;
  context: AITouchpointContext;
  priority: RequestPriority;
  timestamp: number;
  abortController: AbortController;
  resolve: (response: AITouchpointResponse) => void;
  reject: (error: Error) => void;
}

const priorityOrder: Record<RequestPriority, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3
};

// =============================================================================
// HOOK OPTIONS
// =============================================================================

export interface UseAITouchpointOptions {
  elementId: string;
  elementType: ElementType;
  data: Record<string, unknown>;
  frameworks?: Framework[];
  autoFetch?: boolean;
  hoverDelay?: number;
  cacheTTL?: number;
  priority?: RequestPriority;
  onResponse?: (response: AITouchpointResponse) => void;
  onError?: (error: Error) => void;
}

// =============================================================================
// HOOK RETURN TYPE
// =============================================================================

export interface UseAITouchpointReturn {
  // State
  response: AITouchpointResponse | null;
  isLoading: boolean;
  error: Error | null;
  isStreaming: boolean;
  streamedContent: string;

  // Actions
  fetchTooltip: () => Promise<AITouchpointResponse | null>;
  fetchPanel: () => Promise<AITouchpointResponse | null>;
  fetchDeepDive: () => Promise<AITouchpointResponse | null>;
  streamResponse: (depth: ResponseDepth) => AIStreamController | null;
  cancelRequest: () => void;
  clearCache: () => void;

  // Event handlers for components
  handleMouseEnter: () => void;
  handleMouseLeave: () => void;
  handleClick: () => void;
  handleFocus: () => void;
  handleBlur: () => void;

  // Analytics
  trackInteraction: (type: 'hover' | 'click' | 'deepdive' | 'dismiss') => void;
  rateResponse: (rating: number) => void;
}

// =============================================================================
// GLOBAL STATE (Shared across all hook instances)
// =============================================================================

const globalCache = new Map<string, CacheEntry<AITouchpointResponse>>();
const activeRequests = new Set<string>();
const requestQueue: QueuedRequest[] = [];
let sessionId = uuidv4();

// Process queue when requests complete
const processQueue = async (): Promise<void> => {
  if (activeRequests.size >= MAX_CONCURRENT_REQUESTS) return;
  if (requestQueue.length === 0) return;

  // Sort by priority
  requestQueue.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  const request = requestQueue.shift();
  if (!request) return;

  activeRequests.add(request.id);

  try {
    const response = await executeRequest(request.context, request.abortController.signal);
    request.resolve(response);
  } catch (error) {
    request.reject(error instanceof Error ? error : new Error(String(error)));
  } finally {
    activeRequests.delete(request.id);
    processQueue(); // Process next in queue
  }
};

// Execute AI request via IPC
const executeRequest = async (
  context: AITouchpointContext,
  signal: AbortSignal
): Promise<AITouchpointResponse> => {
  const startTime = Date.now();

  // Check if electronAPI is available
  if (!getElectronAPI()?.aiTouchpoint?.query) {
    // Fallback to Ollama service directly
    return executeFallbackRequest(context, signal);
  }

  try {
    const result = await getElectronAPI().aiTouchpoint.query(context);

    if (signal.aborted) {
      throw new Error('Request aborted');
    }

    return {
      ...result,
      responseTime: Date.now() - startTime,
      cached: false,
      timestamp: Date.now()
    };
  } catch (error) {
    if (signal.aborted) {
      throw new Error('Request aborted');
    }
    throw error;
  }
};

// Fallback request using Ollama directly
const executeFallbackRequest = async (
  context: AITouchpointContext,
  signal: AbortSignal
): Promise<AITouchpointResponse> => {
  const startTime = Date.now();

  // Import ollamaService dynamically to avoid circular deps
  const { ollamaService } = await import('../../services/ollamaService');

  const prompt = buildPromptFromContext(context);

  try {
    const contextStr = JSON.stringify({
      findings: context.dataContext.metadata,
      frameworks: context.requestedFrameworks
    });
    const response = await ollamaService.chat(prompt, contextStr);

    if (signal.aborted) {
      throw new Error('Request aborted');
    }

    return parseAIResponse(response, context, startTime);
  } catch (error) {
    if (signal.aborted) {
      throw new Error('Request aborted');
    }
    throw error;
  }
};

// Build prompt from context
const buildPromptFromContext = (context: AITouchpointContext): string => {
  const { elementType, dataContext, requestedFrameworks, depth } = context;

  const depthInstructions: Record<ResponseDepth, string> = {
    tooltip: 'Provide a brief 2-3 sentence explanation.',
    panel: 'Provide a detailed analysis with key points and recommendations.',
    deepdive: 'Provide comprehensive analysis including attack paths, remediation steps, and all relevant framework mappings.'
  };

  return `
Analyze the following ${elementType} and provide security intelligence.

Data Context:
${JSON.stringify(dataContext, null, 2)}

Required Frameworks for Citations: ${requestedFrameworks.join(', ')}

Instructions: ${depthInstructions[depth]}

For each point, cite the relevant security framework control (e.g., "NIST 800-53 AC-2", "MITRE ATT&CK T1190", "CIS Control 5.1").

Format your response with:
1. Summary (brief overview)
2. Analysis (detailed findings)
3. Citations (framework references)
4. Remediation Steps (if applicable)
`.trim();
};

// Parse AI response into structured format
const parseAIResponse = (
  rawResponse: string,
  context: AITouchpointContext,
  startTime: number
): AITouchpointResponse => {
  // Extract sections from response
  const summaryMatch = rawResponse.match(/(?:summary|overview)[:\s]*([^#]+?)(?=\n#|\n\d\.|\nanalysis|\ncitation|$)/i);
  const analysisMatch = rawResponse.match(/(?:analysis|findings)[:\s]*([^#]+?)(?=\n#|\n\d\.|\ncitation|\nremediation|$)/i);

  // Extract citations from response
  const citationRegex = /(?:NIST|CIS|MITRE|OWASP|NASA|DO-178C|CMMC)[\s-]*(?:\d+[-.\s]?\d*|ATT&CK|ASVS|STD)[^\n,]*/gi;
  const citationMatches = rawResponse.match(citationRegex) ?? [];

  const citations = citationMatches.map(match => ({
    framework: extractFramework(match),
    controlId: extractControlId(match),
    title: match.trim(),
    description: '',
    url: '',
    relevance: 'direct' as const
  }));

  return {
    id: uuidv4(),
    requestContext: context,
    summary: summaryMatch?.[1]?.trim() ?? rawResponse.slice(0, 200),
    detailedAnalysis: analysisMatch?.[1]?.trim() ?? rawResponse,
    citations,
    relatedItems: [],
    remediationSteps: [],
    confidence: 85,
    responseTime: Date.now() - startTime,
    cached: false,
    timestamp: Date.now()
  };
};

// Extract framework from citation text
const extractFramework = (text: string): Framework => {
  const lower = text.toLowerCase();
  if (lower.includes('nist') && lower.includes('csf')) return 'NIST-CSF-2.0';
  if (lower.includes('nist') && lower.includes('800-53')) return 'NIST-800-53';
  if (lower.includes('nist') && lower.includes('800-171')) return 'NIST-800-171';
  if (lower.includes('mitre') && lower.includes('attack')) return 'MITRE-ATTACK';
  if (lower.includes('mitre') && lower.includes('defend')) return 'MITRE-DEFEND';
  if (lower.includes('cis')) return 'CIS-CONTROLS';
  if (lower.includes('owasp') && lower.includes('top')) return 'OWASP-TOP-10';
  if (lower.includes('owasp') && lower.includes('asvs')) return 'OWASP-ASVS';
  if (lower.includes('nasa')) return 'NASA-STD-8719';
  if (lower.includes('do-178')) return 'DO-178C';
  if (lower.includes('cmmc')) return 'CMMC-2.0';
  return 'NIST-800-53';
};

// Extract control ID from citation text
const extractControlId = (text: string): string => {
  const patterns = [
    /([A-Z]{2,3}-\d+(?:\.\d+)?)/,  // AC-2, SA-11.1
    /(T\d{4}(?:\.\d{3})?)/,         // T1190, T1190.001
    /(\d+\.\d+)/,                    // 5.1
    /(A\d{2})/                       // A01
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) return match[1];
  }

  return '';
};

// =============================================================================
// MAIN HOOK
// =============================================================================

export const useAITouchpoint = (options: UseAITouchpointOptions): UseAITouchpointReturn => {
  const {
    elementId,
    elementType,
    data,
    frameworks = ['NIST-800-53', 'MITRE-ATTACK', 'OWASP-TOP-10'],
    autoFetch = false,
    hoverDelay = DEFAULT_HOVER_DELAY,
    cacheTTL = DEFAULT_CACHE_TTL,
    priority = 'medium',
    onResponse,
    onError
  } = options;

  // State
  const [response, setResponse] = useState<AITouchpointResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [isStreaming, setIsStreaming] = useState(false);
  const [streamedContent, setStreamedContent] = useState('');

  // Refs
  const abortControllerRef = useRef<AbortController | null>(null);
  const hoverTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const currentRequestIdRef = useRef<string | null>(null);

  // Build context
  const buildContext = useCallback((depth: ResponseDepth): AITouchpointContext => ({
    elementType,
    elementId,
    dataContext: {
      primaryValue: String(data.value ?? data.title ?? ''),
      metadata: data,
      relatedEntities: (data.relatedEntities as string[]) ?? []
    },
    requestedFrameworks: frameworks,
    depth,
    sessionId,
    timestamp: Date.now()
  }), [elementType, elementId, data, frameworks]);

  // Fetch response
  const fetchResponse = useCallback(async (depth: ResponseDepth): Promise<AITouchpointResponse | null> => {
    const context = buildContext(depth);
    const cacheKey = generateCacheKey(context);

    // Check cache
    const cachedEntry = globalCache.get(cacheKey);
    if (isCacheValid(cachedEntry)) {
      const cachedResponse = { ...cachedEntry.data, cached: true };
      setResponse(cachedResponse);
      onResponse?.(cachedResponse);
      return cachedResponse;
    }

    // Cancel previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    const requestId = uuidv4();
    currentRequestIdRef.current = requestId;

    setIsLoading(true);
    setError(null);

    return new Promise((resolve, reject) => {
      const request: QueuedRequest = {
        id: requestId,
        context,
        priority,
        timestamp: Date.now(),
        abortController,
        resolve: (result) => {
          // Cache the response
          globalCache.set(cacheKey, {
            data: result,
            timestamp: Date.now(),
            ttl: cacheTTL,
            hits: 0
          });

          setResponse(result);
          setIsLoading(false);
          onResponse?.(result);
          resolve(result);
        },
        reject: (err) => {
          setError(err);
          setIsLoading(false);
          onError?.(err);
          reject(err);
        }
      };

      requestQueue.push(request);
      processQueue();
    });
  }, [buildContext, cacheTTL, priority, onResponse, onError]);

  // Specific fetch methods
  const fetchTooltip = useCallback(() => fetchResponse('tooltip'), [fetchResponse]);
  const fetchPanel = useCallback(() => fetchResponse('panel'), [fetchResponse]);
  const fetchDeepDive = useCallback(() => fetchResponse('deepdive'), [fetchResponse]);

  // Stream response
  const streamResponse = useCallback((depth: ResponseDepth): AIStreamController | null => {
    const context = buildContext(depth);

    if (!getElectronAPI()?.aiTouchpoint?.streamQuery) {
      console.warn('Streaming not available, falling back to standard request');
      fetchResponse(depth);
      return null;
    }

    setIsStreaming(true);
    setStreamedContent('');
    setError(null);

    const controller = getElectronAPI().aiTouchpoint.streamQuery(context);

    controller.onChunk((chunk: StreamChunk) => {
      setStreamedContent(prev => prev + chunk.content);
    });

    controller.onComplete((result: AITouchpointResponse) => {
      setResponse(result);
      setIsStreaming(false);
      onResponse?.(result);
    });

    controller.onError((err: Error) => {
      setError(err);
      setIsStreaming(false);
      onError?.(err);
    });

    return controller;
  }, [buildContext, fetchResponse, onResponse, onError]);

  // Cancel request
  const cancelRequest = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    if (hoverTimeoutRef.current) {
      clearTimeout(hoverTimeoutRef.current);
      hoverTimeoutRef.current = null;
    }
    setIsLoading(false);
    setIsStreaming(false);
  }, []);

  // Clear cache
  const clearCache = useCallback(() => {
    globalCache.clear();
  }, []);

  // Event handlers
  const handleMouseEnter = useCallback(() => {
    hoverTimeoutRef.current = setTimeout(() => {
      fetchTooltip();
    }, hoverDelay);
  }, [fetchTooltip, hoverDelay]);

  const handleMouseLeave = useCallback(() => {
    if (hoverTimeoutRef.current) {
      clearTimeout(hoverTimeoutRef.current);
      hoverTimeoutRef.current = null;
    }
    cancelRequest();
  }, [cancelRequest]);

  const handleClick = useCallback(() => {
    fetchPanel();
  }, [fetchPanel]);

  const handleFocus = useCallback(() => {
    handleMouseEnter();
  }, [handleMouseEnter]);

  const handleBlur = useCallback(() => {
    handleMouseLeave();
  }, [handleMouseLeave]);

  // Analytics
  const trackInteraction = useCallback((type: 'hover' | 'click' | 'deepdive' | 'dismiss') => {
    if (!getElectronAPI()?.analytics?.track) return;

    const interaction: Omit<UserInteraction, 'id' | 'timestamp'> = {
      sessionId,
      userId: 'current-user', // TODO: Get from auth store
      type,
      elementType,
      elementId,
      durationMs: 0,
      context: data,
      aiQueryId: currentRequestIdRef.current ?? undefined
    };

    getElectronAPI().analytics.track(interaction);
  }, [elementType, elementId, data]);

  const rateResponse = useCallback((rating: number) => {
    if (!currentRequestIdRef.current) return;
    if (!getElectronAPI()?.analytics?.rate) return;

    getElectronAPI().analytics.rate(currentRequestIdRef.current, rating);
  }, []);

  // Auto-fetch on mount if enabled
  useEffect(() => {
    if (autoFetch) {
      fetchTooltip();
    }

    return () => {
      cancelRequest();
    };
  }, [autoFetch, fetchTooltip, cancelRequest]);

  return useMemo(() => ({
    response,
    isLoading,
    error,
    isStreaming,
    streamedContent,
    fetchTooltip,
    fetchPanel,
    fetchDeepDive,
    streamResponse,
    cancelRequest,
    clearCache,
    handleMouseEnter,
    handleMouseLeave,
    handleClick,
    handleFocus,
    handleBlur,
    trackInteraction,
    rateResponse
  }), [
    response,
    isLoading,
    error,
    isStreaming,
    streamedContent,
    fetchTooltip,
    fetchPanel,
    fetchDeepDive,
    streamResponse,
    cancelRequest,
    clearCache,
    handleMouseEnter,
    handleMouseLeave,
    handleClick,
    handleFocus,
    handleBlur,
    trackInteraction,
    rateResponse
  ]);
};

export default useAITouchpoint;
