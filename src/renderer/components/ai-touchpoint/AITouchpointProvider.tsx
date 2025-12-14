/**
 * J.O.E. DevSecOps Arsenal - AI Touchpoint Provider
 * ES6+ React Context Provider for global AI touchpoint state management
 *
 * @module components/ai-touchpoint/AITouchpointProvider
 * @version 1.0.0
 */

import React, {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useMemo,
  useEffect,
  useRef,
  type ReactNode,
  type Dispatch
} from 'react';
import { v4 as uuidv4 } from 'uuid';
import type {
  AITouchpointState,
  AITouchpointActions,
  AITouchpointSettings,
  AITouchpointContext as TouchpointContext,
  AITouchpointResponse,
  AIStreamController,
  CacheEntry,
  QueueStats,
  UserBehaviorProfile,
  UserInteraction,
  Framework
} from '../../../types/ai-touchpoint';

// =============================================================================
// ELECTRON API HELPER
// Type-safe access to getElectronAPI()
// =============================================================================

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const getElectronAPI = (): any => (window as any).electronAPI;

// =============================================================================
// DEFAULT VALUES
// =============================================================================

const DEFAULT_SETTINGS: AITouchpointSettings = {
  enabled: true,
  hoverDelay: 300,
  maxConcurrent: 3,
  cacheTTL: 5 * 60 * 1000, // 5 minutes
  defaultFrameworks: ['NIST-800-53', 'MITRE-ATTACK', 'OWASP-TOP-10', 'CIS-CONTROLS'],
  streamingEnabled: true,
  analyticsEnabled: true,
  autoExpandPanels: false
};

const INITIAL_QUEUE_STATS: QueueStats = {
  pending: 0,
  processing: 0,
  completed: 0,
  failed: 0,
  avgResponseTime: 0
};

const INITIAL_STATE: AITouchpointState = {
  isConnected: false,
  connectionError: null,
  activeTooltip: null,
  activePanel: null,
  loadingElements: new Set(),
  cache: new Map(),
  cacheStats: { hits: 0, misses: 0, size: 0 },
  queue: [],
  queueStats: INITIAL_QUEUE_STATS,
  userProfile: null,
  settings: DEFAULT_SETTINGS
};

// =============================================================================
// ACTION TYPES
// =============================================================================

type Action =
  | { type: 'SET_CONNECTED'; payload: boolean }
  | { type: 'SET_CONNECTION_ERROR'; payload: string | null }
  | { type: 'SHOW_TOOLTIP'; payload: string }
  | { type: 'HIDE_TOOLTIP' }
  | { type: 'SHOW_PANEL'; payload: string }
  | { type: 'HIDE_PANEL' }
  | { type: 'ADD_LOADING'; payload: string }
  | { type: 'REMOVE_LOADING'; payload: string }
  | { type: 'SET_CACHE'; payload: { key: string; entry: CacheEntry<AITouchpointResponse> } }
  | { type: 'CLEAR_CACHE' }
  | { type: 'UPDATE_CACHE_STATS'; payload: { hit: boolean } }
  | { type: 'UPDATE_QUEUE_STATS'; payload: Partial<QueueStats> }
  | { type: 'SET_USER_PROFILE'; payload: UserBehaviorProfile | null }
  | { type: 'UPDATE_SETTINGS'; payload: Partial<AITouchpointSettings> };

// =============================================================================
// REDUCER
// =============================================================================

const reducer = (state: AITouchpointState, action: Action): AITouchpointState => {
  switch (action.type) {
    case 'SET_CONNECTED':
      return { ...state, isConnected: action.payload };

    case 'SET_CONNECTION_ERROR':
      return { ...state, connectionError: action.payload };

    case 'SHOW_TOOLTIP':
      return { ...state, activeTooltip: action.payload };

    case 'HIDE_TOOLTIP':
      return { ...state, activeTooltip: null };

    case 'SHOW_PANEL':
      return { ...state, activePanel: action.payload };

    case 'HIDE_PANEL':
      return { ...state, activePanel: null };

    case 'ADD_LOADING': {
      const newLoading = new Set(state.loadingElements);
      newLoading.add(action.payload);
      return { ...state, loadingElements: newLoading };
    }

    case 'REMOVE_LOADING': {
      const newLoading = new Set(state.loadingElements);
      newLoading.delete(action.payload);
      return { ...state, loadingElements: newLoading };
    }

    case 'SET_CACHE': {
      const newCache = new Map(state.cache);
      newCache.set(action.payload.key, action.payload.entry);
      return {
        ...state,
        cache: newCache,
        cacheStats: { ...state.cacheStats, size: newCache.size }
      };
    }

    case 'CLEAR_CACHE':
      return {
        ...state,
        cache: new Map(),
        cacheStats: { hits: 0, misses: 0, size: 0 }
      };

    case 'UPDATE_CACHE_STATS':
      return {
        ...state,
        cacheStats: {
          ...state.cacheStats,
          hits: state.cacheStats.hits + (action.payload.hit ? 1 : 0),
          misses: state.cacheStats.misses + (action.payload.hit ? 0 : 1)
        }
      };

    case 'UPDATE_QUEUE_STATS':
      return {
        ...state,
        queueStats: { ...state.queueStats, ...action.payload }
      };

    case 'SET_USER_PROFILE':
      return { ...state, userProfile: action.payload };

    case 'UPDATE_SETTINGS':
      return {
        ...state,
        settings: { ...state.settings, ...action.payload }
      };

    default:
      return state;
  }
};

// =============================================================================
// CONTEXT
// =============================================================================

interface AITouchpointContextValue {
  state: AITouchpointState;
  dispatch: Dispatch<Action>;
  actions: AITouchpointActions;
  sessionId: string;
}

const AITouchpointContext = createContext<AITouchpointContextValue | null>(null);

// =============================================================================
// PROVIDER COMPONENT
// =============================================================================

interface AITouchpointProviderProps {
  children: ReactNode;
  initialSettings?: Partial<AITouchpointSettings>;
}

export const AITouchpointProvider: React.FC<AITouchpointProviderProps> = ({
  children,
  initialSettings
}) => {
  const [state, dispatch] = useReducer(reducer, {
    ...INITIAL_STATE,
    settings: { ...DEFAULT_SETTINGS, ...initialSettings }
  });

  const sessionIdRef = useRef(uuidv4());
  const abortControllersRef = useRef(new Map<string, AbortController>());
  const responseTimesRef = useRef<number[]>([]);

  // ==========================================================================
  // CONNECTION CHECK
  // ==========================================================================

  useEffect(() => {
    const checkConnection = async () => {
      try {
        // Check if Ollama is available
        const response = await fetch('http://localhost:11434/api/tags', {
          method: 'GET',
          signal: AbortSignal.timeout(5000)
        });

        dispatch({ type: 'SET_CONNECTED', payload: response.ok });
        dispatch({ type: 'SET_CONNECTION_ERROR', payload: null });
      } catch (error) {
        dispatch({ type: 'SET_CONNECTED', payload: false });
        dispatch({
          type: 'SET_CONNECTION_ERROR',
          payload: 'Unable to connect to Ollama AI service'
        });
      }
    };

    checkConnection();
    const interval = setInterval(checkConnection, 30000); // Check every 30s

    return () => clearInterval(interval);
  }, []);

  // ==========================================================================
  // LOAD USER PROFILE
  // ==========================================================================

  useEffect(() => {
    const loadProfile = async () => {
      try {
        if (getElectronAPI()?.analytics?.getProfile) {
          const profile = await getElectronAPI().analytics.getProfile();
          dispatch({ type: 'SET_USER_PROFILE', payload: profile });
        }
      } catch (error) {
        console.warn('Failed to load user profile:', error);
      }
    };

    loadProfile();
  }, []);

  // ==========================================================================
  // CACHE MANAGEMENT
  // ==========================================================================

  const generateCacheKey = useCallback((context: TouchpointContext): string => {
    const { elementType, elementId, depth, requestedFrameworks } = context;
    const dataHash = JSON.stringify(context.dataContext);
    return `${elementType}:${elementId}:${depth}:${requestedFrameworks.join(',')}:${btoa(dataHash).slice(0, 32)}`;
  }, []);

  const getCachedResponse = useCallback((key: string): AITouchpointResponse | null => {
    const entry = state.cache.get(key);
    if (!entry) {
      dispatch({ type: 'UPDATE_CACHE_STATS', payload: { hit: false } });
      return null;
    }

    const isValid = Date.now() - entry.timestamp < entry.ttl;
    if (!isValid) {
      return null;
    }

    dispatch({ type: 'UPDATE_CACHE_STATS', payload: { hit: true } });
    return { ...entry.data, cached: true };
  }, [state.cache]);

  const setCachedResponse = useCallback((key: string, response: AITouchpointResponse) => {
    dispatch({
      type: 'SET_CACHE',
      payload: {
        key,
        entry: {
          data: response,
          timestamp: Date.now(),
          ttl: state.settings.cacheTTL,
          hits: 0
        }
      }
    });
  }, [state.settings.cacheTTL]);

  // ==========================================================================
  // QUERY METHODS
  // ==========================================================================

  const queryTooltip = useCallback(async (context: TouchpointContext): Promise<AITouchpointResponse> => {
    const cacheKey = generateCacheKey(context);
    const cached = getCachedResponse(cacheKey);
    if (cached) {return cached;}

    dispatch({ type: 'ADD_LOADING', payload: context.elementId });

    const abortController = new AbortController();
    abortControllersRef.current.set(context.elementId, abortController);

    try {
      const startTime = Date.now();

      // Use electron API if available, otherwise fallback
      let response: AITouchpointResponse;

      if (getElectronAPI()?.aiTouchpoint?.query) {
        response = await getElectronAPI().aiTouchpoint.query(context);
      } else {
        // Fallback to direct Ollama call
        const { ollamaService } = await import('../../../services/ollamaService');
        const prompt = buildPromptForContext(context);
        const contextStr = JSON.stringify({
          findings: context.dataContext.metadata,
          frameworks: context.requestedFrameworks
        });
        const rawResponse = await ollamaService.chat(prompt, contextStr);
        response = parseRawResponse(rawResponse, context, startTime);
      }

      const responseTime = Date.now() - startTime;
      responseTimesRef.current.push(responseTime);

      // Update avg response time
      const avgTime = responseTimesRef.current.reduce((a, b) => a + b, 0) / responseTimesRef.current.length;
      dispatch({ type: 'UPDATE_QUEUE_STATS', payload: { avgResponseTime: avgTime } });

      setCachedResponse(cacheKey, response);
      return response;

    } catch (error) {
      throw error instanceof Error ? error : new Error(String(error));
    } finally {
      dispatch({ type: 'REMOVE_LOADING', payload: context.elementId });
      abortControllersRef.current.delete(context.elementId);
    }
  }, [generateCacheKey, getCachedResponse, setCachedResponse]);

  const queryPanel = useCallback(async (context: TouchpointContext): Promise<AITouchpointResponse> => {
    return queryTooltip({ ...context, depth: 'panel' });
  }, [queryTooltip]);

  const streamQuery = useCallback((context: TouchpointContext): AIStreamController => {
    const callbacks = {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      onChunk: [] as Array<(chunk: any) => void>,
      onComplete: [] as Array<(response: AITouchpointResponse) => void>,
      onError: [] as Array<(error: Error) => void>
    };

    let isPaused = false;
    const abortController = new AbortController();

    // Start streaming
    (async () => {
      try {
        if (getElectronAPI()?.aiTouchpoint?.streamQuery) {
          const controller = getElectronAPI().aiTouchpoint.streamQuery(context);
          controller.onChunk((chunk: { type: string; content: string; index: number }) => {
            if (!isPaused) {
              callbacks.onChunk.forEach(cb => cb(chunk));
            }
          });
          controller.onComplete((response: unknown) => {
            callbacks.onComplete.forEach(cb => cb(response as AITouchpointResponse));
          });
          controller.onError((error: Error) => {
            callbacks.onError.forEach(cb => cb(error));
          });
        } else {
          // Fallback: simulate streaming with regular response
          const response = await queryTooltip(context);
          const words = response.detailedAnalysis.split(' ');
          for (let i = 0; i < words.length; i++) {
            if (abortController.signal.aborted) {break;}
            if (!isPaused) {
              callbacks.onChunk.forEach(cb => cb({
                type: 'analysis',
                content: words[i] + ' ',
                index: i,
                total: words.length
              }));
            }
            await new Promise(resolve => setTimeout(resolve, 20));
          }
          callbacks.onComplete.forEach(cb => cb(response));
        }
      } catch (error) {
        callbacks.onError.forEach(cb => cb(error instanceof Error ? error : new Error(String(error))));
      }
    })();

    return {
      onChunk: (cb) => { callbacks.onChunk.push(cb); },
      onComplete: (cb) => { callbacks.onComplete.push(cb); },
      onError: (cb) => { callbacks.onError.push(cb); },
      cancel: () => abortController.abort(),
      isPaused,
      pause: () => { isPaused = true; },
      resume: () => { isPaused = false; }
    };
  }, [queryTooltip]);

  const cancelQuery = useCallback((requestId: string) => {
    const controller = abortControllersRef.current.get(requestId);
    if (controller) {
      controller.abort();
      abortControllersRef.current.delete(requestId);
    }
  }, []);

  const cancelAll = useCallback(() => {
    abortControllersRef.current.forEach(controller => controller.abort());
    abortControllersRef.current.clear();
  }, []);

  // ==========================================================================
  // UI STATE ACTIONS
  // ==========================================================================

  const showTooltip = useCallback((elementId: string) => {
    dispatch({ type: 'SHOW_TOOLTIP', payload: elementId });
  }, []);

  const hideTooltip = useCallback(() => {
    dispatch({ type: 'HIDE_TOOLTIP' });
  }, []);

  const showPanel = useCallback((elementId: string) => {
    dispatch({ type: 'SHOW_PANEL', payload: elementId });
  }, []);

  const hidePanel = useCallback(() => {
    dispatch({ type: 'HIDE_PANEL' });
  }, []);

  // ==========================================================================
  // CACHE ACTIONS
  // ==========================================================================

  const clearCache = useCallback(() => {
    dispatch({ type: 'CLEAR_CACHE' });
  }, []);

  const prefetch = useCallback((contexts: readonly TouchpointContext[]) => {
    contexts.forEach(context => {
      queryTooltip(context).catch(() => {
        // Ignore prefetch errors
      });
    });
  }, [queryTooltip]);

  // ==========================================================================
  // ANALYTICS ACTIONS
  // ==========================================================================

  const trackInteraction = useCallback((interaction: Omit<UserInteraction, 'id' | 'timestamp'>) => {
    if (!state.settings.analyticsEnabled) {return;}

    const fullInteraction: UserInteraction = {
      ...interaction,
      id: uuidv4(),
      timestamp: Date.now()
    };

    if (getElectronAPI()?.analytics?.track) {
      getElectronAPI().analytics.track(fullInteraction);
    }
  }, [state.settings.analyticsEnabled]);

  const rateResponse = useCallback((queryId: string, rating: number) => {
    if (getElectronAPI()?.analytics?.rate) {
      getElectronAPI().analytics.rate(queryId, rating);
    }
  }, []);

  // ==========================================================================
  // SETTINGS ACTIONS
  // ==========================================================================

  const updateSettings = useCallback((settings: Partial<AITouchpointSettings>) => {
    dispatch({ type: 'UPDATE_SETTINGS', payload: settings });
  }, []);

  // ==========================================================================
  // BUILD ACTIONS OBJECT
  // ==========================================================================

  const actions: AITouchpointActions = useMemo(() => ({
    queryTooltip,
    queryPanel,
    streamQuery,
    cancelQuery,
    cancelAll,
    showTooltip,
    hideTooltip,
    showPanel,
    hidePanel,
    clearCache,
    prefetch,
    trackInteraction,
    rateResponse,
    updateSettings
  }), [
    queryTooltip,
    queryPanel,
    streamQuery,
    cancelQuery,
    cancelAll,
    showTooltip,
    hideTooltip,
    showPanel,
    hidePanel,
    clearCache,
    prefetch,
    trackInteraction,
    rateResponse,
    updateSettings
  ]);

  // ==========================================================================
  // CONTEXT VALUE
  // ==========================================================================

  const contextValue = useMemo<AITouchpointContextValue>(() => ({
    state,
    dispatch,
    actions,
    sessionId: sessionIdRef.current
  }), [state, actions]);

  return (
    <AITouchpointContext.Provider value={contextValue}>
      {children}
    </AITouchpointContext.Provider>
  );
};

// =============================================================================
// HOOK TO USE CONTEXT
// =============================================================================

export const useAITouchpointContext = (): AITouchpointContextValue => {
  const context = useContext(AITouchpointContext);
  if (!context) {
    throw new Error('useAITouchpointContext must be used within AITouchpointProvider');
  }
  return context;
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

const buildPromptForContext = (context: TouchpointContext): string => {
  const { elementType, dataContext, requestedFrameworks, depth } = context;

  const depthInstructions: Record<string, string> = {
    tooltip: 'Provide a concise 2-3 sentence security analysis.',
    panel: 'Provide a detailed security analysis with key findings and recommendations.',
    deepdive: 'Provide comprehensive analysis including attack paths, remediation steps, code examples, and framework mappings.'
  };

  return `
As J.O.E. (Joint-Ops-Engine) Security Intelligence AI, analyze this ${elementType}:

**Context Data:**
\`\`\`json
${JSON.stringify(dataContext, null, 2)}
\`\`\`

**Required Framework Citations:** ${requestedFrameworks.join(', ')}

**Instructions:** ${depthInstructions[depth]}

For each finding, cite specific framework controls:
- NIST 800-53: Use format "AC-2", "SA-11"
- MITRE ATT&CK: Use format "T1190", "T1059.001"
- CIS Controls: Use format "CIS 5.1", "CIS 16.3"
- OWASP: Use format "A01:2021", "ASVS 4.0.3"

Structure your response with:
1. **Summary**: Brief overview
2. **Analysis**: Detailed findings
3. **Risk Assessment**: Impact and likelihood
4. **Citations**: Framework references
5. **Remediation**: Actionable steps
`.trim();
};

const parseRawResponse = (
  raw: string,
  context: TouchpointContext,
  startTime: number
): AITouchpointResponse => {
  // Extract summary (first paragraph or up to 200 chars)
  const summaryMatch = raw.match(/(?:\*\*summary\*\*[:\s]*)?([^#\n]+)/i);
  const summary = summaryMatch?.[1]?.trim()?.slice(0, 500) ?? raw.slice(0, 200);

  // Extract citations
  const citationRegex = /(?:NIST|CIS|MITRE|OWASP|NASA|DO-178C|CMMC)[\s-]*(?:\d+[-.\s]?\d*|ATT&CK|ASVS|STD)[^\n,]*/gi;
  const citationMatches = raw.match(citationRegex) ?? [];

  const citations = citationMatches.slice(0, 10).map(match => {
    const framework = detectFramework(match);
    return {
      framework,
      controlId: extractControlId(match),
      title: match.trim(),
      description: '',
      url: buildFrameworkUrl(framework, extractControlId(match)),
      relevance: 'direct' as const
    };
  });

  return {
    id: uuidv4(),
    requestContext: context,
    summary,
    detailedAnalysis: raw,
    citations,
    relatedItems: [],
    remediationSteps: [],
    confidence: 85,
    responseTime: Date.now() - startTime,
    cached: false,
    timestamp: Date.now()
  };
};

const detectFramework = (text: string): Framework => {
  const lower = text.toLowerCase();
  if (lower.includes('nist') && lower.includes('csf')) {return 'NIST-CSF-2.0';}
  if (lower.includes('nist') && lower.includes('800-53')) {return 'NIST-800-53';}
  if (lower.includes('nist') && lower.includes('800-171')) {return 'NIST-800-171';}
  if (lower.includes('mitre') && lower.includes('attack')) {return 'MITRE-ATTACK';}
  if (lower.includes('mitre') && lower.includes('defend')) {return 'MITRE-DEFEND';}
  if (lower.includes('cis')) {return 'CIS-CONTROLS';}
  if (lower.includes('owasp') && lower.includes('top')) {return 'OWASP-TOP-10';}
  if (lower.includes('owasp') && lower.includes('asvs')) {return 'OWASP-ASVS';}
  if (lower.includes('nasa')) {return 'NASA-STD-8719';}
  if (lower.includes('do-178')) {return 'DO-178C';}
  if (lower.includes('cmmc')) {return 'CMMC-2.0';}
  return 'NIST-800-53';
};

const extractControlId = (text: string): string => {
  const patterns = [
    /([A-Z]{2,3}-\d+(?:\.\d+)?)/,
    /(T\d{4}(?:\.\d{3})?)/,
    /(\d+\.\d+)/,
    /(A\d{2})/
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) {return match[1];}
  }
  return '';
};

const buildFrameworkUrl = (framework: Framework, controlId: string): string => {
  const urlBuilders: Record<Framework, (id: string) => string> = {
    'NIST-CSF-2.0': (_id) => `https://www.nist.gov/cyberframework/csf-20/${_id}`,
    'NIST-800-53': (_id) => `https://csrc.nist.gov/Projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=${_id}`,
    'NIST-800-171': (_id) => `https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final#${_id}`,
    'MITRE-ATTACK': (_id) => `https://attack.mitre.org/techniques/${_id}`,
    'MITRE-DEFEND': (_id) => `https://d3fend.mitre.org/technique/${_id}`,
    'CIS-CONTROLS': (_id) => `https://www.cisecurity.org/controls/v8`,
    'OWASP-TOP-10': (_id) => `https://owasp.org/Top10/${_id}`,
    'OWASP-ASVS': (_id) => `https://owasp.org/www-project-application-security-verification-standard`,
    'OWASP-SAMM': (_id) => `https://owaspsamm.org/model/${_id}`,
    'NASA-STD-8719': (_id) => `https://standards.nasa.gov/standard/NASA/NASA-STD-871913`,
    'DO-178C': (_id) => `https://www.rtca.org/content/do-178c`,
    'CMMC-2.0': (_id) => `https://dodcio.defense.gov/CMMC/Model/`,
    'COMMON-CRITERIA': (_id) => `https://www.commoncriteriaportal.org`,
    'ISO-27001': (_id) => `https://www.iso.org/standard/27001`,
    'SOC-2': (_id) => `https://www.aicpa.org/soc2`,
    'SLSA': (_id) => `https://slsa.dev/spec/v1.0/levels`
  };

  return urlBuilders[framework]?.(controlId) ?? '';
};

export default AITouchpointProvider;
