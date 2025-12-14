/**
 * J.O.E. DevSecOps Arsenal - Analytics Store
 * Zustand store for self-learning analytics in renderer
 *
 * @module store/analyticsStore
 * @version 1.0.0
 */

import { create } from 'zustand';

// =============================================================================
// ELECTRON API HELPER
// =============================================================================

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const getElectronAPI = (): any => (window as any).electronAPI;

// =============================================================================
// TYPES
// =============================================================================

export interface TrackingEvent {
  type: 'hover' | 'click' | 'deepdive' | 'dismiss' | 'expand' | 'rate';
  elementType: string;
  elementId?: string;
  durationMs?: number;
  context?: Record<string, unknown>;
}

export interface UserBehaviorProfile {
  userId: string;
  expertiseLevel: 'beginner' | 'intermediate' | 'expert';
  preferredFrameworks: string[];
  commonElementTypes: string[];
  peakUsageHours: number[];
  avgSessionMinutes: number;
  totalInteractions: number;
  engagementScore: number;
}

export interface AnalyticsInsights {
  totalInteractions: number;
  totalQueries: number;
  avgQueryRating: number;
  topElementTypes: Array<{ type: string; count: number }>;
  interactionsByHour: Record<number, number>;
  avgResponseTime: number;
  cacheHitRate: number;
}

export interface AnalyticsStats {
  totalInteractions: number;
  totalQueries: number;
  totalSessions: number;
  totalUsers: number;
  avgRating: number;
  cacheSize: number;
  dbSize: string;
}

export interface LearningInsight {
  type: 'recommendation' | 'warning' | 'optimization' | 'pattern';
  title: string;
  description: string;
  actionable: boolean;
  priority: 'low' | 'medium' | 'high';
  data?: Record<string, unknown>;
}

export interface SecurityPattern {
  id: number;
  patternType: string;
  severity: string;
  description: string;
  frequency: number;
  recommendedActions: string;
  detectedAt: number;
  lastSeen: number;
}

interface AnalyticsState {
  // State
  isInitialized: boolean;
  isLoading: boolean;
  profile: UserBehaviorProfile | null;
  insights: AnalyticsInsights | null;
  stats: AnalyticsStats | null;
  learningInsights: LearningInsight[];
  patterns: SecurityPattern[];
  error: string | null;

  // Actions
  initialize: () => Promise<void>;
  track: (event: TrackingEvent) => Promise<string>;
  rateResponse: (queryId: string, rating: number) => Promise<void>;
  fetchProfile: () => Promise<void>;
  fetchInsights: (timeframe?: { start: number; end: number }) => Promise<void>;
  fetchStats: () => Promise<void>;
  fetchLearningInsights: () => Promise<void>;
  fetchPatterns: (severity?: string) => Promise<void>;
  clearError: () => void;
}

// =============================================================================
// STORE
// =============================================================================

export const useAnalyticsStore = create<AnalyticsState>((set, get) => ({
  // Initial state
  isInitialized: false,
  isLoading: false,
  profile: null,
  insights: null,
  stats: null,
  learningInsights: [],
  patterns: [],
  error: null,

  // ===========================================================================
  // INITIALIZATION
  // ===========================================================================

  initialize: async () => {
    if (get().isInitialized) {return;}

    set({ isLoading: true, error: null });

    try {
      // Fetch initial data in parallel
      await Promise.all([
        get().fetchStats(),
        get().fetchInsights(),
        get().fetchProfile()
      ]);

      set({ isInitialized: true, isLoading: false });
      console.log('[Analytics Store] Initialized');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to initialize analytics';
      set({ error: message, isLoading: false });
      console.error('[Analytics Store] Initialization error:', error);
    }
  },

  // ===========================================================================
  // TRACKING
  // ===========================================================================

  track: async (event: TrackingEvent): Promise<string> => {
    try {
      const result = await getElectronAPI()?.analytics?.track({
        type: event.type,
        elementType: event.elementType,
        elementId: event.elementId,
        durationMs: event.durationMs,
        context: event.context
      });

      return result?.id || '';
    } catch (error) {
      console.error('[Analytics Store] Track error:', error);
      return '';
    }
  },

  rateResponse: async (queryId: string, rating: number): Promise<void> => {
    try {
      await getElectronAPI()?.analytics?.rate(queryId, rating);

      // Update stats after rating
      get().fetchStats();
    } catch (error) {
      console.error('[Analytics Store] Rate error:', error);
    }
  },

  // ===========================================================================
  // DATA FETCHING
  // ===========================================================================

  fetchProfile: async () => {
    try {
      const profile = await getElectronAPI()?.analytics?.getProfile();
      set({ profile: profile || null });
    } catch (error) {
      console.error('[Analytics Store] Fetch profile error:', error);
    }
  },

  fetchInsights: async (timeframe?: { start: number; end: number }) => {
    try {
      const insights = await getElectronAPI()?.analytics?.getInsights(timeframe);
      set({ insights: insights || null });
    } catch (error) {
      console.error('[Analytics Store] Fetch insights error:', error);
    }
  },

  fetchStats: async () => {
    try {
      const stats = await getElectronAPI()?.analytics?.getStats();
      set({ stats: stats || null });
    } catch (error) {
      console.error('[Analytics Store] Fetch stats error:', error);
    }
  },

  fetchLearningInsights: async () => {
    try {
      // This would call a dedicated IPC method for learning insights
      // For now, we'll construct basic insights from patterns
      const patterns = await getElectronAPI()?.analytics?.getPatterns() || [];
      const insights: LearningInsight[] = [];

      // Convert high-frequency patterns to insights
      for (const pattern of (patterns as SecurityPattern[]).filter((p: SecurityPattern) => p.frequency >= 3)) {
        insights.push({
          type: 'pattern',
          title: `Recurring: ${pattern.patternType}`,
          description: pattern.description,
          actionable: pattern.severity !== 'info',
          priority: pattern.severity === 'critical' ? 'high' : pattern.severity === 'high' ? 'medium' : 'low',
          data: { patternId: pattern.id, frequency: pattern.frequency }
        });
      }

      set({ learningInsights: insights });
    } catch (error) {
      console.error('[Analytics Store] Fetch learning insights error:', error);
    }
  },

  fetchPatterns: async (severity?: string) => {
    try {
      const patterns = await getElectronAPI()?.analytics?.getPatterns(severity) || [];
      set({ patterns: patterns as SecurityPattern[] });
    } catch (error) {
      console.error('[Analytics Store] Fetch patterns error:', error);
    }
  },

  clearError: () => set({ error: null })
}));

// =============================================================================
// HOOKS
// =============================================================================

/**
 * Hook to track element interactions
 */
export const useTrackInteraction = () => {
  const track = useAnalyticsStore(state => state.track);

  return {
    trackHover: (elementType: string, elementId?: string, context?: Record<string, unknown>) =>
      track({ type: 'hover', elementType, elementId, context }),

    trackClick: (elementType: string, elementId?: string, context?: Record<string, unknown>) =>
      track({ type: 'click', elementType, elementId, context }),

    trackDeepDive: (elementType: string, elementId?: string, durationMs?: number, context?: Record<string, unknown>) =>
      track({ type: 'deepdive', elementType, elementId, durationMs, context }),

    trackDismiss: (elementType: string, elementId?: string, context?: Record<string, unknown>) =>
      track({ type: 'dismiss', elementType, elementId, context }),

    trackExpand: (elementType: string, elementId?: string, context?: Record<string, unknown>) =>
      track({ type: 'expand', elementType, elementId, context })
  };
};

/**
 * Hook to get user's expertise level for UI adaptation
 */
export const useExpertiseLevel = () => {
  const profile = useAnalyticsStore(state => state.profile);
  return profile?.expertiseLevel || 'intermediate';
};

/**
 * Hook to get engagement score
 */
export const useEngagementScore = () => {
  const profile = useAnalyticsStore(state => state.profile);
  return profile?.engagementScore || 0;
};

export default useAnalyticsStore;
