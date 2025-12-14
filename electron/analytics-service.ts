/**
 * J.O.E. DevSecOps Arsenal - Analytics Service
 * Self-Learning Intelligence Engine
 *
 * @module electron/analytics-service
 * @version 1.0.0
 *
 * Capabilities:
 * - Interaction tracking & behavior analysis
 * - AI query learning & optimization
 * - User expertise detection
 * - Security pattern recognition
 * - Personalized recommendations
 */

import { analyticsDb, InteractionRecord, AIQueryRecord, UserProfile, SecurityPattern } from './analytics-db';

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

export interface AIQueryEvent {
  prompt: string;
  response?: string;
  responseTimeMs?: number;
  elementType?: string;
  frameworks?: string[];
}

export interface LearningInsight {
  type: 'recommendation' | 'warning' | 'optimization' | 'pattern';
  title: string;
  description: string;
  actionable: boolean;
  priority: 'low' | 'medium' | 'high';
  data?: Record<string, unknown>;
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

// =============================================================================
// ANALYTICS SERVICE CLASS
// =============================================================================

class AnalyticsService {
  private currentUserId: string | null = null;
  private sessionStartTime: number = 0;

  // ===========================================================================
  // SESSION MANAGEMENT
  // ===========================================================================

  /**
   * Start a new analytics session
   */
  startSession(userId?: string): string {
    this.currentUserId = userId || null;
    this.sessionStartTime = Date.now();

    const sessionId = analyticsDb.startSession(userId);
    console.log('[J.O.E. Analytics] Session started for user:', userId || 'anonymous');

    return sessionId;
  }

  /**
   * End the current session
   */
  endSession(): void {
    analyticsDb.endSession();
    this.currentUserId = null;
    console.log('[J.O.E. Analytics] Session ended');
  }

  /**
   * Set the current user
   */
  setUser(userId: string): void {
    this.currentUserId = userId;

    // Ensure user profile exists
    analyticsDb.getOrCreateUserProfile(userId);
  }

  // ===========================================================================
  // INTERACTION TRACKING
  // ===========================================================================

  /**
   * Track a user interaction
   */
  track(event: TrackingEvent): string {
    const record: Omit<InteractionRecord, 'id' | 'sessionId'> = {
      timestamp: Date.now(),
      type: event.type,
      elementType: event.elementType,
      elementId: event.elementId || '',
      durationMs: event.durationMs || 0,
      contextJson: event.context ? JSON.stringify(event.context) : '',
      userId: this.currentUserId || undefined
    };

    const id = analyticsDb.trackInteraction(record);

    // Analyze for patterns in background
    this.analyzeInteractionPattern(event);

    return id;
  }

  /**
   * Track an AI query
   */
  trackAIQuery(event: AIQueryEvent): string {
    const record: Omit<AIQueryRecord, 'id' | 'timestamp' | 'promptHash'> = {
      prompt: event.prompt,
      response: event.response || '',
      responseTimeMs: event.responseTimeMs || 0,
      userRating: null,
      wasExpanded: false,
      ledToAction: false,
      elementType: event.elementType || '',
      frameworks: event.frameworks?.join(',') || '',
      userId: this.currentUserId || undefined
    };

    return analyticsDb.trackAIQuery(record);
  }

  /**
   * Rate an AI response (1-5)
   */
  rateResponse(queryId: string, rating: number): void {
    if (rating < 1 || rating > 5) {
      console.warn('[J.O.E. Analytics] Invalid rating:', rating);
      return;
    }

    analyticsDb.rateAIQuery(queryId, rating);

    // Learn from highly rated responses
    if (rating >= 4) {
      this.learnFromPositiveRating(queryId);
    }
  }

  /**
   * Mark that user expanded the response
   */
  markExpanded(queryId: string): void {
    analyticsDb.markQueryExpanded(queryId);
  }

  /**
   * Mark that the response led to user action
   */
  markActionTaken(queryId: string): void {
    analyticsDb.markQueryLedToAction(queryId);
  }

  // ===========================================================================
  // USER PROFILES & PERSONALIZATION
  // ===========================================================================

  /**
   * Get the current user's behavior profile
   */
  getUserProfile(): UserBehaviorProfile | null {
    if (!this.currentUserId) return null;

    const profile = analyticsDb.getOrCreateUserProfile(this.currentUserId);
    const expertiseLevel = analyticsDb.detectExpertiseLevel(this.currentUserId);
    const insights = analyticsDb.getInsights();

    // Calculate engagement score
    const engagementScore = this.calculateEngagementScore(profile, insights);

    // Parse stored JSON fields
    let preferredFrameworks: string[] = [];
    let commonElementTypes: string[] = [];

    try {
      preferredFrameworks = JSON.parse(profile.preferredFrameworks || '[]');
    } catch {
      preferredFrameworks = [];
    }

    // Get common element types from insights
    commonElementTypes = insights.topElementTypes.slice(0, 5).map(t => t.type);

    // Calculate peak usage hours
    const peakUsageHours = Object.entries(insights.interactionsByHour)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([hour]) => parseInt(hour));

    return {
      userId: this.currentUserId,
      expertiseLevel,
      preferredFrameworks,
      commonElementTypes,
      peakUsageHours,
      avgSessionMinutes: Math.round(profile.avgSessionDuration / 60000),
      totalInteractions: profile.totalInteractions,
      engagementScore
    };
  }

  /**
   * Calculate user engagement score (0-100)
   */
  private calculateEngagementScore(profile: UserProfile, insights: any): number {
    let score = 0;

    // Interaction frequency (max 30 points)
    if (profile.totalInteractions > 1000) score += 30;
    else if (profile.totalInteractions > 500) score += 25;
    else if (profile.totalInteractions > 100) score += 20;
    else if (profile.totalInteractions > 50) score += 15;
    else if (profile.totalInteractions > 10) score += 10;
    else score += 5;

    // Query depth (max 30 points) - based on avg rating given
    if (insights.avgQueryRating >= 4) score += 30;
    else if (insights.avgQueryRating >= 3) score += 20;
    else if (insights.avgQueryRating >= 2) score += 10;

    // Feature variety (max 20 points)
    const elementTypeCount = insights.topElementTypes.length;
    if (elementTypeCount >= 8) score += 20;
    else if (elementTypeCount >= 5) score += 15;
    else if (elementTypeCount >= 3) score += 10;
    else score += 5;

    // Recency (max 20 points)
    const daysSinceActive = (Date.now() - profile.lastActive) / (24 * 60 * 60 * 1000);
    if (daysSinceActive < 1) score += 20;
    else if (daysSinceActive < 7) score += 15;
    else if (daysSinceActive < 30) score += 10;
    else score += 5;

    return Math.min(100, score);
  }

  /**
   * Update user's preferred frameworks based on usage
   */
  updatePreferredFrameworks(frameworks: string[]): void {
    if (!this.currentUserId) return;

    const profile = analyticsDb.getOrCreateUserProfile(this.currentUserId);
    let existing: string[] = [];

    try {
      existing = JSON.parse(profile.preferredFrameworks || '[]');
    } catch {
      existing = [];
    }

    // Merge and deduplicate
    const updated = [...new Set([...frameworks, ...existing])].slice(0, 10);

    analyticsDb.updateUserProfile(this.currentUserId, {
      preferredFrameworks: JSON.stringify(updated)
    });
  }

  // ===========================================================================
  // PATTERN DETECTION & LEARNING
  // ===========================================================================

  /**
   * Analyze interaction for security patterns
   */
  private analyzeInteractionPattern(event: TrackingEvent): void {
    // Look for patterns worth recording

    // Pattern: Frequent dismissals of critical findings
    if (event.type === 'dismiss' && event.context?.severity === 'critical') {
      analyticsDb.recordPattern({
        patternType: 'critical_finding_dismissed',
        severity: 'high',
        description: `User dismissed critical finding: ${event.elementId}`,
        frequency: 1,
        recommendedActions: JSON.stringify([
          'Review dismissed critical findings',
          'Consider mandatory review workflow for critical items'
        ])
      });
    }

    // Pattern: Deep-dive on specific element types indicates interest
    if (event.type === 'deepdive' && event.durationMs && event.durationMs > 60000) {
      analyticsDb.recordPattern({
        patternType: 'extended_analysis',
        severity: 'info',
        description: `Extended analysis on ${event.elementType}: ${event.elementId}`,
        frequency: 1,
        recommendedActions: JSON.stringify([
          'Consider creating a focused report on this topic',
          'Recommend related security controls'
        ])
      });
    }

    // Pattern: Rapid-fire interactions may indicate frustration
    // (This would need a queue to track timing between events)
  }

  /**
   * Learn from positively rated responses
   */
  private learnFromPositiveRating(queryId: string): void {
    // In production, this would:
    // 1. Extract features from highly-rated prompts/responses
    // 2. Update model weights or prompt templates
    // 3. Cache effective response patterns

    console.log('[J.O.E. Analytics] Learning from positive rating:', queryId);
  }

  /**
   * Get detected security patterns
   */
  getSecurityPatterns(severity?: string): SecurityPattern[] {
    return analyticsDb.getPatterns(severity);
  }

  /**
   * Get learning insights
   */
  getLearningInsights(): LearningInsight[] {
    const insights: LearningInsight[] = [];
    const stats = analyticsDb.getStats();
    const patterns = analyticsDb.getPatterns(undefined, 20);

    // Insight: Low average rating
    if (stats.avgRating > 0 && stats.avgRating < 3) {
      insights.push({
        type: 'warning',
        title: 'AI Response Quality',
        description: `Average response rating is ${stats.avgRating.toFixed(1)}/5. Consider reviewing prompt engineering.`,
        actionable: true,
        priority: 'high',
        data: { avgRating: stats.avgRating }
      });
    }

    // Insight: High-frequency patterns
    const highFreqPatterns = patterns.filter(p => p.frequency >= 5);
    for (const pattern of highFreqPatterns) {
      insights.push({
        type: 'pattern',
        title: `Recurring Pattern: ${pattern.patternType}`,
        description: pattern.description,
        actionable: pattern.severity !== 'info',
        priority: pattern.severity === 'critical' ? 'high' : pattern.severity === 'high' ? 'medium' : 'low',
        data: { patternId: pattern.id, frequency: pattern.frequency }
      });
    }

    // Insight: Cache optimization
    const cacheInsights = analyticsDb.getInsights();
    if (stats.totalQueries > 100 && cacheInsights.cacheHitRate < 20) {
      insights.push({
        type: 'optimization',
        title: 'Cache Efficiency',
        description: `Cache hit rate is ${cacheInsights.cacheHitRate}%. Consider caching more common queries.`,
        actionable: true,
        priority: 'medium',
        data: { cacheHitRate: cacheInsights.cacheHitRate }
      });
    }

    // Insight: Top-rated response templates
    const topRated = analyticsDb.getTopRatedResponses(undefined, 3);
    if (topRated.length > 0) {
      insights.push({
        type: 'recommendation',
        title: 'High-Quality Response Patterns',
        description: `Found ${topRated.length} response patterns with 4+ star ratings that can be reused.`,
        actionable: true,
        priority: 'low',
        data: { count: topRated.length }
      });
    }

    return insights;
  }

  // ===========================================================================
  // STATISTICS & REPORTING
  // ===========================================================================

  /**
   * Get analytics statistics
   */
  getStats(): ReturnType<typeof analyticsDb.getStats> {
    return analyticsDb.getStats();
  }

  /**
   * Get analytics insights with optional timeframe
   */
  getInsights(timeframe?: { start: number; end: number }): ReturnType<typeof analyticsDb.getInsights> {
    return analyticsDb.getInsights(timeframe);
  }

  /**
   * Get recent interactions
   */
  getRecentInteractions(limit = 100): InteractionRecord[] {
    return analyticsDb.getRecentInteractions(limit, this.currentUserId || undefined);
  }

  /**
   * Get top-rated AI responses for learning
   */
  getTopRatedResponses(elementType?: string): ReturnType<typeof analyticsDb.getTopRatedResponses> {
    return analyticsDb.getTopRatedResponses(elementType);
  }

  // ===========================================================================
  // QUERY CACHING
  // ===========================================================================

  /**
   * Check if response is cached
   */
  getCachedResponse(prompt: string): string | null {
    return analyticsDb.getCachedResponse(prompt);
  }

  /**
   * Cache an AI response
   */
  cacheResponse(prompt: string, response: string): void {
    analyticsDb.cacheResponse(prompt, response);
  }

  // ===========================================================================
  // MAINTENANCE
  // ===========================================================================

  /**
   * Cleanup old data
   */
  cleanup(daysToKeep = 90): void {
    analyticsDb.pruneOldData(daysToKeep);
    analyticsDb.vacuum();
  }

  /**
   * Close database connection
   */
  shutdown(): void {
    this.endSession();
    analyticsDb.close();
  }
}

// Export singleton instance
export const analyticsService = new AnalyticsService();
export default analyticsService;
