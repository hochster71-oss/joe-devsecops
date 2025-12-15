/**
 * J.O.E. DevSecOps Arsenal - Analytics Database
 * SQLite-based Self-Learning Analytics Engine
 *
 * @module electron/analytics-db
 * @version 1.0.0
 *
 * Space-Grade Security Intelligence Tracking
 * - User interaction analytics
 * - AI query learning & optimization
 * - Behavior profiling for personalization
 * - Security pattern detection
 */

import Database from 'better-sqlite3';
import path from 'path';
import { app } from 'electron';
import crypto from 'crypto';
import fs from 'fs';

// =============================================================================
// DATABASE TYPES
// =============================================================================

export interface InteractionRecord {
  id: string;
  sessionId: string;
  timestamp: number;
  type: 'hover' | 'click' | 'deepdive' | 'dismiss' | 'expand' | 'rate';
  elementType: string;
  elementId: string;
  durationMs: number;
  contextJson: string;
  userId?: string;
}

export interface AIQueryRecord {
  id: string;
  timestamp: number;
  prompt: string;
  promptHash: string;
  response: string;
  responseTimeMs: number;
  userRating: number | null;
  wasExpanded: boolean;
  ledToAction: boolean;
  elementType: string;
  frameworks: string;
  userId?: string;
}

export interface UserProfile {
  userId: string;
  expertiseLevel: 'beginner' | 'intermediate' | 'expert';
  preferredFrameworks: string;
  commonQueries: string;
  interactionHeatmap: string;
  totalInteractions: number;
  avgSessionDuration: number;
  lastActive: number;
  createdAt: number;
  updatedAt: number;
}

export interface SecurityPattern {
  id: number;
  patternType: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  description: string;
  frequency: number;
  recommendedActions: string;
  detectedAt: number;
  lastSeen: number;
}

export interface SessionRecord {
  id: string;
  userId: string;
  startTime: number;
  endTime: number | null;
  interactionCount: number;
  aiQueriesCount: number;
  pagesVisited: string;
}

// =============================================================================
// ANALYTICS DATABASE CLASS
// =============================================================================

class AnalyticsDatabase {
  private db: Database.Database | null = null;
  private dbPath: string;
  private currentSessionId: string | null = null;

  constructor() {
    // Store in user data directory
    const userDataPath = app?.getPath?.('userData') || './data';
    this.dbPath = path.join(userDataPath, 'joe-analytics.db');
  }

  // ===========================================================================
  // INITIALIZATION
  // ===========================================================================

  initialize(): void {
    if (this.db) {return;}

    console.log('[J.O.E. Analytics DB] Initializing at:', this.dbPath);

    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');

    this.createTables();
    this.createIndexes();

    console.log('[J.O.E. Analytics DB] Database initialized successfully');
  }

  private createTables(): void {
    if (!this.db) {return;}

    // User interactions tracking
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS interactions (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        type TEXT NOT NULL,
        element_type TEXT NOT NULL,
        element_id TEXT,
        duration_ms INTEGER DEFAULT 0,
        context_json TEXT,
        user_id TEXT
      )
    `);

    // AI query learning
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ai_queries (
        id TEXT PRIMARY KEY,
        timestamp INTEGER NOT NULL,
        prompt TEXT NOT NULL,
        prompt_hash TEXT NOT NULL,
        response TEXT,
        response_time_ms INTEGER,
        user_rating INTEGER,
        was_expanded INTEGER DEFAULT 0,
        led_to_action INTEGER DEFAULT 0,
        element_type TEXT,
        frameworks TEXT,
        user_id TEXT
      )
    `);

    // User behavior profiles
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS user_profiles (
        user_id TEXT PRIMARY KEY,
        expertise_level TEXT DEFAULT 'intermediate',
        preferred_frameworks TEXT DEFAULT '[]',
        common_queries TEXT DEFAULT '[]',
        interaction_heatmap TEXT DEFAULT '{}',
        total_interactions INTEGER DEFAULT 0,
        avg_session_duration INTEGER DEFAULT 0,
        last_active INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);

    // Detected security patterns
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS security_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_type TEXT NOT NULL,
        severity TEXT DEFAULT 'info',
        description TEXT,
        frequency INTEGER DEFAULT 1,
        recommended_actions TEXT,
        detected_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
      )
    `);

    // Sessions tracking
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        start_time INTEGER NOT NULL,
        end_time INTEGER,
        interaction_count INTEGER DEFAULT 0,
        ai_queries_count INTEGER DEFAULT 0,
        pages_visited TEXT DEFAULT '[]'
      )
    `);

    // Query cache for faster responses
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS query_cache (
        prompt_hash TEXT PRIMARY KEY,
        response TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        hit_count INTEGER DEFAULT 1,
        last_accessed INTEGER NOT NULL
      )
    `);
  }

  private createIndexes(): void {
    if (!this.db) {return;}

    // Interaction indexes
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_interactions_timestamp ON interactions(timestamp)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_interactions_type ON interactions(type)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_interactions_user ON interactions(user_id)`);

    // AI query indexes
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_queries_prompt_hash ON ai_queries(prompt_hash)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON ai_queries(timestamp)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_queries_rating ON ai_queries(user_rating)`);

    // Pattern indexes
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_patterns_type ON security_patterns(pattern_type)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_patterns_severity ON security_patterns(severity)`);
  }

  // ===========================================================================
  // SESSION MANAGEMENT
  // ===========================================================================

  startSession(userId?: string): string {
    this.initialize();
    if (!this.db) {throw new Error('Database not initialized');}

    const sessionId = crypto.randomUUID();
    const now = Date.now();

    const stmt = this.db.prepare(`
      INSERT INTO sessions (id, user_id, start_time, interaction_count, ai_queries_count, pages_visited)
      VALUES (?, ?, ?, 0, 0, '[]')
    `);
    stmt.run(sessionId, userId || null, now);

    this.currentSessionId = sessionId;
    console.log('[J.O.E. Analytics DB] Session started:', sessionId);

    return sessionId;
  }

  endSession(sessionId?: string): void {
    if (!this.db) {return;}

    const id = sessionId || this.currentSessionId;
    if (!id) {return;}

    const stmt = this.db.prepare(`
      UPDATE sessions SET end_time = ? WHERE id = ?
    `);
    stmt.run(Date.now(), id);

    if (id === this.currentSessionId) {
      this.currentSessionId = null;
    }

    console.log('[J.O.E. Analytics DB] Session ended:', id);
  }

  getCurrentSessionId(): string {
    if (!this.currentSessionId) {
      return this.startSession();
    }
    return this.currentSessionId;
  }

  // ===========================================================================
  // INTERACTION TRACKING
  // ===========================================================================

  trackInteraction(interaction: Omit<InteractionRecord, 'id' | 'sessionId'>): string {
    this.initialize();
    if (!this.db) {throw new Error('Database not initialized');}

    const id = crypto.randomUUID();
    const sessionId = this.getCurrentSessionId();

    const stmt = this.db.prepare(`
      INSERT INTO interactions (id, session_id, timestamp, type, element_type, element_id, duration_ms, context_json, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      sessionId,
      interaction.timestamp,
      interaction.type,
      interaction.elementType,
      interaction.elementId || null,
      interaction.durationMs || 0,
      interaction.contextJson || null,
      interaction.userId || null
    );

    // Update session interaction count
    const updateSession = this.db.prepare(`
      UPDATE sessions SET interaction_count = interaction_count + 1 WHERE id = ?
    `);
    updateSession.run(sessionId);

    // Update user profile
    if (interaction.userId) {
      this.updateUserInteractionCount(interaction.userId);
    }

    return id;
  }

  getRecentInteractions(limit = 100, userId?: string): InteractionRecord[] {
    this.initialize();
    if (!this.db) {return [];}

    let query = `SELECT * FROM interactions`;
    const params: (string | number)[] = [];

    if (userId) {
      query += ` WHERE user_id = ?`;
      params.push(userId);
    }

    query += ` ORDER BY timestamp DESC LIMIT ?`;
    params.push(limit);

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as Record<string, unknown>[];

    return rows.map(row => ({
      id: row.id as string,
      sessionId: row.session_id as string,
      timestamp: row.timestamp as number,
      type: row.type as string,
      elementType: row.element_type as string,
      elementId: row.element_id as string | undefined,
      durationMs: row.duration_ms as number | undefined,
      contextJson: row.context_json as string | undefined,
      userId: row.user_id as string | undefined
    }));
  }

  // ===========================================================================
  // AI QUERY TRACKING
  // ===========================================================================

  trackAIQuery(query: Omit<AIQueryRecord, 'id' | 'timestamp' | 'promptHash'>): string {
    this.initialize();
    if (!this.db) {throw new Error('Database not initialized');}

    const id = crypto.randomUUID();
    const promptHash = this.hashPrompt(query.prompt);

    const stmt = this.db.prepare(`
      INSERT INTO ai_queries (id, timestamp, prompt, prompt_hash, response, response_time_ms, user_rating, was_expanded, led_to_action, element_type, frameworks, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      Date.now(),
      query.prompt,
      promptHash,
      query.response || null,
      query.responseTimeMs || 0,
      query.userRating,
      query.wasExpanded ? 1 : 0,
      query.ledToAction ? 1 : 0,
      query.elementType || null,
      query.frameworks || null,
      query.userId || null
    );

    // Update session AI queries count
    if (this.currentSessionId) {
      const updateSession = this.db.prepare(`
        UPDATE sessions SET ai_queries_count = ai_queries_count + 1 WHERE id = ?
      `);
      updateSession.run(this.currentSessionId);
    }

    return id;
  }

  rateAIQuery(queryId: string, rating: number): void {
    this.initialize();
    if (!this.db) {return;}

    const stmt = this.db.prepare(`
      UPDATE ai_queries SET user_rating = ? WHERE id = ?
    `);
    stmt.run(rating, queryId);

    console.log('[J.O.E. Analytics DB] Query rated:', queryId, 'Rating:', rating);
  }

  markQueryExpanded(queryId: string): void {
    this.initialize();
    if (!this.db) {return;}

    const stmt = this.db.prepare(`
      UPDATE ai_queries SET was_expanded = 1 WHERE id = ?
    `);
    stmt.run(queryId);
  }

  markQueryLedToAction(queryId: string): void {
    this.initialize();
    if (!this.db) {return;}

    const stmt = this.db.prepare(`
      UPDATE ai_queries SET led_to_action = 1 WHERE id = ?
    `);
    stmt.run(queryId);
  }

  private hashPrompt(prompt: string): string {
    return crypto.createHash('sha256').update(prompt).digest('hex').substring(0, 16);
  }

  // ===========================================================================
  // QUERY CACHE
  // ===========================================================================

  getCachedResponse(prompt: string): string | null {
    this.initialize();
    if (!this.db) {return null;}

    const promptHash = this.hashPrompt(prompt);
    const stmt = this.db.prepare(`
      SELECT response FROM query_cache WHERE prompt_hash = ?
    `);
    const row = stmt.get(promptHash) as { response: string } | undefined;

    if (row) {
      // Update hit count and last accessed
      const update = this.db.prepare(`
        UPDATE query_cache SET hit_count = hit_count + 1, last_accessed = ? WHERE prompt_hash = ?
      `);
      update.run(Date.now(), promptHash);
      return row.response;
    }

    return null;
  }

  cacheResponse(prompt: string, response: string): void {
    this.initialize();
    if (!this.db) {return;}

    const promptHash = this.hashPrompt(prompt);
    const now = Date.now();

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO query_cache (prompt_hash, response, created_at, hit_count, last_accessed)
      VALUES (?, ?, ?, COALESCE((SELECT hit_count FROM query_cache WHERE prompt_hash = ?), 0) + 1, ?)
    `);
    stmt.run(promptHash, response, now, promptHash, now);
  }

  // ===========================================================================
  // USER PROFILES
  // ===========================================================================

  getOrCreateUserProfile(userId: string): UserProfile {
    this.initialize();
    if (!this.db) {throw new Error('Database not initialized');}

    const selectStmt = this.db.prepare(`SELECT * FROM user_profiles WHERE user_id = ?`);
    const row = selectStmt.get(userId) as Record<string, unknown> | undefined;

    if (row) {
      return {
        userId: row.user_id as string,
        expertiseLevel: row.expertise_level as UserProfile['expertiseLevel'],
        preferredFrameworks: row.preferred_frameworks as string,
        commonQueries: row.common_queries as string,
        interactionHeatmap: row.interaction_heatmap as string,
        totalInteractions: row.total_interactions as number,
        avgSessionDuration: row.avg_session_duration as number,
        lastActive: row.last_active as number,
        createdAt: row.created_at as number,
        updatedAt: row.updated_at as number
      };
    }

    // Create new profile
    const now = Date.now();
    const insertStmt = this.db.prepare(`
      INSERT INTO user_profiles (user_id, created_at, updated_at, last_active)
      VALUES (?, ?, ?, ?)
    `);
    insertStmt.run(userId, now, now, now);

    return {
      userId,
      expertiseLevel: 'intermediate',
      preferredFrameworks: '[]',
      commonQueries: '[]',
      interactionHeatmap: '{}',
      totalInteractions: 0,
      avgSessionDuration: 0,
      lastActive: now,
      createdAt: now,
      updatedAt: now
    };
  }

  updateUserProfile(userId: string, updates: Partial<UserProfile>): void {
    this.initialize();
    if (!this.db) {return;}

    const fields: string[] = [];
    const values: (string | number)[] = [];

    if (updates.expertiseLevel) {
      fields.push('expertise_level = ?');
      values.push(updates.expertiseLevel);
    }
    if (updates.preferredFrameworks) {
      fields.push('preferred_frameworks = ?');
      values.push(updates.preferredFrameworks);
    }
    if (updates.commonQueries) {
      fields.push('common_queries = ?');
      values.push(updates.commonQueries);
    }
    if (updates.interactionHeatmap) {
      fields.push('interaction_heatmap = ?');
      values.push(updates.interactionHeatmap);
    }

    fields.push('updated_at = ?', 'last_active = ?');
    const now = Date.now();
    values.push(now, now, userId);

    const stmt = this.db.prepare(`
      UPDATE user_profiles SET ${fields.join(', ')} WHERE user_id = ?
    `);
    stmt.run(...values);
  }

  private updateUserInteractionCount(userId: string): void {
    if (!this.db) {return;}

    const stmt = this.db.prepare(`
      UPDATE user_profiles
      SET total_interactions = total_interactions + 1, last_active = ?, updated_at = ?
      WHERE user_id = ?
    `);
    const now = Date.now();
    stmt.run(now, now, userId);
  }

  // ===========================================================================
  // PATTERN DETECTION
  // ===========================================================================

  recordPattern(pattern: Omit<SecurityPattern, 'id' | 'detectedAt' | 'lastSeen'>): number {
    this.initialize();
    if (!this.db) {throw new Error('Database not initialized');}

    const now = Date.now();

    // Check if pattern already exists
    const selectStmt = this.db.prepare(`
      SELECT id, frequency FROM security_patterns WHERE pattern_type = ? AND description = ?
    `);
    const existing = selectStmt.get(pattern.patternType, pattern.description) as { id: number; frequency: number } | undefined;

    if (existing) {
      // Update frequency and last_seen
      const updateStmt = this.db.prepare(`
        UPDATE security_patterns SET frequency = ?, last_seen = ? WHERE id = ?
      `);
      updateStmt.run(existing.frequency + 1, now, existing.id);
      return existing.id;
    }

    // Insert new pattern
    const insertStmt = this.db.prepare(`
      INSERT INTO security_patterns (pattern_type, severity, description, frequency, recommended_actions, detected_at, last_seen)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    const result = insertStmt.run(
      pattern.patternType,
      pattern.severity,
      pattern.description,
      pattern.frequency,
      pattern.recommendedActions,
      now,
      now
    );

    return result.lastInsertRowid as number;
  }

  getPatterns(severity?: string, limit = 50): SecurityPattern[] {
    this.initialize();
    if (!this.db) {return [];}

    let query = `SELECT * FROM security_patterns`;
    const params: (string | number)[] = [];

    if (severity) {
      query += ` WHERE severity = ?`;
      params.push(severity);
    }

    query += ` ORDER BY frequency DESC, last_seen DESC LIMIT ?`;
    params.push(limit);

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as Record<string, unknown>[];

    return rows.map(row => ({
      id: row.id as number,
      patternType: row.pattern_type as string,
      severity: row.severity as 'critical' | 'high' | 'medium' | 'low',
      description: row.description as string,
      frequency: row.frequency as number,
      recommendedActions: row.recommended_actions as string,
      detectedAt: row.detected_at as number,
      lastSeen: row.last_seen as number
    }));
  }

  // ===========================================================================
  // ANALYTICS & INSIGHTS
  // ===========================================================================

  getInsights(timeframe?: { start: number; end: number }): {
    totalInteractions: number;
    totalQueries: number;
    avgQueryRating: number;
    topElementTypes: Array<{ type: string; count: number }>;
    interactionsByHour: Record<number, number>;
    avgResponseTime: number;
    cacheHitRate: number;
  } {
    this.initialize();
    if (!this.db) {
      return {
        totalInteractions: 0,
        totalQueries: 0,
        avgQueryRating: 0,
        topElementTypes: [],
        interactionsByHour: {},
        avgResponseTime: 0,
        cacheHitRate: 0
      };
    }

    const whereClause = timeframe
      ? `WHERE timestamp >= ${timeframe.start} AND timestamp <= ${timeframe.end}`
      : '';

    // Total interactions
    const interactionsStmt = this.db.prepare(`SELECT COUNT(*) as count FROM interactions ${whereClause}`);
    const totalInteractions = (interactionsStmt.get() as { count: number }).count;

    // Total AI queries
    const queriesStmt = this.db.prepare(`SELECT COUNT(*) as count FROM ai_queries ${whereClause}`);
    const totalQueries = (queriesStmt.get() as { count: number }).count;

    // Average rating
    const ratingStmt = this.db.prepare(`SELECT AVG(user_rating) as avg FROM ai_queries WHERE user_rating IS NOT NULL ${timeframe ? `AND timestamp >= ${timeframe.start} AND timestamp <= ${timeframe.end}` : ''}`);
    const avgQueryRating = (ratingStmt.get() as { avg: number | null }).avg || 0;

    // Top element types
    const elementsStmt = this.db.prepare(`
      SELECT element_type as type, COUNT(*) as count
      FROM interactions ${whereClause}
      GROUP BY element_type
      ORDER BY count DESC
      LIMIT 10
    `);
    const topElementTypes = elementsStmt.all() as Array<{ type: string; count: number }>;

    // Interactions by hour
    const hourStmt = this.db.prepare(`
      SELECT
        CAST(strftime('%H', timestamp / 1000, 'unixepoch') AS INTEGER) as hour,
        COUNT(*) as count
      FROM interactions ${whereClause}
      GROUP BY hour
    `);
    const hourRows = hourStmt.all() as Array<{ hour: number; count: number }>;
    const interactionsByHour: Record<number, number> = {};
    hourRows.forEach(row => {
      interactionsByHour[row.hour] = row.count;
    });

    // Average response time
    const responseTimeStmt = this.db.prepare(`SELECT AVG(response_time_ms) as avg FROM ai_queries ${whereClause}`);
    const avgResponseTime = (responseTimeStmt.get() as { avg: number | null }).avg || 0;

    // Cache hit rate
    const cacheStmt = this.db.prepare(`SELECT SUM(hit_count) as hits, COUNT(*) as total FROM query_cache`);
    const cacheData = cacheStmt.get() as { hits: number; total: number };
    const cacheHitRate = cacheData.total > 0 ? cacheData.hits / (cacheData.hits + cacheData.total) : 0;

    return {
      totalInteractions,
      totalQueries,
      avgQueryRating: Math.round(avgQueryRating * 100) / 100,
      topElementTypes,
      interactionsByHour,
      avgResponseTime: Math.round(avgResponseTime),
      cacheHitRate: Math.round(cacheHitRate * 100)
    };
  }

  getStats(): {
    totalInteractions: number;
    totalQueries: number;
    totalSessions: number;
    totalUsers: number;
    avgRating: number;
    cacheSize: number;
    dbSize: string;
  } {
    this.initialize();
    if (!this.db) {
      return {
        totalInteractions: 0,
        totalQueries: 0,
        totalSessions: 0,
        totalUsers: 0,
        avgRating: 0,
        cacheSize: 0,
        dbSize: '0 KB'
      };
    }

    const interactions = (this.db.prepare(`SELECT COUNT(*) as c FROM interactions`).get() as { c: number }).c;
    const queries = (this.db.prepare(`SELECT COUNT(*) as c FROM ai_queries`).get() as { c: number }).c;
    const sessions = (this.db.prepare(`SELECT COUNT(*) as c FROM sessions`).get() as { c: number }).c;
    const users = (this.db.prepare(`SELECT COUNT(*) as c FROM user_profiles`).get() as { c: number }).c;
    const avgRating = (this.db.prepare(`SELECT AVG(user_rating) as a FROM ai_queries WHERE user_rating IS NOT NULL`).get() as { a: number | null }).a || 0;
    const cacheSize = (this.db.prepare(`SELECT COUNT(*) as c FROM query_cache`).get() as { c: number }).c;

    // Get database file size
    let dbSize = '0 KB';
    try {
      const statsResult = fs.statSync(this.dbPath);
      const bytes = statsResult.size;
      if (bytes < 1024) {dbSize = `${bytes} B`;}
      else if (bytes < 1024 * 1024) {dbSize = `${Math.round(bytes / 1024)} KB`;}
      else {dbSize = `${Math.round(bytes / (1024 * 1024) * 10) / 10} MB`;}
    } catch {
      // Ignore file stat errors
    }

    return {
      totalInteractions: interactions,
      totalQueries: queries,
      totalSessions: sessions,
      totalUsers: users,
      avgRating: Math.round(avgRating * 100) / 100,
      cacheSize,
      dbSize
    };
  }

  // ===========================================================================
  // LEARNING & OPTIMIZATION
  // ===========================================================================

  getTopRatedResponses(elementType?: string, limit = 10): Array<{
    prompt: string;
    response: string;
    avgRating: number;
    usageCount: number;
  }> {
    this.initialize();
    if (!this.db) {return [];}

    let query = `
      SELECT prompt, response, AVG(user_rating) as avg_rating, COUNT(*) as usage_count
      FROM ai_queries
      WHERE user_rating IS NOT NULL
    `;

    const params: (string | number)[] = [];

    if (elementType) {
      query += ` AND element_type = ?`;
      params.push(elementType);
    }

    query += `
      GROUP BY prompt_hash
      HAVING avg_rating >= 4
      ORDER BY avg_rating DESC, usage_count DESC
      LIMIT ?
    `;
    params.push(limit);

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as Array<Record<string, unknown>>;

    return rows.map(row => ({
      prompt: row.prompt as string,
      response: row.response as string,
      avgRating: row.avg_rating as number,
      usageCount: row.usage_count as number
    }));
  }

  detectExpertiseLevel(userId: string): 'beginner' | 'intermediate' | 'expert' {
    this.initialize();
    if (!this.db) {return 'intermediate';}

    const profile = this.getOrCreateUserProfile(userId);

    // Analyze interaction patterns
    const depthStmt = this.db.prepare(`
      SELECT
        SUM(CASE WHEN type = 'deepdive' THEN 1 ELSE 0 END) as deepdives,
        SUM(CASE WHEN type = 'hover' THEN 1 ELSE 0 END) as hovers,
        COUNT(*) as total
      FROM interactions
      WHERE user_id = ?
    `);
    const depthData = depthStmt.get(userId) as { deepdives: number; hovers: number; total: number };

    // More deep-dives relative to hovers suggests expert
    const deepdiveRatio = depthData.total > 0 ? depthData.deepdives / depthData.total : 0;
    const _hoverRatio = depthData.total > 0 ? depthData.hovers / depthData.total : 0;

    // Check average session duration
    const sessionStmt = this.db.prepare(`
      SELECT AVG(end_time - start_time) as avg_duration
      FROM sessions
      WHERE user_id = ? AND end_time IS NOT NULL
    `);
    const sessionData = sessionStmt.get(userId) as { avg_duration: number | null };
    const avgDuration = sessionData.avg_duration || 0;

    // Scoring
    let score = 0;

    // Deep-dive usage indicates expertise
    if (deepdiveRatio > 0.3) {score += 2;}
    else if (deepdiveRatio > 0.1) {score += 1;}

    // Longer sessions indicate thorough analysis
    if (avgDuration > 30 * 60 * 1000) {score += 2;} // > 30 min
    else if (avgDuration > 10 * 60 * 1000) {score += 1;} // > 10 min

    // Total interactions indicate engagement
    if (profile.totalInteractions > 500) {score += 2;}
    else if (profile.totalInteractions > 100) {score += 1;}

    // Determine level
    if (score >= 4) {return 'expert';}
    if (score >= 2) {return 'intermediate';}
    return 'beginner';
  }

  // ===========================================================================
  // CLEANUP
  // ===========================================================================

  pruneOldData(daysToKeep = 90): void {
    this.initialize();
    if (!this.db) {return;}

    const cutoff = Date.now() - (daysToKeep * 24 * 60 * 60 * 1000);

    const interactions = this.db.prepare(`DELETE FROM interactions WHERE timestamp < ?`).run(cutoff);
    const queries = this.db.prepare(`DELETE FROM ai_queries WHERE timestamp < ?`).run(cutoff);
    const sessions = this.db.prepare(`DELETE FROM sessions WHERE end_time < ?`).run(cutoff);

    console.log('[J.O.E. Analytics DB] Pruned old data:', {
      interactions: interactions.changes,
      queries: queries.changes,
      sessions: sessions.changes
    });
  }

  vacuum(): void {
    this.initialize();
    if (!this.db) {return;}

    this.db.exec('VACUUM');
    console.log('[J.O.E. Analytics DB] Database vacuumed');
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
      console.log('[J.O.E. Analytics DB] Database closed');
    }
  }
}

// Export singleton instance
export const analyticsDb = new AnalyticsDatabase();
export default analyticsDb;
