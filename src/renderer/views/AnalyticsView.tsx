/**
 * J.O.E. DevSecOps Arsenal - Analytics Dashboard
 * Self-Learning Intelligence & User Behavior Analytics
 *
 * Dark Wolf Solutions - Space-Grade Security Platform
 * @version 1.0.0
 */

import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Brain,
  BarChart3,
  TrendingUp,
  Activity,
  Users,
  Clock,
  Target,
  Zap,
  RefreshCw,
  Database,
  Shield,
  AlertTriangle,
  CheckCircle,
  ChevronRight,
  Sparkles,
  LineChart,
  PieChart,
  Star,
  Eye,
  MousePointer,
  Layers,
  ArrowUp,
  ArrowDown,
  Minus
} from 'lucide-react';
import { useAnalyticsStore, SecurityPattern, LearningInsight } from '../store/analyticsStore';

export default function AnalyticsView() {
  const {
    isInitialized,
    isLoading,
    profile,
    insights,
    stats,
    learningInsights,
    patterns,
    error,
    initialize,
    fetchStats,
    fetchInsights,
    fetchPatterns,
    fetchLearningInsights,
    clearError
  } = useAnalyticsStore();

  const [activeTab, setActiveTab] = useState<'overview' | 'patterns' | 'learning'>('overview');
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d' | 'all'>('7d');

  // Initialize analytics on mount
  useEffect(() => {
    if (!isInitialized) {
      initialize();
    }
  }, [isInitialized, initialize]);

  // Fetch patterns and learning insights
  useEffect(() => {
    if (isInitialized) {
      fetchPatterns();
      fetchLearningInsights();
    }
  }, [isInitialized, fetchPatterns, fetchLearningInsights]);

  const handleRefresh = async () => {
    await Promise.all([
      fetchStats(),
      fetchInsights(),
      fetchPatterns(),
      fetchLearningInsights()
    ]);
  };

  const getExpertiseBadge = (level: string) => {
    switch (level) {
      case 'expert': return { color: 'text-purple-400 bg-purple-400/10', label: 'Expert' };
      case 'intermediate': return { color: 'text-joe-blue bg-joe-blue/10', label: 'Intermediate' };
      default: return { color: 'text-dws-green bg-dws-green/10', label: 'Beginner' };
    }
  };

  const getSeverityConfig = (severity: string) => {
    switch (severity) {
      case 'critical': return { color: 'text-alert-critical', bg: 'bg-alert-critical/10', border: 'border-alert-critical/30' };
      case 'high': return { color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/30' };
      case 'medium': return { color: 'text-alert-warning', bg: 'bg-alert-warning/10', border: 'border-alert-warning/30' };
      default: return { color: 'text-dws-green', bg: 'bg-dws-green/10', border: 'border-dws-green/30' };
    }
  };

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'high': return <ArrowUp className="text-alert-critical" size={14} />;
      case 'medium': return <Minus className="text-alert-warning" size={14} />;
      default: return <ArrowDown className="text-dws-green" size={14} />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-purple-500/20 to-joe-blue/20 border border-purple-500/30">
            <Brain className="text-purple-400" size={28} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-white">
              Self-Learning Analytics
            </h1>
            <p className="text-gray-400 mt-1">AI Intelligence & Behavior Patterns</p>
          </div>
        </div>
        <button
          onClick={handleRefresh}
          disabled={isLoading}
          className="btn-secondary flex items-center gap-2"
        >
          <RefreshCw size={16} className={isLoading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="p-4 bg-alert-critical/10 border border-alert-critical/30 rounded-lg flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <AlertTriangle className="text-alert-critical" size={20} />
            <span className="text-alert-critical">{error}</span>
          </div>
          <button onClick={clearError} className="text-gray-400 hover:text-white">
            <ChevronRight size={16} />
          </button>
        </motion.div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="glass-card p-4"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-joe-blue/10">
              <Activity className="text-joe-blue" size={20} />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Total Interactions</p>
              <p className="text-2xl font-bold text-white">
                {stats?.totalInteractions?.toLocaleString() || '0'}
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.1 }}
          className="glass-card p-4"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/10">
              <Sparkles className="text-purple-400" size={20} />
            </div>
            <div>
              <p className="text-gray-400 text-sm">AI Queries</p>
              <p className="text-2xl font-bold text-white">
                {stats?.totalQueries?.toLocaleString() || '0'}
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
          className="glass-card p-4"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-alert-warning/10">
              <Star className="text-alert-warning" size={20} />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Avg Rating</p>
              <p className="text-2xl font-bold text-white">
                {stats?.avgRating?.toFixed(1) || '0.0'} / 5
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3 }}
          className="glass-card p-4"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-dws-green/10">
              <Database className="text-dws-green" size={20} />
            </div>
            <div>
              <p className="text-gray-400 text-sm">Cache Size</p>
              <p className="text-2xl font-bold text-white">
                {stats?.cacheSize || 0} entries
              </p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* User Profile Card */}
      {profile && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-6"
        >
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Users className="text-joe-blue" size={20} />
            User Behavior Profile
          </h2>
          <div className="grid grid-cols-4 gap-6">
            <div>
              <p className="text-gray-400 text-sm mb-2">Expertise Level</p>
              <span className={`px-3 py-1 rounded-full text-sm font-medium ${getExpertiseBadge(profile.expertiseLevel).color}`}>
                {getExpertiseBadge(profile.expertiseLevel).label}
              </span>
            </div>
            <div>
              <p className="text-gray-400 text-sm mb-2">Preferred Frameworks</p>
              <div className="flex flex-wrap gap-1">
                {profile.preferredFrameworks?.slice(0, 3).map((fw, i) => (
                  <span key={i} className="px-2 py-0.5 bg-joe-blue/10 text-joe-blue text-xs rounded">
                    {fw}
                  </span>
                )) || <span className="text-gray-500 text-sm">None yet</span>}
              </div>
            </div>
            <div>
              <p className="text-gray-400 text-sm mb-2">Engagement Score</p>
              <div className="flex items-center gap-2">
                <div className="flex-1 h-2 bg-dws-dark rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${profile.engagementScore}%` }}
                    className="h-full bg-gradient-to-r from-joe-blue to-dws-green"
                  />
                </div>
                <span className="text-white font-medium">{profile.engagementScore}%</span>
              </div>
            </div>
            <div>
              <p className="text-gray-400 text-sm mb-2">Avg Session</p>
              <p className="text-white font-medium">{profile.avgSessionMinutes || 0} min</p>
            </div>
          </div>
        </motion.div>
      )}

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-dws-border pb-2">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'overview'
              ? 'bg-joe-blue/10 text-joe-blue border-b-2 border-joe-blue'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <BarChart3 size={18} />
          Overview
        </button>
        <button
          onClick={() => setActiveTab('patterns')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'patterns'
              ? 'bg-purple-500/10 text-purple-400 border-b-2 border-purple-400'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Target size={18} />
          Security Patterns
          {patterns.length > 0 && (
            <span className="ml-1 px-1.5 py-0.5 text-xs bg-purple-500/20 text-purple-400 rounded">
              {patterns.length}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab('learning')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'learning'
              ? 'bg-dws-green/10 text-dws-green border-b-2 border-dws-green'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Brain size={18} />
          Learning Insights
          {learningInsights.length > 0 && (
            <span className="ml-1 px-1.5 py-0.5 text-xs bg-dws-green/20 text-dws-green rounded">
              {learningInsights.length}
            </span>
          )}
        </button>
      </div>

      <AnimatePresence mode="wait">
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <motion.div
            key="overview"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Interaction Breakdown */}
            <div className="grid grid-cols-2 gap-4">
              <div className="glass-card p-6">
                <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                  <MousePointer size={18} className="text-joe-blue" />
                  Top Interaction Types
                </h3>
                {insights?.topElementTypes && insights.topElementTypes.length > 0 ? (
                  <div className="space-y-3">
                    {insights.topElementTypes.map((item, i) => (
                      <div key={i} className="flex items-center gap-3">
                        <span className="w-24 text-gray-400 text-sm">{item.type}</span>
                        <div className="flex-1 h-2 bg-dws-dark rounded-full overflow-hidden">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${(item.count / (insights.topElementTypes?.[0]?.count || 1)) * 100}%` }}
                            className="h-full bg-joe-blue"
                          />
                        </div>
                        <span className="text-white font-medium w-12 text-right">{item.count}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Eye className="text-gray-600 mx-auto mb-3" size={32} />
                    <p className="text-gray-500">No interaction data yet</p>
                    <p className="text-gray-600 text-sm">Start using AI touchpoints to see analytics</p>
                  </div>
                )}
              </div>

              <div className="glass-card p-6">
                <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                  <Clock size={18} className="text-purple-400" />
                  Performance Metrics
                </h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-3 bg-dws-dark rounded-lg">
                    <span className="text-gray-400">Avg Response Time</span>
                    <span className="text-white font-medium">
                      {insights?.avgResponseTime?.toFixed(0) || 0}ms
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-dws-dark rounded-lg">
                    <span className="text-gray-400">Cache Hit Rate</span>
                    <span className="text-dws-green font-medium">
                      {((insights?.cacheHitRate || 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-dws-dark rounded-lg">
                    <span className="text-gray-400">Total Sessions</span>
                    <span className="text-white font-medium">
                      {stats?.totalSessions || 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-dws-dark rounded-lg">
                    <span className="text-gray-400">Database Size</span>
                    <span className="text-white font-medium">
                      {stats?.dbSize || '0 KB'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* AI Effectiveness */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                <Zap size={18} className="text-alert-warning" />
                AI Touchpoint Effectiveness
              </h3>
              <div className="grid grid-cols-4 gap-4">
                <div className="p-4 bg-dws-dark rounded-lg text-center">
                  <Sparkles className="text-purple-400 mx-auto mb-2" size={24} />
                  <p className="text-2xl font-bold text-white">{stats?.totalQueries || 0}</p>
                  <p className="text-gray-500 text-sm">AI Queries</p>
                </div>
                <div className="p-4 bg-dws-dark rounded-lg text-center">
                  <Star className="text-alert-warning mx-auto mb-2" size={24} />
                  <p className="text-2xl font-bold text-white">{stats?.avgRating?.toFixed(1) || '0.0'}</p>
                  <p className="text-gray-500 text-sm">Avg Rating</p>
                </div>
                <div className="p-4 bg-dws-dark rounded-lg text-center">
                  <TrendingUp className="text-dws-green mx-auto mb-2" size={24} />
                  <p className="text-2xl font-bold text-white">
                    {((insights?.cacheHitRate || 0) * 100).toFixed(0)}%
                  </p>
                  <p className="text-gray-500 text-sm">Cache Efficiency</p>
                </div>
                <div className="p-4 bg-dws-dark rounded-lg text-center">
                  <Activity className="text-joe-blue mx-auto mb-2" size={24} />
                  <p className="text-2xl font-bold text-white">
                    {insights?.avgResponseTime?.toFixed(0) || 0}ms
                  </p>
                  <p className="text-gray-500 text-sm">Response Time</p>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Patterns Tab */}
        {activeTab === 'patterns' && (
          <motion.div
            key="patterns"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-4"
          >
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                <Target size={18} className="text-purple-400" />
                Detected Security Patterns
              </h3>

              {patterns.length === 0 ? (
                <div className="text-center py-12">
                  <Shield className="text-gray-600 mx-auto mb-3" size={48} />
                  <p className="text-gray-400">No security patterns detected yet</p>
                  <p className="text-gray-500 text-sm mt-1">
                    Patterns will emerge as you interact with security findings
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {patterns.map((pattern) => {
                    const config = getSeverityConfig(pattern.severity);
                    return (
                      <motion.div
                        key={pattern.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className={`p-4 rounded-lg border ${config.bg} ${config.border}`}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              <span className={`px-2 py-0.5 rounded text-xs font-medium ${config.color} ${config.bg}`}>
                                {pattern.severity.toUpperCase()}
                              </span>
                              <span className="text-white font-medium">{pattern.patternType}</span>
                              <span className="text-gray-500 text-sm">
                                ({pattern.frequency}x detected)
                              </span>
                            </div>
                            <p className="text-gray-400 text-sm">{pattern.description}</p>
                          </div>
                          <div className="text-right">
                            <p className="text-gray-500 text-xs">
                              Last seen: {new Date(pattern.lastSeen).toLocaleDateString()}
                            </p>
                          </div>
                        </div>
                        {pattern.recommendedActions && (
                          <div className="mt-3 pt-3 border-t border-white/10">
                            <p className="text-sm text-joe-blue flex items-center gap-1">
                              <ChevronRight size={14} />
                              {pattern.recommendedActions}
                            </p>
                          </div>
                        )}
                      </motion.div>
                    );
                  })}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* Learning Tab */}
        {activeTab === 'learning' && (
          <motion.div
            key="learning"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-4"
          >
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                <Brain size={18} className="text-dws-green" />
                AI Learning Insights
              </h3>

              {learningInsights.length === 0 ? (
                <div className="text-center py-12">
                  <Sparkles className="text-gray-600 mx-auto mb-3" size={48} />
                  <p className="text-gray-400">No learning insights yet</p>
                  <p className="text-gray-500 text-sm mt-1">
                    The AI will learn from your interactions and provide personalized insights
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {learningInsights.map((insight, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.05 }}
                      className="p-4 bg-dws-dark rounded-lg border border-dws-border"
                    >
                      <div className="flex items-start gap-3">
                        <div className="p-2 rounded-lg bg-dws-green/10">
                          {getPriorityIcon(insight.priority)}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-white font-medium">{insight.title}</span>
                            <span className={`px-2 py-0.5 rounded text-xs ${
                              insight.type === 'recommendation' ? 'bg-joe-blue/10 text-joe-blue' :
                              insight.type === 'warning' ? 'bg-alert-warning/10 text-alert-warning' :
                              insight.type === 'pattern' ? 'bg-purple-500/10 text-purple-400' :
                              'bg-dws-green/10 text-dws-green'
                            }`}>
                              {insight.type}
                            </span>
                          </div>
                          <p className="text-gray-400 text-sm">{insight.description}</p>
                        </div>
                        {insight.actionable && (
                          <CheckCircle className="text-dws-green" size={16} />
                        )}
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </div>

            {/* Learning Summary */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                <Layers size={18} className="text-joe-blue" />
                System Learning Summary
              </h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="p-4 bg-dws-dark rounded-lg">
                  <p className="text-gray-400 text-sm mb-2">Queries Analyzed</p>
                  <p className="text-2xl font-bold text-white">{stats?.totalQueries || 0}</p>
                </div>
                <div className="p-4 bg-dws-dark rounded-lg">
                  <p className="text-gray-400 text-sm mb-2">Patterns Detected</p>
                  <p className="text-2xl font-bold text-purple-400">{patterns.length}</p>
                </div>
                <div className="p-4 bg-dws-dark rounded-lg">
                  <p className="text-gray-400 text-sm mb-2">Insights Generated</p>
                  <p className="text-2xl font-bold text-dws-green">{learningInsights.length}</p>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
