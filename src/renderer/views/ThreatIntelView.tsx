/**
 * J.O.E. Threat Intelligence View
 * EPSS + CISA KEV Integration Dashboard
 *
 * Data Sources:
 * - EPSS (Exploit Prediction Scoring System) - FIRST.org
 * - CISA KEV (Known Exploited Vulnerabilities) Catalog
 * - NVD (National Vulnerability Database) enrichment
 *
 * References:
 * - https://www.first.org/epss
 * - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 */

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert,
  Shield,
  AlertTriangle,
  AlertOctagon,
  Search,
  RefreshCw,
  Loader2,
  TrendingUp,
  Target,
  Skull,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Filter,
  Info,
  X,
  BarChart3,
  Clock,
  Building2,
  Bug,
  Zap
} from 'lucide-react';
import { useThreatIntelStore, getFilteredResults, getTopVendors, KEVEntry, ThreatIntelResult } from '../store/threatIntelStore';

export default function ThreatIntelView() {
  const {
    kevCatalog: _kevCatalog,
    kevStats,
    analysisResults,
    searchResults,
    isLoading,
    isAnalyzing,
    error,
    lastRefresh,
    searchQuery,
    selectedCVE,
    filterRating,
    filterKEV,
    sortBy,
    fetchKEVCatalog,
    fetchKEVStats,
    searchKEV,
    analyzeCVE,
    analyzeCVEsBatch,
    clearCache: _clearCache,
    setSearchQuery,
    setFilterRating,
    setFilterKEV,
    setSortBy,
    setSelectedCVE,
    clearError
  } = useThreatIntelStore();

  const [cveInput, setCveInput] = useState('');
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['stats', 'search']));
  const [showFilters, setShowFilters] = useState(false);

  // Load KEV data on mount
  useEffect(() => {
    fetchKEVCatalog();
    fetchKEVStats();
  }, [fetchKEVCatalog, fetchKEVStats]);

  // Get filtered results
  const filteredResults = getFilteredResults(useThreatIntelStore.getState());
  const topVendors = getTopVendors(useThreatIntelStore.getState(), 5);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      await searchKEV(searchQuery.trim());
    }
  };

  const handleAnalyzeCVE = async (e: React.FormEvent) => {
    e.preventDefault();
    if (cveInput.trim()) {
      // Support multiple CVEs separated by comma or newline
      const cves = cveInput.split(/[,\n]/).map(c => c.trim().toUpperCase()).filter(c => c.startsWith('CVE-'));
      if (cves.length === 1) {
        await analyzeCVE(cves[0]);
      } else if (cves.length > 1) {
        await analyzeCVEsBatch(cves);
      }
    }
  };

  const handleRefresh = async () => {
    await fetchKEVCatalog(true);
    await fetchKEVStats();
  };

  const toggleSection = (section: string) => {
    const newSections = new Set(expandedSections);
    if (newSections.has(section)) {
      newSections.delete(section);
    } else {
      newSections.add(section);
    }
    setExpandedSections(newSections);
  };

  // Priority badge colors
  const _getPriorityColor = (rating: string) => {
    switch (rating) {
      case 'CRITICAL': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'HIGH': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'MEDIUM': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'LOW': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const _getPriorityIcon = (rating: string) => {
    switch (rating) {
      case 'CRITICAL': return <AlertOctagon className="w-4 h-4" />;
      case 'HIGH': return <AlertTriangle className="w-4 h-4" />;
      case 'MEDIUM': return <ShieldAlert className="w-4 h-4" />;
      case 'LOW': return <Shield className="w-4 h-4" />;
      default: return <Info className="w-4 h-4" />;
    }
  };

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <ShieldAlert className="w-8 h-8 text-joe-blue" />
            Threat Intelligence
          </h1>
          <p className="text-gray-400 mt-1">
            EPSS + CISA KEV vulnerability prioritization
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-xs text-gray-500">
              Last updated: {new Date(lastRefresh).toLocaleString()}
            </span>
          )}
          <button
            onClick={handleRefresh}
            disabled={isLoading}
            className="flex items-center gap-2 px-4 py-2 bg-joe-blue hover:bg-joe-blue-dark text-white rounded-lg transition-colors disabled:opacity-50"
          >
            {isLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4" />
            )}
            Refresh
          </button>
        </div>
      </div>

      {/* Error Banner */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-center justify-between"
          >
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <span className="text-red-400">{error}</span>
            </div>
            <button onClick={clearError} className="text-red-400 hover:text-red-300">
              <X className="w-5 h-5" />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Stats Overview */}
      <section className="glass-card p-6">
        <button
          onClick={() => toggleSection('stats')}
          className="w-full flex items-center justify-between mb-4"
        >
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-joe-blue" />
            CISA KEV Overview
          </h2>
          {expandedSections.has('stats') ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </button>

        <AnimatePresence>
          {expandedSections.has('stats') && kevStats && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="grid grid-cols-2 md:grid-cols-4 gap-4"
            >
              {/* Total KEV */}
              <div className="bg-dws-dark rounded-lg p-4 border border-dws-border">
                <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                  <Bug className="w-4 h-4" />
                  Total KEV
                </div>
                <div className="text-3xl font-bold text-white">{kevStats.totalCount}</div>
                <div className="text-xs text-gray-500 mt-1">Active exploits</div>
              </div>

              {/* Ransomware Related */}
              <div className="bg-dws-dark rounded-lg p-4 border border-red-500/30">
                <div className="flex items-center gap-2 text-red-400 text-sm mb-2">
                  <Skull className="w-4 h-4" />
                  Ransomware
                </div>
                <div className="text-3xl font-bold text-red-400">{kevStats.ransomwareRelated}</div>
                <div className="text-xs text-gray-500 mt-1">Known campaigns</div>
              </div>

              {/* Recently Added */}
              <div className="bg-dws-dark rounded-lg p-4 border border-yellow-500/30">
                <div className="flex items-center gap-2 text-yellow-400 text-sm mb-2">
                  <Clock className="w-4 h-4" />
                  Recent (30d)
                </div>
                <div className="text-3xl font-bold text-yellow-400">{kevStats.recentlyAdded.length}</div>
                <div className="text-xs text-gray-500 mt-1">New additions</div>
              </div>

              {/* Top Vendor */}
              <div className="bg-dws-dark rounded-lg p-4 border border-dws-border">
                <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                  <Building2 className="w-4 h-4" />
                  Top Vendor
                </div>
                <div className="text-xl font-bold text-white truncate">
                  {topVendors[0]?.vendor || 'N/A'}
                </div>
                <div className="text-xs text-gray-500 mt-1">{topVendors[0]?.count || 0} CVEs</div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* CVE Analysis */}
      <section className="glass-card p-6">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
          <Target className="w-5 h-5 text-joe-blue" />
          CVE Analysis
        </h2>

        <form onSubmit={handleAnalyzeCVE} className="flex gap-3 mb-4">
          <div className="flex-1 relative">
            <input
              type="text"
              value={cveInput}
              onChange={(e) => setCveInput(e.target.value)}
              placeholder="Enter CVE ID(s) - e.g., CVE-2024-1234, CVE-2024-5678"
              className="w-full px-4 py-3 bg-dws-dark border border-dws-border rounded-lg text-white placeholder:text-gray-500 focus:outline-none focus:border-joe-blue"
            />
          </div>
          <button
            type="submit"
            disabled={isAnalyzing || !cveInput.trim()}
            className="px-6 py-3 bg-joe-blue hover:bg-joe-blue-dark text-white rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            {isAnalyzing ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Zap className="w-4 h-4" />
            )}
            Analyze
          </button>
        </form>

        {/* Analysis Results */}
        {analysisResults.length > 0 && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">{analysisResults.length} CVEs analyzed</span>
              <button
                onClick={() => setShowFilters(!showFilters)}
                className="flex items-center gap-2 text-sm text-gray-400 hover:text-white"
              >
                <Filter className="w-4 h-4" />
                Filters
              </button>
            </div>

            {/* Filters */}
            <AnimatePresence>
              {showFilters && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="flex flex-wrap gap-3 p-3 bg-dws-dark rounded-lg"
                >
                  <select
                    value={filterRating}
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                    onChange={(e) => setFilterRating(e.target.value as any)}
                    className="px-3 py-2 bg-dws-darker border border-dws-border rounded text-sm text-white"
                  >
                    <option value="ALL">All Priorities</option>
                    <option value="CRITICAL">Critical Only</option>
                    <option value="HIGH">High Only</option>
                    <option value="MEDIUM">Medium Only</option>
                    <option value="LOW">Low Only</option>
                  </select>
                  <label className="flex items-center gap-2 text-sm text-gray-400">
                    <input
                      type="checkbox"
                      checked={filterKEV}
                      onChange={(e) => setFilterKEV(e.target.checked)}
                      className="rounded"
                    />
                    In KEV only
                  </label>
                  <select
                    value={sortBy}
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                    onChange={(e) => setSortBy(e.target.value as any)}
                    className="px-3 py-2 bg-dws-darker border border-dws-border rounded text-sm text-white"
                  >
                    <option value="priority">Sort by Priority</option>
                    <option value="epss">Sort by EPSS</option>
                    <option value="cvss">Sort by CVSS</option>
                    <option value="date">Sort by Date</option>
                  </select>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Results List */}
            <div className="space-y-3">
              {filteredResults.map((result) => (
                <CVEResultCard
                  key={result.cve}
                  result={result}
                  onSelect={() => setSelectedCVE(result)}
                  isSelected={selectedCVE?.cve === result.cve}
                />
              ))}
            </div>
          </div>
        )}
      </section>

      {/* KEV Search */}
      <section className="glass-card p-6">
        <button
          onClick={() => toggleSection('search')}
          className="w-full flex items-center justify-between mb-4"
        >
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Search className="w-5 h-5 text-joe-blue" />
            Search CISA KEV Catalog
          </h2>
          {expandedSections.has('search') ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </button>

        <AnimatePresence>
          {expandedSections.has('search') && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <form onSubmit={handleSearch} className="flex gap-3 mb-4">
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search by CVE, vendor, product..."
                    className="w-full pl-10 pr-4 py-3 bg-dws-dark border border-dws-border rounded-lg text-white placeholder:text-gray-500 focus:outline-none focus:border-joe-blue"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="px-6 py-3 bg-dws-card hover:bg-dws-elevated text-white rounded-lg flex items-center gap-2 transition-colors border border-dws-border"
                >
                  Search
                </button>
              </form>

              {/* Search Results */}
              {searchResults.length > 0 && (
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {searchResults.map((kev) => (
                    <KEVCard key={kev.cveID} kev={kev} onAnalyze={(cve) => {
                      setCveInput(cve);
                      analyzeCVE(cve);
                    }} />
                  ))}
                </div>
              )}

              {searchQuery && searchResults.length === 0 && !isLoading && (
                <div className="text-center text-gray-500 py-8">
                  No results found for "{searchQuery}"
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* Recently Added to KEV */}
      {kevStats?.recentlyAdded && kevStats.recentlyAdded.length > 0 && (
        <section className="glass-card p-6">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
            Recently Added to KEV (Last 30 Days)
          </h2>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {kevStats.recentlyAdded.slice(0, 10).map((kev) => (
              <KEVCard key={kev.cveID} kev={kev} onAnalyze={(cve) => {
                setCveInput(cve);
                analyzeCVE(cve);
              }} />
            ))}
          </div>
        </section>
      )}

      {/* CVE Detail Modal */}
      <AnimatePresence>
        {selectedCVE && (
          <CVEDetailModal
            result={selectedCVE}
            onClose={() => setSelectedCVE(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

// ========================================
// SUB-COMPONENTS
// ========================================

function CVEResultCard({
  result,
  onSelect,
  isSelected
}: {
  result: ThreatIntelResult;
  onSelect: () => void;
  isSelected: boolean;
}) {
  const getPriorityColor = (rating: string) => {
    switch (rating) {
      case 'CRITICAL': return 'border-red-500/50 bg-red-500/5';
      case 'HIGH': return 'border-orange-500/50 bg-orange-500/5';
      case 'MEDIUM': return 'border-yellow-500/50 bg-yellow-500/5';
      case 'LOW': return 'border-green-500/50 bg-green-500/5';
      default: return 'border-dws-border bg-dws-dark';
    }
  };

  const getBadgeColor = (rating: string) => {
    switch (rating) {
      case 'CRITICAL': return 'bg-red-500/20 text-red-400';
      case 'HIGH': return 'bg-orange-500/20 text-orange-400';
      case 'MEDIUM': return 'bg-yellow-500/20 text-yellow-400';
      case 'LOW': return 'bg-green-500/20 text-green-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  return (
    <motion.div
      onClick={onSelect}
      className={`p-4 rounded-lg border cursor-pointer transition-all ${getPriorityColor(result.priorityRating)} ${isSelected ? 'ring-2 ring-joe-blue' : 'hover:border-joe-blue/30'}`}
      whileHover={{ scale: 1.01 }}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <span className="font-mono font-bold text-white">{result.cve}</span>
            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getBadgeColor(result.priorityRating)}`}>
              {result.priorityRating}
            </span>
            {result.kev && (
              <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/20 text-red-400 flex items-center gap-1">
                <AlertOctagon className="w-3 h-3" />
                KEV
              </span>
            )}
          </div>

          {result.nvdData && (
            <p className="text-sm text-gray-400 line-clamp-2 mb-2">
              {result.nvdData.description}
            </p>
          )}

          <div className="flex items-center gap-4 text-xs text-gray-500">
            <span className="flex items-center gap-1">
              <Target className="w-3 h-3" />
              Priority: {result.priorityScore}
            </span>
            {result.epss && (
              <span className="flex items-center gap-1">
                <TrendingUp className="w-3 h-3" />
                EPSS: {(result.epss.epss * 100).toFixed(2)}%
              </span>
            )}
            {result.nvdData && (
              <span className="flex items-center gap-1">
                <ShieldAlert className="w-3 h-3" />
                CVSS: {result.nvdData.cvssV3Score}
              </span>
            )}
          </div>
        </div>

        <ChevronRight className="w-5 h-5 text-gray-500 flex-shrink-0" />
      </div>
    </motion.div>
  );
}

function KEVCard({ kev, onAnalyze }: { kev: KEVEntry; onAnalyze: (cve: string) => void }) {
  return (
    <div className="p-3 bg-dws-dark rounded-lg border border-dws-border hover:border-joe-blue/30 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-sm font-bold text-joe-blue">{kev.cveID}</span>
            {kev.knownRansomwareCampaignUse === 'Known' && (
              <span className="px-1.5 py-0.5 rounded text-xs bg-red-500/20 text-red-400 flex items-center gap-1">
                <Skull className="w-3 h-3" />
                Ransomware
              </span>
            )}
          </div>
          <p className="text-sm text-white mb-1">{kev.vulnerabilityName}</p>
          <p className="text-xs text-gray-500">
            {kev.vendorProject} - {kev.product}
          </p>
          <p className="text-xs text-gray-600 mt-1">
            Added: {new Date(kev.dateAdded).toLocaleDateString()} | Due: {new Date(kev.dueDate).toLocaleDateString()}
          </p>
        </div>
        <button
          onClick={() => onAnalyze(kev.cveID)}
          className="px-3 py-1.5 text-xs bg-joe-blue/10 hover:bg-joe-blue/20 text-joe-blue rounded transition-colors"
        >
          Analyze
        </button>
      </div>
    </div>
  );
}

function CVEDetailModal({ result, onClose }: { result: ThreatIntelResult; onClose: () => void }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        className="bg-dws-card rounded-xl border border-dws-border max-w-2xl w-full max-h-[80vh] overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-4 border-b border-dws-border flex items-center justify-between">
          <div>
            <h3 className="text-xl font-bold text-white font-mono">{result.cve}</h3>
            <p className="text-sm text-gray-400">Threat Intelligence Analysis</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-dws-elevated rounded-lg transition-colors">
            <X className="w-5 h-5 text-gray-400" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 overflow-y-auto max-h-[60vh] space-y-4">
          {/* Priority Score */}
          <div className="flex items-center gap-4 p-4 bg-dws-dark rounded-lg">
            <div className="text-center">
              <div className="text-4xl font-bold text-joe-blue">{result.priorityScore}</div>
              <div className="text-xs text-gray-500">Priority Score</div>
            </div>
            <div className="flex-1">
              <div className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${
                result.priorityRating === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                result.priorityRating === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                result.priorityRating === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                'bg-green-500/20 text-green-400'
              }`}>
                {result.priorityRating}
              </div>
              <p className="text-sm text-gray-400 mt-2">{result.recommendation}</p>
            </div>
          </div>

          {/* KEV Status */}
          {result.kev && (
            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
              <div className="flex items-center gap-2 text-red-400 font-medium mb-2">
                <AlertOctagon className="w-5 h-5" />
                In CISA KEV Catalog
              </div>
              <p className="text-sm text-gray-300 mb-2">{result.kev.shortDescription}</p>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-gray-500">Vendor:</span>{' '}
                  <span className="text-white">{result.kev.vendorProject}</span>
                </div>
                <div>
                  <span className="text-gray-500">Product:</span>{' '}
                  <span className="text-white">{result.kev.product}</span>
                </div>
                <div>
                  <span className="text-gray-500">Due Date:</span>{' '}
                  <span className="text-yellow-400">{result.kev.dueDate}</span>
                </div>
                <div>
                  <span className="text-gray-500">Ransomware:</span>{' '}
                  <span className={result.kev.knownRansomwareCampaignUse === 'Known' ? 'text-red-400' : 'text-gray-400'}>
                    {result.kev.knownRansomwareCampaignUse}
                  </span>
                </div>
              </div>
              <p className="text-sm text-yellow-400 mt-2">
                <strong>Required Action:</strong> {result.kev.requiredAction}
              </p>
            </div>
          )}

          {/* EPSS Score */}
          {result.epss && (
            <div className="p-4 bg-dws-dark rounded-lg">
              <div className="flex items-center gap-2 text-joe-blue font-medium mb-2">
                <TrendingUp className="w-5 h-5" />
                EPSS Score
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-2xl font-bold text-white">{(result.epss.epss * 100).toFixed(2)}%</div>
                  <div className="text-xs text-gray-500">Exploitation Probability (30 days)</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-white">{result.epss.percentile.toFixed(1)}%</div>
                  <div className="text-xs text-gray-500">Percentile Ranking</div>
                </div>
              </div>
            </div>
          )}

          {/* NVD Data */}
          {result.nvdData && (
            <div className="p-4 bg-dws-dark rounded-lg">
              <div className="flex items-center gap-2 text-joe-blue font-medium mb-2">
                <Shield className="w-5 h-5" />
                NVD Details
              </div>
              <p className="text-sm text-gray-300 mb-3">{result.nvdData.description}</p>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>
                  <span className="text-gray-500">CVSS v3:</span>{' '}
                  <span className="text-white font-bold">{result.nvdData.cvssV3Score}</span>{' '}
                  <span className={`text-xs ${
                    result.nvdData.cvssV3Severity === 'CRITICAL' ? 'text-red-400' :
                    result.nvdData.cvssV3Severity === 'HIGH' ? 'text-orange-400' :
                    result.nvdData.cvssV3Severity === 'MEDIUM' ? 'text-yellow-400' :
                    'text-green-400'
                  }`}>({result.nvdData.cvssV3Severity})</span>
                </div>
                <div>
                  <span className="text-gray-500">Published:</span>{' '}
                  <span className="text-white">{new Date(result.nvdData.publishedDate).toLocaleDateString()}</span>
                </div>
              </div>
              {result.nvdData.cwes.length > 0 && (
                <div className="mt-2">
                  <span className="text-xs text-gray-500">CWEs:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {result.nvdData.cwes.map((cwe) => (
                      <span key={cwe} className="px-2 py-0.5 bg-dws-elevated rounded text-xs text-gray-400">
                        {cwe}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {result.nvdData.references.length > 0 && (
                <div className="mt-3">
                  <span className="text-xs text-gray-500">References:</span>
                  <div className="mt-1 space-y-1 max-h-24 overflow-y-auto">
                    {result.nvdData.references.slice(0, 5).map((ref, i) => (
                      <a
                        key={i}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block text-xs text-joe-blue hover:underline truncate flex items-center gap-1"
                      >
                        <ExternalLink className="w-3 h-3 flex-shrink-0" />
                        {ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}
