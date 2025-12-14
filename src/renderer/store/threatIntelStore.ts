/**
 * J.O.E. Threat Intelligence Store
 * Zustand state management for EPSS + CISA KEV integration
 *
 * Data Sources:
 * - EPSS (Exploit Prediction Scoring System) - FIRST.org
 * - CISA KEV (Known Exploited Vulnerabilities) Catalog
 * - NVD (National Vulnerability Database) enrichment
 *
 * References:
 * - https://www.first.org/epss
 * - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 * - https://nvd.nist.gov/developers/vulnerabilities
 */

import { create } from 'zustand';

// ========================================
// TYPE DEFINITIONS
// ========================================

export interface EPSSScore {
  cve: string;
  epss: number;        // Probability of exploitation (0-1)
  percentile: number;  // Percentile ranking (0-100)
  date: string;
}

export interface KEVEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: 'Known' | 'Unknown';
  notes: string;
}

export interface KEVCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KEVEntry[];
}

export interface NVDData {
  description: string;
  cvssV3Score: number;
  cvssV3Severity: string;
  cvssV2Score?: number;
  publishedDate: string;
  lastModified: string;
  references: string[];
  cwes: string[];
}

export interface ThreatIntelResult {
  cve: string;
  epss?: EPSSScore;
  kev?: KEVEntry;
  nvdData?: NVDData;
  priorityScore: number;  // Combined priority (0-100)
  priorityRating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  recommendation: string;
}

export interface KEVStats {
  totalCount: number;
  lastUpdated: string;
  byVendor: Record<string, number>;
  ransomwareRelated: number;
  recentlyAdded: KEVEntry[];
}

// ========================================
// STORE STATE
// ========================================

interface ThreatIntelState {
  // Data
  kevCatalog: KEVCatalog | null;
  kevStats: KEVStats | null;
  epssCache: Record<string, EPSSScore>;
  analysisResults: ThreatIntelResult[];
  searchResults: KEVEntry[];

  // UI State
  isLoading: boolean;
  isAnalyzing: boolean;
  error: string | null;
  lastRefresh: string | null;

  // Search
  searchQuery: string;
  selectedCVE: ThreatIntelResult | null;

  // Filters
  filterRating: 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  filterKEV: boolean;
  sortBy: 'priority' | 'epss' | 'cvss' | 'date';

  // Actions
  fetchKEVCatalog: (forceRefresh?: boolean) => Promise<void>;
  fetchKEVStats: () => Promise<void>;
  searchKEV: (query: string) => Promise<void>;
  checkCVEInKEV: (cveId: string) => Promise<KEVEntry | null>;
  getEPSSScore: (cveId: string) => Promise<EPSSScore | null>;
  analyzeCVE: (cveId: string) => Promise<ThreatIntelResult | null>;
  analyzeCVEsBatch: (cveIds: string[]) => Promise<ThreatIntelResult[]>;
  clearCache: () => Promise<void>;
  setSearchQuery: (query: string) => void;
  setFilterRating: (rating: 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW') => void;
  setFilterKEV: (enabled: boolean) => void;
  setSortBy: (sort: 'priority' | 'epss' | 'cvss' | 'date') => void;
  setSelectedCVE: (cve: ThreatIntelResult | null) => void;
  clearError: () => void;
}

// ========================================
// STORE IMPLEMENTATION
// ========================================

export const useThreatIntelStore = create<ThreatIntelState>((set, get) => ({
  // Initial state
  kevCatalog: null,
  kevStats: null,
  epssCache: {},
  analysisResults: [],
  searchResults: [],
  isLoading: false,
  isAnalyzing: false,
  error: null,
  lastRefresh: null,
  searchQuery: '',
  selectedCVE: null,
  filterRating: 'ALL',
  filterKEV: false,
  sortBy: 'priority',

  // Fetch CISA KEV catalog
  fetchKEVCatalog: async (forceRefresh = false) => {
    set({ isLoading: true, error: null });
    try {
      const catalog = await window.electronAPI?.threatIntel?.getKEVCatalog(forceRefresh) as KEVCatalog | null;
      set({
        kevCatalog: catalog ?? null,
        isLoading: false,
        lastRefresh: new Date().toISOString()
      });
    } catch (error) {
      set({
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to fetch KEV catalog'
      });
    }
  },

  // Fetch KEV statistics
  fetchKEVStats: async () => {
    set({ isLoading: true, error: null });
    try {
      const stats = await window.electronAPI?.threatIntel?.getKEVStats() as KEVStats | null;
      set({
        kevStats: stats ?? null,
        isLoading: false
      });
    } catch (error) {
      set({
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to fetch KEV stats'
      });
    }
  },

  // Search KEV catalog
  searchKEV: async (query: string) => {
    set({ isLoading: true, error: null, searchQuery: query });
    try {
      const results = await window.electronAPI?.threatIntel?.searchKEV(query) as KEVEntry[] | null;
      set({
        searchResults: results ?? [],
        isLoading: false
      });
    } catch (error) {
      set({
        isLoading: false,
        error: error instanceof Error ? error.message : 'KEV search failed'
      });
    }
  },

  // Check if CVE is in KEV
  checkCVEInKEV: async (cveId: string) => {
    try {
      const kevEntry = await window.electronAPI?.threatIntel?.checkKEV(cveId) as KEVEntry | null;
      return kevEntry ?? null;
    } catch (error) {
      console.error('KEV check failed:', error);
      return null;
    }
  },

  // Get EPSS score for CVE
  getEPSSScore: async (cveId: string) => {
    const { epssCache } = get();

    // Check cache first
    if (epssCache[cveId]) {
      return epssCache[cveId];
    }

    try {
      const epss = await window.electronAPI?.threatIntel?.getEPSS(cveId);
      if (epss) {
        set({
          epssCache: { ...get().epssCache, [cveId]: epss }
        });
      }
      return epss ?? null;
    } catch (error) {
      console.error('EPSS lookup failed:', error);
      return null;
    }
  },

  // Analyze single CVE (comprehensive)
  analyzeCVE: async (cveId: string) => {
    set({ isAnalyzing: true, error: null });
    try {
      const result = await window.electronAPI?.threatIntel?.analyzeCVE(cveId) as ThreatIntelResult | null;
      set({
        selectedCVE: result ?? null,
        isAnalyzing: false
      });
      return result ?? null;
    } catch (error) {
      set({
        isAnalyzing: false,
        error: error instanceof Error ? error.message : 'CVE analysis failed'
      });
      return null;
    }
  },

  // Analyze multiple CVEs (batch)
  analyzeCVEsBatch: async (cveIds: string[]) => {
    set({ isAnalyzing: true, error: null });
    try {
      const results = await window.electronAPI?.threatIntel?.analyzeCVEsBatch(cveIds) as ThreatIntelResult[] | null;
      set({
        analysisResults: results ?? [],
        isAnalyzing: false
      });
      return results ?? [];
    } catch (error) {
      set({
        isAnalyzing: false,
        error: error instanceof Error ? error.message : 'Batch analysis failed'
      });
      return [];
    }
  },

  // Clear caches
  clearCache: async () => {
    try {
      await window.electronAPI?.threatIntel?.clearCache();
      set({
        epssCache: {},
        kevCatalog: null,
        kevStats: null,
        analysisResults: [],
        searchResults: [],
        lastRefresh: null
      });
    } catch (error) {
      console.error('Failed to clear cache:', error);
    }
  },

  // UI actions
  setSearchQuery: (query: string) => set({ searchQuery: query }),
  setFilterRating: (rating) => set({ filterRating: rating }),
  setFilterKEV: (enabled) => set({ filterKEV: enabled }),
  setSortBy: (sort) => set({ sortBy: sort }),
  setSelectedCVE: (cve) => set({ selectedCVE: cve }),
  clearError: () => set({ error: null })
}));

// ========================================
// SELECTOR HELPERS
// ========================================

export const getFilteredResults = (state: ThreatIntelState): ThreatIntelResult[] => {
  let results = [...state.analysisResults];

  // Apply rating filter
  if (state.filterRating !== 'ALL') {
    results = results.filter(r => r.priorityRating === state.filterRating);
  }

  // Apply KEV filter
  if (state.filterKEV) {
    results = results.filter(r => r.kev !== undefined);
  }

  // Apply sorting
  switch (state.sortBy) {
    case 'priority':
      results.sort((a, b) => b.priorityScore - a.priorityScore);
      break;
    case 'epss':
      results.sort((a, b) => (b.epss?.epss || 0) - (a.epss?.epss || 0));
      break;
    case 'cvss':
      results.sort((a, b) => (b.nvdData?.cvssV3Score || 0) - (a.nvdData?.cvssV3Score || 0));
      break;
    case 'date':
      results.sort((a, b) => {
        const dateA = a.kev?.dateAdded || a.nvdData?.publishedDate || '';
        const dateB = b.kev?.dateAdded || b.nvdData?.publishedDate || '';
        return dateB.localeCompare(dateA);
      });
      break;
  }

  return results;
};

export const getTopVendors = (state: ThreatIntelState, limit = 10): { vendor: string; count: number }[] => {
  if (!state.kevStats?.byVendor) return [];

  return Object.entries(state.kevStats.byVendor)
    .map(([vendor, count]) => ({ vendor, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
};

export const getCriticalCount = (state: ThreatIntelState): number => {
  return state.analysisResults.filter(r => r.priorityRating === 'CRITICAL').length;
};

export const getKEVCount = (state: ThreatIntelState): number => {
  return state.analysisResults.filter(r => r.kev !== undefined).length;
};

// Types are declared globally in src/types/electron.d.ts

export default useThreatIntelStore;
