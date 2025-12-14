/**
 * J.O.E. DevSecOps Arsenal - API Security Store
 * Zustand store for managing API security scanning
 */

import { create } from 'zustand';

// Types
export type OWASPAPICategory =
  | 'API1:2023'
  | 'API2:2023'
  | 'API3:2023'
  | 'API4:2023'
  | 'API5:2023'
  | 'API6:2023'
  | 'API7:2023'
  | 'API8:2023'
  | 'API9:2023'
  | 'API10:2023';

export interface APISecurityFinding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: OWASPAPICategory;
  endpoint?: string;
  method?: string;
  parameter?: string;
  location: string;
  remediation: string;
  owaspApiReference: string;
}

export interface APIScanResult {
  specFile: string;
  apiName: string;
  apiVersion: string;
  openApiVersion: string;
  scanTime: string;
  endpointsAnalyzed: number;
  findings: APISecurityFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  securitySchemes: string[];
  coverage: {
    authenticated: number;
    unauthenticated: number;
    total: number;
  };
}

export interface OWASPAPITop10 {
  id: OWASPAPICategory;
  name: string;
  description: string;
}

interface APISecurityState {
  // State
  scanResults: APIScanResult[];
  currentResult: APIScanResult | null;
  owaspTop10: OWASPAPITop10[];
  selectedSpecFile: string | null;
  isScanning: boolean;
  error: string | null;

  // Filters
  severityFilter: APISecurityFinding['severity'][];
  categoryFilter: OWASPAPICategory[];
  searchQuery: string;

  // Actions
  scanSpec: (filePath: string) => Promise<void>;
  scanDirectory: (dirPath: string) => Promise<void>;
  selectSpecFile: () => Promise<void>;
  clearResults: () => void;
  setCurrentResult: (result: APIScanResult | null) => void;

  // Filter actions
  setSeverityFilter: (severities: APISecurityFinding['severity'][]) => void;
  setCategoryFilter: (categories: OWASPAPICategory[]) => void;
  setSearchQuery: (query: string) => void;
  clearFilters: () => void;

  // Computed
  getFilteredFindings: () => APISecurityFinding[];
  getCategoryCounts: () => Record<OWASPAPICategory, number>;
  getSecurityScore: () => number;
}

// OWASP API Top 10 2023 definitions
const OWASP_API_TOP_10: OWASPAPITop10[] = [
  { id: 'API1:2023', name: 'Broken Object Level Authorization', description: 'APIs exposing object IDs without proper authorization checks' },
  { id: 'API2:2023', name: 'Broken Authentication', description: 'Weak or missing authentication mechanisms' },
  { id: 'API3:2023', name: 'Broken Object Property Level Authorization', description: 'Excessive data exposure through API responses' },
  { id: 'API4:2023', name: 'Unrestricted Resource Consumption', description: 'Missing or improper rate limiting and resource controls' },
  { id: 'API5:2023', name: 'Broken Function Level Authorization', description: 'Missing authorization for administrative functions' },
  { id: 'API6:2023', name: 'Unrestricted Access to Sensitive Business Flows', description: 'Business logic abuse through automated attacks' },
  { id: 'API7:2023', name: 'Server Side Request Forgery', description: 'URL parameters that could enable SSRF attacks' },
  { id: 'API8:2023', name: 'Security Misconfiguration', description: 'Insecure default configurations and missing security headers' },
  { id: 'API9:2023', name: 'Improper Inventory Management', description: 'Outdated or shadow APIs that are not properly managed' },
  { id: 'API10:2023', name: 'Unsafe Consumption of APIs', description: 'Insufficient validation when consuming third-party APIs' }
];

export const useAPISecurityStore = create<APISecurityState>((set, get) => ({
  // Initial state
  scanResults: [],
  currentResult: null,
  owaspTop10: OWASP_API_TOP_10,
  selectedSpecFile: null,
  isScanning: false,
  error: null,

  // Filters
  severityFilter: [],
  categoryFilter: [],
  searchQuery: '',

  // Scan a single OpenAPI spec file
  scanSpec: async (filePath) => {
    set({ isScanning: true, error: null, selectedSpecFile: filePath });
    try {
      const result = await window.electronAPI?.apiSecurity?.scanSpec?.(filePath);

      if (result) {
        set((state) => ({
          scanResults: [result, ...state.scanResults.filter(r => r.specFile !== filePath)],
          currentResult: result,
          isScanning: false
        }));
      } else {
        set({ isScanning: false, error: 'No scan results returned' });
      }
    } catch (error) {
      set({ error: String(error), isScanning: false });
    }
  },

  // Scan a directory for OpenAPI specs
  scanDirectory: async (dirPath) => {
    set({ isScanning: true, error: null });
    try {
      const results = await window.electronAPI?.apiSecurity?.scanDirectory?.(dirPath) || [];

      set({
        scanResults: results,
        currentResult: results[0] || null,
        isScanning: false
      });
    } catch (error) {
      set({ error: String(error), isScanning: false });
    }
  },

  // Select a spec file using file dialog
  selectSpecFile: async () => {
    try {
      const filePath = await window.electronAPI?.fs?.selectFile?.([
        { name: 'OpenAPI Specs', extensions: ['yaml', 'yml', 'json'] }
      ]);

      if (filePath) {
        await get().scanSpec(filePath);
      }
    } catch (error) {
      set({ error: String(error) });
    }
  },

  // Clear all results
  clearResults: () => {
    set({
      scanResults: [],
      currentResult: null,
      selectedSpecFile: null,
      error: null
    });
  },

  // Set current result for viewing
  setCurrentResult: (result) => {
    set({ currentResult: result });
  },

  // Filter actions
  setSeverityFilter: (severities) => set({ severityFilter: severities }),
  setCategoryFilter: (categories) => set({ categoryFilter: categories }),
  setSearchQuery: (query) => set({ searchQuery: query }),
  clearFilters: () => set({ severityFilter: [], categoryFilter: [], searchQuery: '' }),

  // Get filtered findings for current result
  getFilteredFindings: () => {
    const { currentResult, severityFilter, categoryFilter, searchQuery } = get();

    if (!currentResult) {return [];}

    return currentResult.findings.filter((finding) => {
      // Severity filter
      if (severityFilter.length > 0 && !severityFilter.includes(finding.severity)) {
        return false;
      }

      // Category filter
      if (categoryFilter.length > 0 && !categoryFilter.includes(finding.category)) {
        return false;
      }

      // Search query
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          finding.title.toLowerCase().includes(query) ||
          finding.description.toLowerCase().includes(query) ||
          (finding.endpoint?.toLowerCase().includes(query) || false) ||
          finding.location.toLowerCase().includes(query)
        );
      }

      return true;
    });
  },

  // Get category counts for current result
  getCategoryCounts: () => {
    const { currentResult } = get();
    const counts: Record<OWASPAPICategory, number> = {
      'API1:2023': 0,
      'API2:2023': 0,
      'API3:2023': 0,
      'API4:2023': 0,
      'API5:2023': 0,
      'API6:2023': 0,
      'API7:2023': 0,
      'API8:2023': 0,
      'API9:2023': 0,
      'API10:2023': 0
    };

    if (!currentResult) {return counts;}

    for (const finding of currentResult.findings) {
      if (counts[finding.category] !== undefined) {
        counts[finding.category]++;
      }
    }

    return counts;
  },

  // Calculate security score (0-100)
  getSecurityScore: () => {
    const { currentResult } = get();
    if (!currentResult || currentResult.endpointsAnalyzed === 0) {return 100;}

    const { summary, coverage } = currentResult;

    // Base score starts at 100
    let score = 100;

    // Deduct points for findings
    score -= summary.critical * 15;
    score -= summary.high * 10;
    score -= summary.medium * 5;
    score -= summary.low * 2;
    score -= summary.info * 0.5;

    // Bonus for authenticated coverage
    const authCoverage = coverage.total > 0 ? (coverage.authenticated / coverage.total) * 100 : 0;
    if (authCoverage >= 80) {score += 5;}
    else if (authCoverage < 50) {score -= 10;}

    // Clamp to 0-100
    return Math.max(0, Math.min(100, Math.round(score)));
  }
}));

// Type declarations consolidated in src/types/electron.d.ts
