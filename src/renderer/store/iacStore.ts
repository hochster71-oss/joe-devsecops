/**
 * J.O.E. DevSecOps Arsenal - Infrastructure as Code Store
 * Zustand store for managing IaC security scanning
 */

import { create } from 'zustand';

// Types
export type IaCType = 'terraform' | 'cloudformation' | 'kubernetes' | 'dockerfile' | 'ansible' | 'helm';

export interface IaCFinding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  iacType: IaCType;
  file: string;
  line?: number;
  endLine?: number;
  resource?: string;
  resourceType?: string;
  checkId: string;
  remediation: string;
  documentation?: string;
  framework?: string;
  controlId?: string;
}

export interface IaCScanResult {
  iacType: IaCType;
  scanTime: string;
  filesScanned: number;
  findings: IaCFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  passed: number;
  failed: number;
  skipped: number;
}

export interface IaCRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: IaCFinding['severity'];
  iacTypes: IaCType[];
}

interface IaCState {
  // State
  scanResults: IaCScanResult | null;
  findings: IaCFinding[];
  rules: IaCRule[];
  selectedPath: string | null;
  isScanning: boolean;
  error: string | null;
  scanHistory: Array<{
    id: string;
    path: string;
    timestamp: string;
    summary: IaCScanResult['summary'];
  }>;

  // Filters
  severityFilter: IaCFinding['severity'][];
  iacTypeFilter: IaCType[];
  searchQuery: string;

  // Actions
  scanDirectory: (path: string) => Promise<void>;
  scanFile: (path: string) => Promise<void>;
  selectPath: () => Promise<void>;
  clearResults: () => void;

  // Rule management
  fetchRules: () => Promise<void>;
  enableRule: (ruleId: string) => Promise<void>;
  disableRule: (ruleId: string) => Promise<void>;

  // Filter actions
  setSeverityFilter: (severities: IaCFinding['severity'][]) => void;
  setIaCTypeFilter: (types: IaCType[]) => void;
  setSearchQuery: (query: string) => void;
  clearFilters: () => void;

  // Computed
  getFilteredFindings: () => IaCFinding[];
  getSeverityCounts: () => Record<IaCFinding['severity'], number>;
  getIaCTypeCounts: () => Record<IaCType, number>;
}

export const useIaCStore = create<IaCState>((set, get) => ({
  // Initial state
  scanResults: null,
  findings: [],
  rules: [],
  selectedPath: null,
  isScanning: false,
  error: null,
  scanHistory: [],

  // Filters
  severityFilter: [],
  iacTypeFilter: [],
  searchQuery: '',

  // Scan a directory for IaC files
  scanDirectory: async (path) => {
    set({ isScanning: true, error: null, selectedPath: path });
    try {
      const result = await window.electronAPI?.iac?.scanDirectory?.(path);

      if (result) {
        set({
          scanResults: result,
          findings: result.findings,
          isScanning: false,
          scanHistory: [
            {
              id: `scan-${Date.now()}`,
              path,
              timestamp: result.scanTime,
              summary: result.summary
            },
            ...get().scanHistory.slice(0, 9)
          ]
        });
      } else {
        set({ isScanning: false, error: 'No scan results returned' });
      }
    } catch (error) {
      set({ error: String(error), isScanning: false });
    }
  },

  // Scan a single file
  scanFile: async (path) => {
    set({ isScanning: true, error: null, selectedPath: path });
    try {
      const findings = await window.electronAPI?.iac?.scanFile?.(path) || [];

      const summary = {
        critical: findings.filter((f: IaCFinding) => f.severity === 'critical').length,
        high: findings.filter((f: IaCFinding) => f.severity === 'high').length,
        medium: findings.filter((f: IaCFinding) => f.severity === 'medium').length,
        low: findings.filter((f: IaCFinding) => f.severity === 'low').length,
        info: findings.filter((f: IaCFinding) => f.severity === 'info').length,
        total: findings.length
      };

      const result: IaCScanResult = {
        iacType: findings[0]?.iacType || 'terraform',
        scanTime: new Date().toISOString(),
        filesScanned: 1,
        findings,
        summary,
        passed: findings.length === 0 ? 1 : 0,
        failed: findings.length > 0 ? 1 : 0,
        skipped: 0
      };

      set({
        scanResults: result,
        findings,
        isScanning: false
      });
    } catch (error) {
      set({ error: String(error), isScanning: false });
    }
  },

  // Select a path using file dialog
  selectPath: async () => {
    try {
      const path = await window.electronAPI?.fs?.selectDirectory?.();
      if (path) {
        set({ selectedPath: path });
        await get().scanDirectory(path);
      }
    } catch (error) {
      set({ error: String(error) });
    }
  },

  // Clear scan results
  clearResults: () => {
    set({
      scanResults: null,
      findings: [],
      selectedPath: null,
      error: null
    });
  },

  // Fetch available rules
  fetchRules: async () => {
    try {
      const rules = await window.electronAPI?.iac?.getRules?.() || [];
      set({ rules });
    } catch (error) {
      set({ error: String(error) });
    }
  },

  // Enable a rule
  enableRule: async (ruleId) => {
    try {
      await window.electronAPI?.iac?.enableRule?.(ruleId);
      set((state) => ({
        rules: state.rules.map((r) =>
          r.id === ruleId ? { ...r, enabled: true } : r
        )
      }));
    } catch (error) {
      set({ error: String(error) });
    }
  },

  // Disable a rule
  disableRule: async (ruleId) => {
    try {
      await window.electronAPI?.iac?.disableRule?.(ruleId);
      set((state) => ({
        rules: state.rules.map((r) =>
          r.id === ruleId ? { ...r, enabled: false } : r
        )
      }));
    } catch (error) {
      set({ error: String(error) });
    }
  },

  // Filter actions
  setSeverityFilter: (severities) => set({ severityFilter: severities }),
  setIaCTypeFilter: (types) => set({ iacTypeFilter: types }),
  setSearchQuery: (query) => set({ searchQuery: query }),
  clearFilters: () => set({ severityFilter: [], iacTypeFilter: [], searchQuery: '' }),

  // Get filtered findings
  getFilteredFindings: () => {
    const { findings, severityFilter, iacTypeFilter, searchQuery } = get();

    return findings.filter((finding) => {
      // Severity filter
      if (severityFilter.length > 0 && !severityFilter.includes(finding.severity)) {
        return false;
      }

      // IaC type filter
      if (iacTypeFilter.length > 0 && !iacTypeFilter.includes(finding.iacType)) {
        return false;
      }

      // Search query
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          finding.title.toLowerCase().includes(query) ||
          finding.description.toLowerCase().includes(query) ||
          finding.file.toLowerCase().includes(query) ||
          finding.checkId.toLowerCase().includes(query)
        );
      }

      return true;
    });
  },

  // Get severity counts
  getSeverityCounts: () => {
    const { findings } = get();
    return {
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
      info: findings.filter((f) => f.severity === 'info').length
    };
  },

  // Get IaC type counts
  getIaCTypeCounts: () => {
    const { findings } = get();
    return {
      terraform: findings.filter((f) => f.iacType === 'terraform').length,
      cloudformation: findings.filter((f) => f.iacType === 'cloudformation').length,
      kubernetes: findings.filter((f) => f.iacType === 'kubernetes').length,
      dockerfile: findings.filter((f) => f.iacType === 'dockerfile').length,
      ansible: findings.filter((f) => f.iacType === 'ansible').length,
      helm: findings.filter((f) => f.iacType === 'helm').length
    };
  }
}));

// Extend window.electronAPI types
declare global {
  interface Window {
    electronAPI?: {
      iac?: {
        scanDirectory: (path: string) => Promise<IaCScanResult>;
        scanFile: (path: string) => Promise<IaCFinding[]>;
        getRules: () => Promise<IaCRule[]>;
        enableRule: (ruleId: string) => Promise<void>;
        disableRule: (ruleId: string) => Promise<void>;
      };
      fs?: {
        selectDirectory: () => Promise<string | null>;
      };
    };
  }
}
