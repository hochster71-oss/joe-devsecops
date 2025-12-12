import { create } from 'zustand';

export interface RiskScore {
  overall: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ComplianceStatus {
  framework: string;
  score: number;
  level: number;
  totalControls: number;
  compliant: number;
  partiallyCompliant: number;
  nonCompliant: number;
  notAssessed: number;
}

export interface LibraryInfo {
  name: string;
  version: string;
  type: 'dependency' | 'devDependency';
  category: 'library' | 'framework' | 'tool';
  license?: string;
  description?: string;
  hasVulnerability: boolean;
  vulnerabilityLevel?: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  aiAnalysis?: string;
}

export interface SbomStats {
  totalComponents: number;
  libraries: number;
  frameworks: number;
  vulnerableComponents: number;
  lastGenerated: string | null;
  libraryDetails?: LibraryInfo[];
}

interface DashboardState {
  // Risk metrics
  riskScore: RiskScore;
  lastScanTime: string | null;
  isScanning: boolean;

  // Compliance
  compliance: ComplianceStatus;

  // SBOM
  sbomStats: SbomStats;

  // Recent findings - includes full details for actionable fixes
  recentFindings: Array<{
    id: string;
    title: string;
    severity: string;
    tool: string;
    timestamp: string;
    description?: string;
    remediation?: string;
    file?: string;
    line?: number;
  }>;

  // Auto-fix state
  isFixing: boolean;
  lastFixResult: { success: boolean; fixed: string[]; failed: string[] } | null;

  // Actions
  setRiskScore: (score: RiskScore) => void;
  setLastScanTime: (time: string) => void;
  setIsScanning: (scanning: boolean) => void;
  setCompliance: (compliance: ComplianceStatus) => void;
  setSbomStats: (stats: SbomStats) => void;
  setRecentFindings: (findings: DashboardState['recentFindings']) => void;
  refreshDashboard: () => Promise<void>;
  runAutoFix: () => Promise<{ success: boolean; fixed: string[]; failed: string[] }>;
  fixFinding: (finding: DashboardState['recentFindings'][0]) => Promise<void>;
}

export const useDashboardStore = create<DashboardState>((set, get) => ({
  // Initial state
  riskScore: {
    overall: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  },
  lastScanTime: null,
  isScanning: false,

  compliance: {
    framework: 'CMMC 2.0',
    score: 0,
    level: 0,
    totalControls: 17,
    compliant: 0,
    partiallyCompliant: 0,
    nonCompliant: 0,
    notAssessed: 17
  },

  sbomStats: {
    totalComponents: 0,
    libraries: 0,
    frameworks: 0,
    vulnerableComponents: 0,
    lastGenerated: null
  },

  recentFindings: [],

  // Auto-fix state
  isFixing: false,
  lastFixResult: null,

  // Actions
  setRiskScore: (riskScore) => set({ riskScore }),
  setLastScanTime: (lastScanTime) => set({ lastScanTime }),
  setIsScanning: (isScanning) => set({ isScanning }),
  setCompliance: (compliance) => set({ compliance }),
  setSbomStats: (sbomStats) => set({ sbomStats }),
  setRecentFindings: (recentFindings) => set({ recentFindings }),

  refreshDashboard: async () => {
    // REAL SECURITY SCANNING - Calls actual npm audit and code analysis
    set({ isScanning: true });

    try {
      // Check if we're running in Electron with the security API
      if (window.electronAPI?.security?.runAudit) {
        console.log('[J.O.E. Dashboard] Starting REAL security audit...');
        const results = await window.electronAPI.security.runAudit();
        console.log('[J.O.E. Dashboard] Audit complete:', results);

        set({
          riskScore: results.riskScore,
          lastScanTime: results.scanTime,
          compliance: results.compliance,
          sbomStats: {
            ...results.sbomStats,
            // Include library details for AI-driven analysis modal
            libraryDetails: results.sbomStats.libraryDetails || []
          },
          // Include FULL finding data for actionable fixes
          recentFindings: results.findings.map(f => ({
            id: f.id,
            title: f.title,
            severity: f.severity,
            tool: f.tool,
            timestamp: f.timestamp,
            description: f.description,
            remediation: f.remediation,
            file: f.file,
            line: f.line
          })),
          isScanning: false
        });
      } else {
        // Fallback for browser development mode (not in Electron)
        console.warn('[J.O.E. Dashboard] Not in Electron - using dev fallback data');
        set({
          riskScore: {
            overall: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
          },
          lastScanTime: new Date().toISOString(),
          compliance: {
            framework: 'CMMC 2.0',
            score: 0,
            level: 0,
            totalControls: 17,
            compliant: 0,
            partiallyCompliant: 0,
            nonCompliant: 0,
            notAssessed: 17
          },
          sbomStats: {
            totalComponents: 0,
            libraries: 0,
            frameworks: 0,
            vulnerableComponents: 0,
            lastGenerated: null
          },
          recentFindings: [{
            id: 'dev-notice',
            title: 'Running in browser mode - launch in Electron for real scans',
            severity: 'info',
            tool: 'J.O.E. System',
            timestamp: new Date().toISOString()
          }],
          isScanning: false
        });
      }
    } catch (error) {
      console.error('[J.O.E. Dashboard] Security audit failed:', error);
      set({
        isScanning: false,
        recentFindings: [{
          id: 'error-1',
          title: `Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          severity: 'high',
          tool: 'J.O.E. System',
          timestamp: new Date().toISOString()
        }]
      });
    }
  },

  runAutoFix: async () => {
    // AI-POWERED AUTO-REMEDIATION
    set({ isFixing: true, lastFixResult: null });

    try {
      if (window.electronAPI?.security?.autoFix) {
        console.log('[J.O.E. Dashboard] Starting AI auto-fix...');
        const result = await window.electronAPI.security.autoFix();
        console.log('[J.O.E. Dashboard] Auto-fix complete:', result);

        set({
          isFixing: false,
          lastFixResult: result
        });

        // Re-scan after fixes
        if (result.success && result.fixed.length > 0) {
          console.log('[J.O.E. Dashboard] Re-scanning after fixes...');
          await get().refreshDashboard();
        }

        return result;
      } else {
        console.warn('[J.O.E. Dashboard] Not in Electron - auto-fix unavailable');
        const fallbackResult = { success: false, fixed: [], failed: ['Auto-fix requires Electron environment'] };
        set({ isFixing: false, lastFixResult: fallbackResult });
        return fallbackResult;
      }
    } catch (error) {
      console.error('[J.O.E. Dashboard] Auto-fix failed:', error);
      const errorResult = {
        success: false,
        fixed: [],
        failed: [error instanceof Error ? error.message : 'Unknown error']
      };
      set({ isFixing: false, lastFixResult: errorResult });
      return errorResult;
    }
  },

  fixFinding: async (finding) => {
    // FIX A SPECIFIC FINDING
    console.log('[J.O.E. Dashboard] Fixing finding:', finding.id, finding.title);

    try {
      // For npm vulnerabilities, run auto-fix
      if (finding.tool === 'npm audit') {
        const result = await get().runAutoFix();
        if (result.success) {
          // Remove the finding from the list
          const currentFindings = get().recentFindings;
          set({
            recentFindings: currentFindings.filter(f => f.id !== finding.id)
          });
        }
        return;
      }

      // For other findings, show remediation and re-scan
      console.log('[J.O.E. Dashboard] Remediation:', finding.remediation);

      // Re-scan after potential manual fix
      await get().refreshDashboard();

    } catch (error) {
      console.error('[J.O.E. Dashboard] Fix finding failed:', error);
    }
  }
}));
