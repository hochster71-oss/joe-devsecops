/**
 * J.O.E. GitLab Security Store
 * Zustand state management for GitLab repository security
 *
 * Security Standards:
 * - OWASP ASVS v4.0
 * - NIST SP 800-53 SA-11
 * - DoD DevSecOps Reference Design
 * - SLSA Framework v1.0
 */

import { create } from 'zustand';

// ========================================
// TYPE DEFINITIONS
// ========================================

export interface GitLabUser {
  username: string;
  name: string;
  email: string;
}

export interface GitLabProject {
  id: number;
  name: string;
  path: string;
  pathWithNamespace: string;
  description: string;
  defaultBranch: string;
  visibility: 'private' | 'internal' | 'public';
  webUrl: string;
  lastActivity: string;
  namespace: {
    id: number;
    name: string;
    path: string;
  };
}

export interface SASTFinding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'high' | 'medium' | 'low';
  category: string;
  file: string;
  line: number;
  endLine?: number;
  code?: string;
  description: string;
  remediation: string;
  cwe?: string;
  owasp?: string;
  reference?: string;
}

export interface SecretFinding {
  id: string;
  type: string;
  file: string;
  line: number;
  secret: string;
  severity: 'critical' | 'high';
  description: string;
  remediation: string;
}

export interface PipelineIssue {
  id: string;
  type: 'security' | 'configuration' | 'best-practice';
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  location: string;
  description: string;
  remediation: string;
  reference?: string;
}

export interface PipelineSecurity {
  hasSecurityStages: boolean;
  hasSASTJob: boolean;
  hasDependencyScan: boolean;
  hasContainerScan: boolean;
  hasSecretDetection: boolean;
  hasLicenseCompliance: boolean;
  issues: PipelineIssue[];
  score: number;
}

export interface ContainerImage {
  name: string;
  tag: string;
  digest?: string;
  registry: string;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings?: Array<{
    id: string;
    severity: string;
    package: string;
    version: string;
    fixedVersion?: string;
    description: string;
  }>;
  lastScanned?: string;
}

export interface DependencyVulnerability {
  package: string;
  version: string;
  severity: string;
  cve?: string;
  fixedVersion?: string;
}

export interface GitLabScanResults {
  project: GitLabProject;
  sastFindings: SASTFinding[];
  secretsDetected: SecretFinding[];
  pipelineSecurity: PipelineSecurity;
  containerImages: ContainerImage[];
  dependencyVulnerabilities: DependencyVulnerability[];
  complianceScore: number;
  scanTime: string;
}

// ========================================
// STORE INTERFACE
// ========================================

interface GitLabState {
  // Connection state
  connected: boolean;
  connecting: boolean;
  gitlabUrl: string;
  currentUser: GitLabUser | null;
  connectionError: string | null;

  // Projects
  projects: GitLabProject[];
  selectedProject: GitLabProject | null;
  loadingProjects: boolean;

  // Scan state
  isScanning: boolean;
  scanProgress: number;
  lastScanTime: string | null;
  scanResults: GitLabScanResults | null;

  // Metrics (derived from scan results)
  sastScore: number;
  secretsCount: number;
  pipelineScore: number;
  dependencyVulnCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };

  // Critical findings for display
  criticalFindings: Array<{
    id: string;
    type: 'sast' | 'secret' | 'pipeline' | 'dependency';
    title: string;
    severity: string;
    file?: string;
    line?: number;
    description: string;
    remediation: string;
  }>;

  // Actions
  connect: (url: string, token: string) => Promise<boolean>;
  disconnect: () => void;
  loadProjects: (search?: string) => Promise<void>;
  selectProject: (project: GitLabProject) => void;
  scanProject: (projectId?: number) => Promise<void>;
  clearResults: () => void;
}

// ========================================
// STORE IMPLEMENTATION
// ========================================

export const useGitLabStore = create<GitLabState>((set, get) => ({
  // Initial state
  connected: false,
  connecting: false,
  gitlabUrl: '',
  currentUser: null,
  connectionError: null,

  projects: [],
  selectedProject: null,
  loadingProjects: false,

  isScanning: false,
  scanProgress: 0,
  lastScanTime: null,
  scanResults: null,

  sastScore: 0,
  secretsCount: 0,
  pipelineScore: 0,
  dependencyVulnCount: { critical: 0, high: 0, medium: 0, low: 0 },

  criticalFindings: [],

  // Connect to GitLab instance
  connect: async (url: string, token: string) => {
    set({ connecting: true, connectionError: null });

    try {
      if (!window.electronAPI?.gitlab?.connect) {
        throw new Error('GitLab API not available');
      }

      const result = await window.electronAPI.gitlab.connect(url, token);

      if (result.success && result.user) {
        set({
          connected: true,
          connecting: false,
          gitlabUrl: url,
          currentUser: result.user,
          connectionError: null
        });

        // Auto-load projects after connecting
        get().loadProjects();
        return true;
      } else {
        set({
          connected: false,
          connecting: false,
          connectionError: result.error || 'Failed to connect'
        });
        return false;
      }
    } catch (error: unknown) {
      set({
        connected: false,
        connecting: false,
        connectionError: error instanceof Error ? error.message : 'Connection failed'
      });
      return false;
    }
  },

  // Disconnect from GitLab
  disconnect: () => {
    if (window.electronAPI?.gitlab?.disconnect) {
      window.electronAPI.gitlab.disconnect();
    }
    set({
      connected: false,
      gitlabUrl: '',
      currentUser: null,
      projects: [],
      selectedProject: null,
      scanResults: null,
      sastScore: 0,
      secretsCount: 0,
      pipelineScore: 0,
      dependencyVulnCount: { critical: 0, high: 0, medium: 0, low: 0 },
      criticalFindings: []
    });
  },

  // Load projects
  loadProjects: async (search?: string) => {
    if (!get().connected) {return;}

    set({ loadingProjects: true });

    try {
      if (window.electronAPI?.gitlab?.listProjects) {
        const projects = await window.electronAPI.gitlab.listProjects(search);
        set({ projects, loadingProjects: false });
      }
    } catch (error) {
      console.error('[GitLab Store] Failed to load projects:', error);
      set({ loadingProjects: false });
    }
  },

  // Select a project
  selectProject: (project: GitLabProject) => {
    set({ selectedProject: project, scanResults: null, criticalFindings: [] });
  },

  // Scan selected project
  scanProject: async (projectId?: number) => {
    const project = projectId ? get().projects.find(p => p.id === projectId) : get().selectedProject;
    if (!project || !get().connected) {
      throw new Error('No project selected or not connected');
    }

    set({ isScanning: true, scanProgress: 0 });

    // Declare progressInterval outside try block so it can be cleared in finally
    let progressInterval: ReturnType<typeof setInterval> | null = null;

    try {
      // Simulate progress
      progressInterval = setInterval(() => {
        set(state => ({
          scanProgress: Math.min(state.scanProgress + 5, 90)
        }));
      }, 1000);

      if (!window.electronAPI?.gitlab?.scanProject) {
        throw new Error('GitLab scan API not available');
      }

      const results = await window.electronAPI.gitlab.scanProject(project.id) as GitLabScanResults;

      // Calculate metrics
      const criticalFindings = extractCriticalFindings(results);
      const sastScore = calculateSASTScore(results.sastFindings);
      const dependencyVulnCount = results.dependencyVulnerabilities.reduce(
        (acc: { critical: number; high: number; medium: number; low: number }, v: { severity: string }) => {
          const sev = v.severity.toLowerCase();
          if (sev === 'critical') {acc.critical++;}
          else if (sev === 'high') {acc.high++;}
          else if (sev === 'medium') {acc.medium++;}
          else {acc.low++;}
          return acc;
        },
        { critical: 0, high: 0, medium: 0, low: 0 }
      );

      set({
        isScanning: false,
        scanProgress: 100,
        lastScanTime: results.scanTime,
        scanResults: results,
        selectedProject: results.project,
        sastScore,
        secretsCount: results.secretsDetected.length,
        pipelineScore: results.pipelineSecurity.score,
        dependencyVulnCount,
        criticalFindings
      });

    } catch (error: unknown) {
      set({
        isScanning: false,
        scanProgress: 0,
        connectionError: error instanceof Error ? error.message : 'Scan failed'
      });
      throw error;
    } finally {
      // Always clear the interval to prevent memory leaks
      if (progressInterval) {
        clearInterval(progressInterval);
      }
    }
  },

  // Clear results
  clearResults: () => {
    set({
      scanResults: null,
      sastScore: 0,
      secretsCount: 0,
      pipelineScore: 0,
      dependencyVulnCount: { critical: 0, high: 0, medium: 0, low: 0 },
      criticalFindings: []
    });
  }
}));

// ========================================
// HELPER FUNCTIONS
// ========================================

function extractCriticalFindings(results: GitLabScanResults): GitLabState['criticalFindings'] {
  const findings: GitLabState['criticalFindings'] = [];

  // SAST findings
  for (const finding of results.sastFindings) {
    if (['critical', 'high'].includes(finding.severity)) {
      findings.push({
        id: finding.id,
        type: 'sast',
        title: finding.title,
        severity: finding.severity,
        file: finding.file,
        line: finding.line,
        description: finding.description,
        remediation: finding.remediation
      });
    }
  }

  // Secret findings (all are critical/high)
  for (const secret of results.secretsDetected) {
    findings.push({
      id: secret.id,
      type: 'secret',
      title: `${secret.type} detected`,
      severity: secret.severity,
      file: secret.file,
      line: secret.line,
      description: secret.description,
      remediation: secret.remediation
    });
  }

  // Pipeline issues
  for (const issue of results.pipelineSecurity.issues) {
    if (['critical', 'high'].includes(issue.severity)) {
      findings.push({
        id: issue.id,
        type: 'pipeline',
        title: issue.title,
        severity: issue.severity,
        description: issue.description,
        remediation: issue.remediation
      });
    }
  }

  // Dependency vulnerabilities
  for (const vuln of results.dependencyVulnerabilities) {
    if (['critical', 'high'].includes(vuln.severity.toLowerCase())) {
      findings.push({
        id: `dep-${vuln.package}-${vuln.cve || vuln.version}`,
        type: 'dependency',
        title: `${vuln.package}@${vuln.version} - ${vuln.cve || 'Vulnerability'}`,
        severity: vuln.severity.toLowerCase(),
        description: `Vulnerable dependency: ${vuln.package} version ${vuln.version}`,
        remediation: vuln.fixedVersion ? `Update to version ${vuln.fixedVersion}` : 'Update to latest secure version'
      });
    }
  }

  return findings.slice(0, 30); // Limit to top 30
}

function calculateSASTScore(findings: SASTFinding[]): number {
  let score = 100;

  score -= findings.filter(f => f.severity === 'critical').length * 15;
  score -= findings.filter(f => f.severity === 'high').length * 8;
  score -= findings.filter(f => f.severity === 'medium').length * 3;
  score -= findings.filter(f => f.severity === 'low').length * 1;

  return Math.max(0, Math.min(100, score));
}

// Types are declared globally in src/types/electron.d.ts

export default useGitLabStore;
