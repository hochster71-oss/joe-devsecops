/**
 * J.O.E. Kubernetes Security Store
 * Zustand state management for Kubernetes cluster security
 *
 * Security Standards:
 * - CIS Kubernetes Benchmark v1.8
 * - NSA/CISA Kubernetes Hardening Guide v1.2
 * - NIST SP 800-190 (Container Security)
 */

import { create } from 'zustand';

// ========================================
// TYPE DEFINITIONS
// ========================================

export interface ClusterInfo {
  name: string;
  context: string;
  server: string;
  version?: string;
  nodeCount: number;
  namespaceCount: number;
  podCount: number;
  connected: boolean;
}

export interface CISFinding {
  id: string;
  section: string;
  title: string;
  status: 'PASS' | 'FAIL' | 'WARN' | 'INFO';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  remediation: string;
  reference: string;
}

export interface CISBenchmarkResult {
  version: string;
  totalChecks: number;
  passed: number;
  failed: number;
  warnings: number;
  findings: CISFinding[];
  scanTime: string;
}

export interface PSSViolation {
  namespace: string;
  pod: string;
  container: string;
  profile: 'privileged' | 'baseline' | 'restricted';
  violations: string[];
  severity: 'critical' | 'high' | 'medium';
}

export interface PodSecurityResult {
  totalPods: number;
  privilegedPods: number;
  baselinePods: number;
  restrictedPods: number;
  violations: PSSViolation[];
}

export interface RBACFinding {
  subject: string;
  subjectKind: 'User' | 'Group' | 'ServiceAccount';
  namespace?: string;
  permissions: string[];
  risk: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  recommendation: string;
}

export interface RBACAnalysisResult {
  totalServiceAccounts: number;
  overprivilegedAccounts: RBACFinding[];
  clusterAdminBindings: number;
  wildcardPermissions: RBACFinding[];
  serviceAccountRisks: RBACFinding[];
}

export interface NetworkPolicyGap {
  namespace: string;
  resource: string;
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  recommendation: string;
}

export interface NetworkPolicyResult {
  totalPolicies: number;
  namespacesWithPolicies: number;
  namespacesWithoutPolicies: string[];
  defaultDenyIngress: number;
  defaultDenyEgress: number;
  gaps: NetworkPolicyGap[];
  coverage: number;
}

export interface ImageVulnerability {
  image: string;
  namespace: string;
  pod: string;
  container: string;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  lastScanned?: string;
  findings?: Array<{
    id: string;
    severity: string;
    title: string;
    description: string;
    fixedVersion?: string;
  }>;
}

export interface SecretsExposureResult {
  totalSecrets: number;
  secretsInDefaultNamespace: number;
  secretsWithWeakEncoding: number;
  envVarSecrets: number;
  findings: Array<{
    namespace: string;
    secretName: string;
    issue: string;
    severity: 'critical' | 'high' | 'medium';
    recommendation: string;
  }>;
}

export interface ResourceQuotaResult {
  namespacesWithQuotas: number;
  namespacesWithoutQuotas: string[];
  namespacesWithLimitRanges: number;
  podsWithoutLimits: number;
  podsWithoutRequests: number;
  findings: Array<{
    namespace: string;
    resource: string;
    issue: string;
    severity: 'medium' | 'low';
  }>;
}

export interface K8sScanResults {
  cluster: ClusterInfo;
  cisBenchmark: CISBenchmarkResult;
  podSecurity: PodSecurityResult;
  rbacAnalysis: RBACAnalysisResult;
  networkPolicies: NetworkPolicyResult;
  containerImages: ImageVulnerability[];
  secretsExposure: SecretsExposureResult;
  resourceQuotas: ResourceQuotaResult;
  complianceScore: number;
  scanTime: string;
}

export interface K8sClusterConfig {
  name: string;
  context: string;
  kubeconfigPath?: string;
  namespace?: string;
}

// ========================================
// STORE INTERFACE
// ========================================

interface KubernetesState {
  // Connection state
  connected: boolean;
  connecting: boolean;
  currentCluster: ClusterInfo | null;
  availableContexts: string[];
  connectionError: string | null;

  // Scan state
  isScanning: boolean;
  scanProgress: number;
  lastScanTime: string | null;
  scanResults: K8sScanResults | null;

  // Metrics (derived from scan results)
  cisScore: number;
  pssCompliance: {
    privileged: number;
    baseline: number;
    restricted: number;
  };
  rbacRiskScore: number;
  networkCoverage: number;
  imageVulnCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };

  // Findings
  criticalFindings: Array<{
    id: string;
    type: 'cis' | 'pss' | 'rbac' | 'network' | 'image' | 'secret';
    title: string;
    severity: string;
    description: string;
    remediation: string;
  }>;

  // Actions
  loadContexts: () => Promise<void>;
  connect: (config: K8sClusterConfig) => Promise<boolean>;
  disconnect: () => void;
  runFullAudit: (namespace?: string) => Promise<void>;
  scanPodSecurity: (namespace?: string) => Promise<void>;
  scanImages: (namespace?: string) => Promise<void>;
  analyzeRBAC: () => Promise<void>;
  clearResults: () => void;
}

// ========================================
// STORE IMPLEMENTATION
// ========================================

export const useKubernetesStore = create<KubernetesState>((set, get) => ({
  // Initial state
  connected: false,
  connecting: false,
  currentCluster: null,
  availableContexts: [],
  connectionError: null,

  isScanning: false,
  scanProgress: 0,
  lastScanTime: null,
  scanResults: null,

  cisScore: 0,
  pssCompliance: { privileged: 0, baseline: 0, restricted: 0 },
  rbacRiskScore: 0,
  networkCoverage: 0,
  imageVulnCount: { critical: 0, high: 0, medium: 0, low: 0 },

  criticalFindings: [],

  // Load available Kubernetes contexts
  loadContexts: async () => {
    try {
      if (window.electronAPI?.kubernetes?.getContexts) {
        const contexts = await window.electronAPI.kubernetes.getContexts();
        set({ availableContexts: contexts });
      }
    } catch (error) {
      console.error('[K8s Store] Failed to load contexts:', error);
    }
  },

  // Connect to a Kubernetes cluster
  connect: async (config: K8sClusterConfig) => {
    set({ connecting: true, connectionError: null });

    try {
      if (!window.electronAPI?.kubernetes?.connect) {
        throw new Error('Kubernetes API not available');
      }

      const result = await window.electronAPI.kubernetes.connect(config);

      if (result.success && result.cluster) {
        set({
          connected: true,
          connecting: false,
          currentCluster: result.cluster,
          connectionError: null
        });
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

  // Disconnect from cluster
  disconnect: () => {
    if (window.electronAPI?.kubernetes?.disconnect) {
      window.electronAPI.kubernetes.disconnect();
    }
    set({
      connected: false,
      currentCluster: null,
      scanResults: null,
      cisScore: 0,
      pssCompliance: { privileged: 0, baseline: 0, restricted: 0 },
      rbacRiskScore: 0,
      networkCoverage: 0,
      imageVulnCount: { critical: 0, high: 0, medium: 0, low: 0 },
      criticalFindings: []
    });
  },

  // Run full security audit
  runFullAudit: async (namespace?: string) => {
    if (!get().connected) {
      throw new Error('Not connected to a cluster');
    }

    set({ isScanning: true, scanProgress: 0 });

    // Declare progressInterval outside try block so it can be cleared in finally
    let progressInterval: ReturnType<typeof setInterval> | null = null;

    try {
      // Simulate progress updates
      progressInterval = setInterval(() => {
        set(state => ({
          scanProgress: Math.min(state.scanProgress + 10, 90)
        }));
      }, 500);

      if (!window.electronAPI?.kubernetes?.runAudit) {
        throw new Error('Kubernetes audit API not available');
      }

      const results = await window.electronAPI.kubernetes.runAudit(namespace) as K8sScanResults;

      // Update state with results
      const criticalFindings = extractCriticalFindings(results);

      // Calculate image vulnerability totals
      const imageVulnCount = results.containerImages.reduce(
        (acc: { critical: number; high: number; medium: number; low: number }, img: ImageVulnerability) => ({
          critical: acc.critical + img.vulnerabilities.critical,
          high: acc.high + img.vulnerabilities.high,
          medium: acc.medium + img.vulnerabilities.medium,
          low: acc.low + img.vulnerabilities.low
        }),
        { critical: 0, high: 0, medium: 0, low: 0 }
      );

      set({
        isScanning: false,
        scanProgress: 100,
        lastScanTime: results.scanTime,
        scanResults: results,
        cisScore: results.cisBenchmark.totalChecks > 0
          ? Math.round((results.cisBenchmark.passed / results.cisBenchmark.totalChecks) * 100)
          : 0,
        pssCompliance: {
          privileged: results.podSecurity.privilegedPods,
          baseline: results.podSecurity.baselinePods,
          restricted: results.podSecurity.restrictedPods
        },
        rbacRiskScore: calculateRBACRiskScore(results.rbacAnalysis),
        networkCoverage: results.networkPolicies.coverage,
        imageVulnCount,
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

  // Scan pod security only
  scanPodSecurity: async (namespace?: string) => {
    if (!get().connected) {return;}

    set({ isScanning: true });
    try {
      if (window.electronAPI?.kubernetes?.getPods) {
        const podSecurity = await window.electronAPI.kubernetes.getPods(namespace) as PodSecurityResult;
        set(state => ({
          isScanning: false,
          scanResults: state.scanResults ? {
            ...state.scanResults,
            podSecurity
          } : null,
          pssCompliance: {
            privileged: podSecurity.privilegedPods,
            baseline: podSecurity.baselinePods,
            restricted: podSecurity.restrictedPods
          }
        }));
      }
    } catch (error) {
      set({ isScanning: false });
    }
  },

  // Scan container images
  scanImages: async (namespace?: string) => {
    if (!get().connected) {return;}

    set({ isScanning: true });
    try {
      if (window.electronAPI?.kubernetes?.scanImages) {
        const containerImages = await window.electronAPI.kubernetes.scanImages(namespace) as ImageVulnerability[];

        const imageVulnCount = containerImages.reduce(
          (acc: { critical: number; high: number; medium: number; low: number }, img: ImageVulnerability) => ({
            critical: acc.critical + img.vulnerabilities.critical,
            high: acc.high + img.vulnerabilities.high,
            medium: acc.medium + img.vulnerabilities.medium,
            low: acc.low + img.vulnerabilities.low
          }),
          { critical: 0, high: 0, medium: 0, low: 0 }
        );

        set(state => ({
          isScanning: false,
          scanResults: state.scanResults ? {
            ...state.scanResults,
            containerImages
          } : null,
          imageVulnCount
        }));
      }
    } catch (error) {
      set({ isScanning: false });
    }
  },

  // Analyze RBAC
  analyzeRBAC: async () => {
    if (!get().connected) {return;}

    set({ isScanning: true });
    try {
      if (window.electronAPI?.kubernetes?.analyzeRBAC) {
        const rbacAnalysis = await window.electronAPI.kubernetes.analyzeRBAC() as RBACAnalysisResult;
        set(state => ({
          isScanning: false,
          scanResults: state.scanResults ? {
            ...state.scanResults,
            rbacAnalysis
          } : null,
          rbacRiskScore: calculateRBACRiskScore(rbacAnalysis)
        }));
      }
    } catch (error) {
      set({ isScanning: false });
    }
  },

  // Clear results
  clearResults: () => {
    set({
      scanResults: null,
      cisScore: 0,
      pssCompliance: { privileged: 0, baseline: 0, restricted: 0 },
      rbacRiskScore: 0,
      networkCoverage: 0,
      imageVulnCount: { critical: 0, high: 0, medium: 0, low: 0 },
      criticalFindings: []
    });
  }
}));

// ========================================
// HELPER FUNCTIONS
// ========================================

function extractCriticalFindings(results: K8sScanResults): KubernetesState['criticalFindings'] {
  const findings: KubernetesState['criticalFindings'] = [];

  // CIS findings
  for (const finding of results.cisBenchmark.findings) {
    if (finding.status === 'FAIL' && ['critical', 'high'].includes(finding.severity)) {
      findings.push({
        id: `cis-${finding.id}`,
        type: 'cis',
        title: finding.title,
        severity: finding.severity,
        description: finding.description,
        remediation: finding.remediation
      });
    }
  }

  // PSS violations
  for (const violation of results.podSecurity.violations) {
    if (['critical', 'high'].includes(violation.severity)) {
      findings.push({
        id: `pss-${violation.namespace}-${violation.pod}`,
        type: 'pss',
        title: `Pod Security Violation: ${violation.pod}`,
        severity: violation.severity,
        description: violation.violations.join(', '),
        remediation: `Update pod ${violation.namespace}/${violation.pod} to meet ${violation.profile} profile requirements.`
      });
    }
  }

  // RBAC findings
  for (const finding of results.rbacAnalysis.overprivilegedAccounts) {
    findings.push({
      id: `rbac-${finding.subject}`,
      type: 'rbac',
      title: `Overprivileged: ${finding.subject}`,
      severity: finding.risk,
      description: finding.description,
      remediation: finding.recommendation
    });
  }

  // Image vulnerabilities
  for (const image of results.containerImages) {
    if (image.vulnerabilities.critical > 0) {
      findings.push({
        id: `image-${image.image}`,
        type: 'image',
        title: `Critical vulnerabilities in ${image.image}`,
        severity: 'critical',
        description: `${image.vulnerabilities.critical} critical, ${image.vulnerabilities.high} high vulnerabilities`,
        remediation: 'Update to patched version or use alternative image.'
      });
    }
  }

  return findings.slice(0, 20); // Limit to top 20
}

function calculateRBACRiskScore(rbac: RBACAnalysisResult): number {
  let score = 100;

  // Deduct for overprivileged accounts
  score -= rbac.overprivilegedAccounts.filter(a => a.risk === 'critical').length * 20;
  score -= rbac.overprivilegedAccounts.filter(a => a.risk === 'high').length * 10;

  // Deduct for excess cluster-admin bindings
  if (rbac.clusterAdminBindings > 3) {
    score -= (rbac.clusterAdminBindings - 3) * 5;
  }

  // Deduct for wildcard permissions
  score -= rbac.wildcardPermissions.length * 5;

  return Math.max(0, Math.min(100, score));
}

// Types are declared globally in src/types/electron.d.ts

export default useKubernetesStore;
