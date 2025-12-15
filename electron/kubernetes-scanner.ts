/**
 * J.O.E. Kubernetes Security Scanner
 * DoD-Hardened Kubernetes Cluster Security Analysis
 *
 * Security Standards Implemented:
 * - CIS Kubernetes Benchmark v1.8 (Center for Internet Security)
 * - NSA/CISA Kubernetes Hardening Guide v1.2
 * - NIST SP 800-190 (Container Security Guide)
 * - Pod Security Standards (Privileged, Baseline, Restricted)
 *
 * References:
 * - CIS Benchmark: https://www.cisecurity.org/benchmark/kubernetes
 * - NSA/CISA Guide: https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
 * - NIST SP 800-190: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as k8s from '@kubernetes/client-node';
import * as fs from 'fs';

const execAsync = promisify(exec);

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
  id: string;                // e.g., "1.1.1", "4.2.6"
  section: string;           // e.g., "Control Plane Configuration"
  title: string;
  status: 'PASS' | 'FAIL' | 'WARN' | 'INFO';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  remediation: string;
  reference: string;         // CIS Benchmark reference URL
}

export interface CISBenchmarkResult {
  version: string;           // "v1.8.0"
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
  privilegedPods: number;    // Pods running as privileged
  baselinePods: number;      // Pods meeting baseline but not restricted
  restrictedPods: number;    // Pods meeting restricted profile
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
  coverage: number;          // Percentage of namespaces with policies
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
  envVarSecrets: number;     // Secrets exposed via environment variables
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
  complianceScore: number;   // 0-100
  scanTime: string;
}

export interface K8sClusterConfig {
  name: string;
  context: string;
  kubeconfigPath?: string;
  namespace?: string;        // Target namespace (scans all if omitted)
}

// ========================================
// KUBERNETES SCANNER CLASS
// ========================================

class KubernetesScanner {
  private kc: k8s.KubeConfig;
  private k8sApi: k8s.CoreV1Api | null = null;
  private rbacApi: k8s.RbacAuthorizationV1Api | null = null;
  private networkingApi: k8s.NetworkingV1Api | null = null;
  private currentContext: string = '';
  private connected: boolean = false;

  constructor() {
    this.kc = new k8s.KubeConfig();
  }

  /**
   * Get available Kubernetes contexts from kubeconfig
   */
  async getContexts(): Promise<string[]> {
    try {
      this.kc.loadFromDefault();
      return this.kc.getContexts().map(ctx => ctx.name);
    } catch (error) {
      console.error('[J.O.E. K8s] Error loading kubeconfig:', error);
      return [];
    }
  }

  /**
   * Connect to a Kubernetes cluster
   * Reference: NSA/CISA Guide Section 2 - Kubernetes Authentication
   */
  async connect(config: K8sClusterConfig): Promise<{ success: boolean; cluster?: ClusterInfo; error?: string }> {
    try {
      console.log('[J.O.E. K8s] Connecting to cluster:', config.context);

      // Load kubeconfig
      if (config.kubeconfigPath && fs.existsSync(config.kubeconfigPath)) {
        this.kc.loadFromFile(config.kubeconfigPath);
      } else {
        this.kc.loadFromDefault();
      }

      // Set context
      this.kc.setCurrentContext(config.context);
      this.currentContext = config.context;

      // Initialize API clients
      this.k8sApi = this.kc.makeApiClient(k8s.CoreV1Api);
      this.rbacApi = this.kc.makeApiClient(k8s.RbacAuthorizationV1Api);
      this.networkingApi = this.kc.makeApiClient(k8s.NetworkingV1Api);

      // Test connection by getting cluster info
      const versionInfo = await this.getClusterVersion();
      const nodes = await this.k8sApi.listNode();
      const namespaces = await this.k8sApi.listNamespace();
      const pods = await this.k8sApi.listPodForAllNamespaces();

      const cluster = this.kc.getCurrentCluster();

      this.connected = true;

      const clusterInfo: ClusterInfo = {
        name: config.name || config.context,
        context: config.context,
        server: cluster?.server || 'unknown',
        version: versionInfo,
        nodeCount: nodes.items.length,
        namespaceCount: namespaces.items.length,
        podCount: pods.items.length,
        connected: true
      };

      console.log('[J.O.E. K8s] Connected successfully:', clusterInfo.name);
      return { success: true, cluster: clusterInfo };

    } catch (error) {
      console.error('[J.O.E. K8s] Connection failed:', error);
      this.connected = false;
      return {
        success: false,
        error: (error as Error).message || 'Failed to connect to Kubernetes cluster'
      };
    }
  }

  /**
   * Disconnect from cluster
   */
  disconnect(): void {
    this.k8sApi = null;
    this.rbacApi = null;
    this.networkingApi = null;
    this.connected = false;
    this.currentContext = '';
    console.log('[J.O.E. K8s] Disconnected from cluster');
  }

  /**
   * Run full Kubernetes security audit
   * Reference: CIS Kubernetes Benchmark v1.8
   */
  async runFullAudit(targetNamespace?: string): Promise<K8sScanResults> {
    if (!this.connected || !this.k8sApi) {
      throw new Error('Not connected to a Kubernetes cluster');
    }

    console.log('[J.O.E. K8s] Starting full security audit...');
    const startTime = new Date();

    // Run all security checks in parallel where possible
    const [
      clusterInfo,
      cisBenchmark,
      podSecurity,
      rbacAnalysis,
      networkPolicies,
      containerImages,
      secretsExposure,
      resourceQuotas
    ] = await Promise.all([
      this.getClusterInfo(),
      this.runCISBenchmark(),
      this.analyzePodSecurity(targetNamespace),
      this.analyzeRBAC(),
      this.analyzeNetworkPolicies(),
      this.scanContainerImages(targetNamespace),
      this.analyzeSecretsExposure(targetNamespace),
      this.analyzeResourceQuotas()
    ]);

    // Calculate overall compliance score
    const complianceScore = this.calculateComplianceScore({
      cisBenchmark,
      podSecurity,
      rbacAnalysis,
      networkPolicies,
      secretsExposure
    });

    const scanTime = new Date().toISOString();
    const duration = Date.now() - startTime.getTime();
    console.log(`[J.O.E. K8s] Audit complete in ${duration}ms. Score: ${complianceScore}%`);

    return {
      cluster: clusterInfo,
      cisBenchmark,
      podSecurity,
      rbacAnalysis,
      networkPolicies,
      containerImages,
      secretsExposure,
      resourceQuotas,
      complianceScore,
      scanTime
    };
  }

  /**
   * Get cluster version
   */
  private async getClusterVersion(): Promise<string> {
    try {
      const { stdout } = await execAsync('kubectl version --client=false -o json');
      const version = JSON.parse(stdout);
      return version.serverVersion?.gitVersion || 'unknown';
    } catch {
      return 'unknown';
    }
  }

  /**
   * Get cluster information
   */
  private async getClusterInfo(): Promise<ClusterInfo> {
    if (!this.k8sApi) {throw new Error('Not connected');}

    const nodes = await this.k8sApi.listNode();
    const namespaces = await this.k8sApi.listNamespace();
    const pods = await this.k8sApi.listPodForAllNamespaces();
    const cluster = this.kc.getCurrentCluster();

    return {
      name: this.currentContext,
      context: this.currentContext,
      server: cluster?.server || 'unknown',
      version: await this.getClusterVersion(),
      nodeCount: nodes.items.length,
      namespaceCount: namespaces.items.length,
      podCount: pods.items.length,
      connected: true
    };
  }

  /**
   * Run CIS Kubernetes Benchmark checks
   * Reference: CIS Kubernetes Benchmark v1.8.0
   * https://www.cisecurity.org/benchmark/kubernetes
   */
  private async runCISBenchmark(): Promise<CISBenchmarkResult> {
    console.log('[J.O.E. K8s] Running CIS Benchmark checks...');
    const findings: CISFinding[] = [];

    // Try to run kube-bench if available
    try {
      const { stdout } = await execAsync('kube-bench run --json', { timeout: 120000 });
      const benchResults = JSON.parse(stdout);

      // Parse kube-bench results
      for (const control of benchResults.Controls || []) {
        for (const test of control.tests || []) {
          for (const result of test.results || []) {
            findings.push({
              id: result.test_number,
              section: control.text,
              title: result.test_desc,
              status: result.status.toUpperCase() as 'PASS' | 'FAIL' | 'WARN' | 'INFO',
              severity: this.mapCISSeverity(result.status, result.scored),
              description: result.test_desc,
              remediation: result.remediation || 'See CIS Benchmark documentation',
              reference: `CIS Kubernetes Benchmark v1.8.0 - ${result.test_number}`
            });
          }
        }
      }
    } catch {
      // kube-bench not available, run manual checks
      console.log('[J.O.E. K8s] kube-bench not available, running manual CIS checks...');
      findings.push(...await this.runManualCISChecks());
    }

    const passed = findings.filter(f => f.status === 'PASS').length;
    const failed = findings.filter(f => f.status === 'FAIL').length;
    const warnings = findings.filter(f => f.status === 'WARN').length;

    return {
      version: 'v1.8.0',
      totalChecks: findings.length,
      passed,
      failed,
      warnings,
      findings,
      scanTime: new Date().toISOString()
    };
  }

  /**
   * Manual CIS checks when kube-bench is not available
   */
  private async runManualCISChecks(): Promise<CISFinding[]> {
    const findings: CISFinding[] = [];

    if (!this.k8sApi) {return findings;}

    // CIS 5.1.1 - Ensure that the cluster-admin role is only used where required
    const clusterRoleBindings = await this.rbacApi?.listClusterRoleBinding();
    const adminBindings = clusterRoleBindings?.items.filter(
      (crb: k8s.V1ClusterRoleBinding) => crb.roleRef.name === 'cluster-admin'
    ) || [];

    if (adminBindings.length > 2) {
      findings.push({
        id: '5.1.1',
        section: 'RBAC and Service Accounts',
        title: 'Minimize use of cluster-admin role',
        status: 'FAIL',
        severity: 'high',
        description: `Found ${adminBindings.length} cluster-admin role bindings. Limit cluster-admin usage.`,
        remediation: 'Review cluster-admin bindings and use more restrictive roles where possible.',
        reference: 'CIS Kubernetes Benchmark v1.8.0 - 5.1.1'
      });
    } else {
      findings.push({
        id: '5.1.1',
        section: 'RBAC and Service Accounts',
        title: 'Minimize use of cluster-admin role',
        status: 'PASS',
        severity: 'info',
        description: 'Cluster-admin role usage is minimal.',
        remediation: 'N/A',
        reference: 'CIS Kubernetes Benchmark v1.8.0 - 5.1.1'
      });
    }

    // CIS 5.1.3 - Minimize wildcard use in Roles and ClusterRoles
    const clusterRoles = await this.rbacApi?.listClusterRole();
    const wildcardRoles = clusterRoles?.items.filter((cr: k8s.V1ClusterRole) =>
      cr.rules?.some((rule: k8s.V1PolicyRule) =>
        rule.verbs?.includes('*') || rule.resources?.includes('*') || rule.apiGroups?.includes('*')
      )
    ) || [];

    if (wildcardRoles.length > 5) {
      findings.push({
        id: '5.1.3',
        section: 'RBAC and Service Accounts',
        title: 'Minimize wildcard use in Roles and ClusterRoles',
        status: 'FAIL',
        severity: 'medium',
        description: `Found ${wildcardRoles.length} roles with wildcard permissions.`,
        remediation: 'Replace wildcard (*) permissions with specific resource and verb lists.',
        reference: 'CIS Kubernetes Benchmark v1.8.0 - 5.1.3'
      });
    }

    // CIS 5.2.2 - Minimize the admission of privileged containers
    const pods = await this.k8sApi.listPodForAllNamespaces();
    const privilegedPods = pods.items.filter((pod: k8s.V1Pod) =>
      pod.spec?.containers?.some((c: k8s.V1Container) => c.securityContext?.privileged === true)
    );

    if (privilegedPods.length > 0) {
      findings.push({
        id: '5.2.2',
        section: 'Pod Security Standards',
        title: 'Minimize the admission of privileged containers',
        status: 'FAIL',
        severity: 'critical',
        description: `Found ${privilegedPods.length} pods running privileged containers.`,
        remediation: 'Remove privileged: true from container security contexts. Use Pod Security Standards.',
        reference: 'CIS Kubernetes Benchmark v1.8.0 - 5.2.2'
      });
    } else {
      findings.push({
        id: '5.2.2',
        section: 'Pod Security Standards',
        title: 'Minimize the admission of privileged containers',
        status: 'PASS',
        severity: 'info',
        description: 'No privileged containers found.',
        remediation: 'N/A',
        reference: 'CIS Kubernetes Benchmark v1.8.0 - 5.2.2'
      });
    }

    // CIS 5.2.3 - Minimize the admission of containers wishing to share the host process ID namespace
    const hostPIDPods = pods.items.filter((pod: k8s.V1Pod) => pod.spec?.hostPID === true);
    if (hostPIDPods.length > 0) {
      findings.push({
        id: '5.2.3',
        section: 'Pod Security Standards',
        title: 'Minimize containers sharing host PID namespace',
        status: 'FAIL',
        severity: 'high',
        description: `Found ${hostPIDPods.length} pods with hostPID: true.`,
        remediation: 'Set hostPID: false in pod specifications unless absolutely required.',
        reference: 'CIS Kubernetes Benchmark v1.8.0 - 5.2.3'
      });
    }

    // CIS 5.2.4 - Minimize the admission of containers wishing to share the host network namespace
    const hostNetworkPods = pods.items.filter((pod: k8s.V1Pod) => pod.spec?.hostNetwork === true);
    if (hostNetworkPods.length > 0) {
      findings.push({
        id: '5.2.4',
        section: 'Pod Security Standards',
        title: 'Minimize containers sharing host network namespace',
        status: 'FAIL',
        severity: 'high',
        description: `Found ${hostNetworkPods.length} pods with hostNetwork: true.`,
        remediation: 'Set hostNetwork: false in pod specifications unless absolutely required.',
        reference: 'CIS Kubernetes Benchmark v1.8.0 - 5.2.4'
      });
    }

    // CIS 5.3.2 - Ensure that all Namespaces have Network Policies defined
    const namespaces = await this.k8sApi.listNamespace();
    const networkPolicies = await this.networkingApi?.listNetworkPolicyForAllNamespaces();
    const nsWithPolicies = new Set(networkPolicies?.items.map((np: k8s.V1NetworkPolicy) => np.metadata?.namespace));

    const nsWithoutPolicies = namespaces.items
      .filter((ns: k8s.V1Namespace) => !['kube-system', 'kube-public', 'kube-node-lease'].includes(ns.metadata?.name || ''))
      .filter((ns: k8s.V1Namespace) => !nsWithPolicies.has(ns.metadata?.name));

    if (nsWithoutPolicies.length > 0) {
      findings.push({
        id: '5.3.2',
        section: 'Network Policies and CNI',
        title: 'Ensure all Namespaces have Network Policies defined',
        status: 'FAIL',
        severity: 'medium',
        description: `${nsWithoutPolicies.length} namespaces lack network policies: ${nsWithoutPolicies.map(ns => ns.metadata?.name).join(', ')}`,
        remediation: 'Define NetworkPolicy resources for all namespaces to restrict pod-to-pod communication.',
        reference: 'CIS Kubernetes Benchmark v1.8.0 - 5.3.2'
      });
    }

    // CIS 5.4.1 - Prefer using secrets as files over secrets as environment variables
    const podsWithEnvSecrets = pods.items.filter((pod: k8s.V1Pod) =>
      pod.spec?.containers?.some((c: k8s.V1Container) =>
        c.env?.some((e: k8s.V1EnvVar) => e.valueFrom?.secretKeyRef) ||
        c.envFrom?.some((ef: k8s.V1EnvFromSource) => ef.secretRef)
      )
    );

    if (podsWithEnvSecrets.length > 0) {
      findings.push({
        id: '5.4.1',
        section: 'Secrets Management',
        title: 'Prefer using secrets as files over environment variables',
        status: 'WARN',
        severity: 'medium',
        description: `${podsWithEnvSecrets.length} pods expose secrets via environment variables.`,
        remediation: 'Mount secrets as volumes instead of environment variables to reduce exposure risk.',
        reference: 'CIS Kubernetes Benchmark v1.8.0 - 5.4.1'
      });
    }

    return findings;
  }

  /**
   * Analyze Pod Security Standards compliance
   * Reference: Kubernetes Pod Security Standards
   * https://kubernetes.io/docs/concepts/security/pod-security-standards/
   */
  private async analyzePodSecurity(targetNamespace?: string): Promise<PodSecurityResult> {
    console.log('[J.O.E. K8s] Analyzing Pod Security Standards...');

    if (!this.k8sApi) {throw new Error('Not connected');}

    const pods = targetNamespace
      ? await this.k8sApi.listNamespacedPod({ namespace: targetNamespace })
      : await this.k8sApi.listPodForAllNamespaces();

    const violations: PSSViolation[] = [];
    let privilegedPods = 0;
    let baselinePods = 0;
    let restrictedPods = 0;

    for (const pod of pods.items) {
      const podName = pod.metadata?.name || 'unknown';
      const namespace = pod.metadata?.namespace || 'default';
      const containers = pod.spec?.containers || [];
      const initContainers = pod.spec?.initContainers || [];
      const allContainers = [...containers, ...initContainers];

      // Check each container against PSS profiles
      for (const container of allContainers) {
        const containerName = container.name;
        const sc = container.securityContext;
        const podSc = pod.spec?.securityContext;
        const containerViolations: string[] = [];

        // PRIVILEGED profile violations (should never happen)
        if (sc?.privileged === true) {
          containerViolations.push('Container runs as privileged');
          privilegedPods++;
        }

        // BASELINE profile violations
        if (pod.spec?.hostNetwork === true) {
          containerViolations.push('Pod uses host network namespace');
        }
        if (pod.spec?.hostPID === true) {
          containerViolations.push('Pod uses host PID namespace');
        }
        if (pod.spec?.hostIPC === true) {
          containerViolations.push('Pod uses host IPC namespace');
        }
        if (sc?.capabilities?.add?.some((cap: string) => ['NET_ADMIN', 'SYS_ADMIN', 'ALL'].includes(cap))) {
          containerViolations.push('Container adds dangerous capabilities');
        }

        // RESTRICTED profile violations
        if (sc?.runAsNonRoot !== true && podSc?.runAsNonRoot !== true) {
          containerViolations.push('Container may run as root (runAsNonRoot not set)');
        }
        if (sc?.allowPrivilegeEscalation !== false) {
          containerViolations.push('Privilege escalation not explicitly disabled');
        }
        if (!sc?.seccompProfile && !podSc?.seccompProfile) {
          containerViolations.push('No seccomp profile defined');
        }

        if (containerViolations.length > 0) {
          const severity = sc?.privileged === true ? 'critical' :
            (pod.spec?.hostNetwork || pod.spec?.hostPID) ? 'high' : 'medium';

          violations.push({
            namespace,
            pod: podName,
            container: containerName,
            profile: sc?.privileged === true ? 'privileged' : 'baseline',
            violations: containerViolations,
            severity
          });
        } else {
          restrictedPods++;
        }
      }
    }

    baselinePods = pods.items.length - privilegedPods - restrictedPods;

    return {
      totalPods: pods.items.length,
      privilegedPods,
      baselinePods: Math.max(0, baselinePods),
      restrictedPods,
      violations
    };
  }

  /**
   * Analyze RBAC configuration for overprivileged accounts
   * Reference: NSA/CISA Kubernetes Hardening Guide - Section 4
   */
  private async analyzeRBAC(): Promise<RBACAnalysisResult> {
    console.log('[J.O.E. K8s] Analyzing RBAC configuration...');

    if (!this.rbacApi || !this.k8sApi) {throw new Error('Not connected');}

    const serviceAccounts = await this.k8sApi.listServiceAccountForAllNamespaces();
    const clusterRoleBindings = await this.rbacApi.listClusterRoleBinding();
    const clusterRoles = await this.rbacApi.listClusterRole();
    const roleBindings = await this.rbacApi.listRoleBindingForAllNamespaces();

    const overprivilegedAccounts: RBACFinding[] = [];
    const wildcardPermissions: RBACFinding[] = [];
    const serviceAccountRisks: RBACFinding[] = [];

    // Count cluster-admin bindings
    const adminBindings = clusterRoleBindings.items.filter(
      (crb: k8s.V1ClusterRoleBinding) => crb.roleRef.name === 'cluster-admin'
    );

    // Find overprivileged cluster role bindings
    for (const crb of clusterRoleBindings.items) {
      if (crb.roleRef.name === 'cluster-admin') {
        for (const subject of crb.subjects || []) {
          if (subject.kind === 'ServiceAccount' && subject.namespace !== 'kube-system') {
            overprivilegedAccounts.push({
              subject: `${subject.namespace}/${subject.name}`,
              subjectKind: 'ServiceAccount',
              namespace: subject.namespace,
              permissions: ['cluster-admin'],
              risk: 'critical',
              description: 'ServiceAccount has cluster-admin privileges',
              recommendation: 'Replace with more restrictive role. Cluster-admin should only be used for system components.'
            });
          }
        }
      }
    }

    // Check for wildcard permissions in cluster roles
    for (const cr of clusterRoles.items) {
      const wildcardRules = cr.rules?.filter((rule: k8s.V1PolicyRule) =>
        rule.verbs?.includes('*') || rule.resources?.includes('*')
      ) || [];

      if (wildcardRules.length > 0 && !cr.metadata?.name?.startsWith('system:')) {
        wildcardPermissions.push({
          subject: cr.metadata?.name || 'unknown',
          subjectKind: 'ServiceAccount',
          permissions: wildcardRules.map((r: k8s.V1PolicyRule) =>
            `${r.apiGroups?.join(',')}/${r.resources?.join(',')}:${r.verbs?.join(',')}`
          ),
          risk: 'high',
          description: 'ClusterRole uses wildcard permissions',
          recommendation: 'Replace wildcards with explicit resource and verb lists.'
        });
      }
    }

    // Check for service accounts with automounted tokens in non-system namespaces
    for (const sa of serviceAccounts.items) {
      const namespace = sa.metadata?.namespace || '';
      if (!['kube-system', 'kube-public'].includes(namespace)) {
        if (sa.automountServiceAccountToken !== false) {
          // Check if this SA has any bindings
          const hasBindings = roleBindings.items.some((rb: k8s.V1RoleBinding) =>
            rb.subjects?.some((s: k8s.RbacV1Subject) =>
              s.kind === 'ServiceAccount' &&
              s.name === sa.metadata?.name &&
              s.namespace === namespace
            )
          );

          if (!hasBindings) {
            serviceAccountRisks.push({
              subject: `${namespace}/${sa.metadata?.name}`,
              subjectKind: 'ServiceAccount',
              namespace,
              permissions: ['token auto-mounted'],
              risk: 'low',
              description: 'ServiceAccount has auto-mounted token but no role bindings',
              recommendation: 'Set automountServiceAccountToken: false if token not needed.'
            });
          }
        }
      }
    }

    return {
      totalServiceAccounts: serviceAccounts.items.length,
      overprivilegedAccounts,
      clusterAdminBindings: adminBindings.length,
      wildcardPermissions,
      serviceAccountRisks
    };
  }

  /**
   * Analyze Network Policies
   * Reference: NSA/CISA Guide Section 5 - Network Separation and Hardening
   */
  private async analyzeNetworkPolicies(): Promise<NetworkPolicyResult> {
    console.log('[J.O.E. K8s] Analyzing Network Policies...');

    if (!this.networkingApi || !this.k8sApi) {throw new Error('Not connected');}

    const namespaces = await this.k8sApi.listNamespace();
    const networkPolicies = await this.networkingApi.listNetworkPolicyForAllNamespaces();

    const gaps: NetworkPolicyGap[] = [];
    const nsWithPolicies = new Set<string>();
    let defaultDenyIngress = 0;
    let defaultDenyEgress = 0;

    // Analyze each network policy
    for (const np of networkPolicies.items) {
      const namespace = np.metadata?.namespace || '';
      nsWithPolicies.add(namespace);

      // Check for default deny policies
      const policyTypes = np.spec?.policyTypes || [];
      const podSelector = np.spec?.podSelector?.matchLabels;

      if (!podSelector || Object.keys(podSelector).length === 0) {
        // Empty pod selector = applies to all pods
        if (policyTypes.includes('Ingress') && !np.spec?.ingress?.length) {
          defaultDenyIngress++;
        }
        if (policyTypes.includes('Egress') && !np.spec?.egress?.length) {
          defaultDenyEgress++;
        }
      }
    }

    // Find namespaces without policies
    const systemNamespaces = ['kube-system', 'kube-public', 'kube-node-lease'];
    const namespacesWithoutPolicies: string[] = [];

    for (const ns of namespaces.items) {
      const nsName = ns.metadata?.name || '';
      if (!systemNamespaces.includes(nsName) && !nsWithPolicies.has(nsName)) {
        namespacesWithoutPolicies.push(nsName);
        gaps.push({
          namespace: nsName,
          resource: 'Namespace',
          issue: 'No NetworkPolicy defined',
          severity: 'medium',
          recommendation: 'Create a default-deny NetworkPolicy and allow only required traffic.'
        });
      }
    }

    const userNamespaces = namespaces.items.filter(
      (ns: k8s.V1Namespace) => !systemNamespaces.includes(ns.metadata?.name || '')
    );
    const coverage = userNamespaces.length > 0
      ? Math.round((nsWithPolicies.size / userNamespaces.length) * 100)
      : 100;

    return {
      totalPolicies: networkPolicies.items.length,
      namespacesWithPolicies: nsWithPolicies.size,
      namespacesWithoutPolicies,
      defaultDenyIngress,
      defaultDenyEgress,
      gaps,
      coverage
    };
  }

  /**
   * Scan container images for vulnerabilities using Trivy
   * Reference: NIST SP 800-190 Section 4 - Image Vulnerabilities
   */
  private async scanContainerImages(targetNamespace?: string): Promise<ImageVulnerability[]> {
    console.log('[J.O.E. K8s] Scanning container images...');

    if (!this.k8sApi) {throw new Error('Not connected');}

    const pods = targetNamespace
      ? await this.k8sApi.listNamespacedPod({ namespace: targetNamespace })
      : await this.k8sApi.listPodForAllNamespaces();

    const imageVulns: ImageVulnerability[] = [];
    const scannedImages = new Set<string>();

    for (const pod of pods.items) {
      const namespace = pod.metadata?.namespace || '';
      const podName = pod.metadata?.name || '';

      for (const container of pod.spec?.containers || []) {
        const image = container.image || '';
        const containerName = container.name;

        // Skip if already scanned this image
        if (scannedImages.has(image)) {
          continue;
        }
        scannedImages.add(image);

        // Try to scan with Trivy
        try {
          const { stdout } = await execAsync(`trivy image --format json --quiet "${image}"`, {
            timeout: 60000
          });

          const trivyResults = JSON.parse(stdout);
          let critical = 0, high = 0, medium = 0, low = 0;
          const findings: Array<{
            id: string;
            severity: string;
            title: string;
            description: string;
            fixedVersion?: string;
          }> = [];

          for (const result of trivyResults.Results || []) {
            for (const vuln of result.Vulnerabilities || []) {
              switch (vuln.Severity) {
                case 'CRITICAL': critical++; break;
                case 'HIGH': high++; break;
                case 'MEDIUM': medium++; break;
                case 'LOW': low++; break;
              }

              if (findings.length < 10) { // Limit to top 10 findings per image
                findings.push({
                  id: vuln.VulnerabilityID,
                  severity: vuln.Severity,
                  title: vuln.Title || vuln.VulnerabilityID,
                  description: vuln.Description || '',
                  fixedVersion: vuln.FixedVersion
                });
              }
            }
          }

          imageVulns.push({
            image,
            namespace,
            pod: podName,
            container: containerName,
            vulnerabilities: { critical, high, medium, low },
            lastScanned: new Date().toISOString(),
            findings
          });

        } catch (error) {
          // Trivy not available or scan failed
          imageVulns.push({
            image,
            namespace,
            pod: podName,
            container: containerName,
            vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
            lastScanned: undefined,
            findings: []
          });
        }
      }
    }

    return imageVulns;
  }

  /**
   * Analyze secrets exposure
   * Reference: CIS Benchmark 5.4 - Secrets Management
   */
  private async analyzeSecretsExposure(targetNamespace?: string): Promise<SecretsExposureResult> {
    console.log('[J.O.E. K8s] Analyzing secrets exposure...');

    if (!this.k8sApi) {throw new Error('Not connected');}

    const secrets = targetNamespace
      ? await this.k8sApi.listNamespacedSecret({ namespace: targetNamespace })
      : await this.k8sApi.listSecretForAllNamespaces();

    const pods = targetNamespace
      ? await this.k8sApi.listNamespacedPod({ namespace: targetNamespace })
      : await this.k8sApi.listPodForAllNamespaces();

    const findings: SecretsExposureResult['findings'] = [];
    let secretsInDefault = 0;
    let envVarSecrets = 0;

    // Check secrets in default namespace
    for (const secret of secrets.items) {
      if (secret.metadata?.namespace === 'default' && secret.type !== 'kubernetes.io/service-account-token') {
        secretsInDefault++;
        findings.push({
          namespace: 'default',
          secretName: secret.metadata?.name || 'unknown',
          issue: 'Secret in default namespace',
          severity: 'medium',
          recommendation: 'Move secrets to dedicated namespaces with appropriate RBAC.'
        });
      }
    }

    // Check for secrets exposed via environment variables
    for (const pod of pods.items) {
      const namespace = pod.metadata?.namespace || '';
      const podName = pod.metadata?.name || '';

      for (const container of pod.spec?.containers || []) {
        // Check env from secrets
        const envSecrets = container.env?.filter(e => e.valueFrom?.secretKeyRef) || [];
        const envFromSecrets = container.envFrom?.filter(ef => ef.secretRef) || [];

        if (envSecrets.length > 0 || envFromSecrets.length > 0) {
          envVarSecrets++;
          findings.push({
            namespace,
            secretName: `${podName}/${container.name}`,
            issue: 'Secret exposed via environment variable',
            severity: 'medium',
            recommendation: 'Mount secrets as volumes instead of environment variables.'
          });
        }
      }
    }

    return {
      totalSecrets: secrets.items.length,
      secretsInDefaultNamespace: secretsInDefault,
      secretsWithWeakEncoding: 0, // Would need to check encryption at rest
      envVarSecrets,
      findings
    };
  }

  /**
   * Analyze resource quotas and limits
   * Reference: DoD Container Hardening Guide - Resource Management
   */
  private async analyzeResourceQuotas(): Promise<ResourceQuotaResult> {
    console.log('[J.O.E. K8s] Analyzing resource quotas...');

    if (!this.k8sApi) {throw new Error('Not connected');}

    const namespaces = await this.k8sApi.listNamespace();
    const resourceQuotas = await this.k8sApi.listResourceQuotaForAllNamespaces();
    const limitRanges = await this.k8sApi.listLimitRangeForAllNamespaces();
    const pods = await this.k8sApi.listPodForAllNamespaces();

    const nsWithQuotas = new Set(resourceQuotas.items.map(rq => rq.metadata?.namespace));
    const nsWithLimitRanges = new Set(limitRanges.items.map(lr => lr.metadata?.namespace));

    const systemNamespaces = ['kube-system', 'kube-public', 'kube-node-lease'];
    const namespacesWithoutQuotas: string[] = [];
    const findings: ResourceQuotaResult['findings'] = [];

    let podsWithoutLimits = 0;
    let podsWithoutRequests = 0;

    // Check namespaces without quotas
    for (const ns of namespaces.items) {
      const nsName = ns.metadata?.name || '';
      if (!systemNamespaces.includes(nsName) && !nsWithQuotas.has(nsName)) {
        namespacesWithoutQuotas.push(nsName);
      }
    }

    // Check pods without resource limits/requests
    for (const pod of pods.items) {
      const namespace = pod.metadata?.namespace || '';
      if (systemNamespaces.includes(namespace)) {continue;}

      for (const container of pod.spec?.containers || []) {
        const resources = container.resources;

        if (!resources?.limits?.cpu || !resources?.limits?.memory) {
          podsWithoutLimits++;
        }
        if (!resources?.requests?.cpu || !resources?.requests?.memory) {
          podsWithoutRequests++;
        }
      }
    }

    if (podsWithoutLimits > 0) {
      findings.push({
        namespace: 'cluster-wide',
        resource: 'Pods',
        issue: `${podsWithoutLimits} containers without resource limits`,
        severity: 'medium'
      });
    }

    return {
      namespacesWithQuotas: nsWithQuotas.size,
      namespacesWithoutQuotas,
      namespacesWithLimitRanges: nsWithLimitRanges.size,
      podsWithoutLimits,
      podsWithoutRequests,
      findings
    };
  }

  /**
   * Calculate overall compliance score
   */
  private calculateComplianceScore(data: {
    cisBenchmark: CISBenchmarkResult;
    podSecurity: PodSecurityResult;
    rbacAnalysis: RBACAnalysisResult;
    networkPolicies: NetworkPolicyResult;
    secretsExposure: SecretsExposureResult;
  }): number {
    let score = 100;

    // CIS Benchmark failures (-2 per critical, -1 per high)
    const criticalCIS = data.cisBenchmark.findings.filter(f => f.status === 'FAIL' && f.severity === 'critical');
    const highCIS = data.cisBenchmark.findings.filter(f => f.status === 'FAIL' && f.severity === 'high');
    score -= criticalCIS.length * 5;
    score -= highCIS.length * 2;

    // Pod Security violations
    score -= data.podSecurity.privilegedPods * 10;
    score -= data.podSecurity.violations.filter(v => v.severity === 'critical').length * 5;
    score -= data.podSecurity.violations.filter(v => v.severity === 'high').length * 2;

    // RBAC issues
    score -= data.rbacAnalysis.overprivilegedAccounts.length * 5;
    score -= data.rbacAnalysis.wildcardPermissions.length * 2;

    // Network policy coverage
    if (data.networkPolicies.coverage < 100) {
      score -= Math.floor((100 - data.networkPolicies.coverage) / 10);
    }

    // Secrets exposure
    score -= data.secretsExposure.secretsInDefaultNamespace * 2;
    score -= Math.floor(data.secretsExposure.envVarSecrets / 5);

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Map CIS severity
   */
  private mapCISSeverity(status: string, scored: boolean): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    if (!scored) {return 'info';}
    switch (status.toLowerCase()) {
      case 'fail': return 'high';
      case 'warn': return 'medium';
      default: return 'info';
    }
  }
}

// Export singleton instance
export const kubernetesScanner = new KubernetesScanner();
export default KubernetesScanner;
