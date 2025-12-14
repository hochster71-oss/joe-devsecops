/**
 * J.O.E. DevSecOps Arsenal - Virtual Spaces Service
 * DoD-hardened Kubernetes namespaces for secure code analysis
 *
 * Features:
 * - Kind cluster management (Docker-based K8s)
 * - Namespace isolation with DoD STIG hardening
 * - Three-tier security: Team, Elevated (Joseph Scholer), Admin (Michael Hoch)
 * - Code ingress/egress gates with security scanning
 * - Ephemeral workspaces with auto-destroy
 * - Air-gapped/disconnected mode support
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const execAsync = promisify(exec);

// ========================================
// TYPE DEFINITIONS
// ========================================

export type SpaceTierType = 'team' | 'elevated' | 'admin';
export type SpaceStatus = 'creating' | 'ready' | 'scanning' | 'importing' | 'exporting' | 'destroying' | 'destroyed' | 'error';
export type ClusterStatus = 'offline' | 'starting' | 'ready' | 'error' | 'not-installed';
export type PSSLevel = 'restricted' | 'baseline' | 'privileged';
export type NetworkPolicyType = 'deny-all' | 'limited-egress' | 'allow-all';

export interface SpaceTier {
  name: string;
  description: string;
  pssLevel: PSSLevel;
  networkPolicy: NetworkPolicyType;
  resourceQuota: {
    cpu: string;
    memory: string;
    pods: number;
  };
  allowPrivileged: boolean;
  allowHostPath: boolean;
  allowedOwners?: string[]; // If specified, only these users can create this tier
}

export interface CodeSource {
  type: 'git' | 'upload' | 'local';
  url?: string;
  branch?: string;
  path?: string;
}

export interface ScanResult {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  tool: string;
  description?: string;
  remediation?: string;
  file?: string;
  line?: number;
}

export interface SpaceScanResults {
  scanTime: string;
  findings: ScanResult[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  passed: boolean;
}

export interface VirtualSpace {
  id: string;
  name: string;
  owner: string;
  tier: SpaceTierType;
  status: SpaceStatus;
  namespace: string;
  createdAt: string;
  expiresAt: string;
  ttlMinutes: number;
  codeSource?: CodeSource;
  scanResults?: SpaceScanResults;
  error?: string;
}

export interface CreateSpaceConfig {
  name: string;
  owner: string;
  tier: SpaceTierType;
  ttlMinutes?: number; // Default 60 minutes
}

export interface ImportResult {
  success: boolean;
  filesImported: number;
  path: string;
  error?: string;
}

export interface ExportResult {
  success: boolean;
  exportPath: string;
  artifacts: string[];
  error?: string;
}

export interface ClusterInfo {
  status: ClusterStatus;
  name: string;
  nodes: number;
  version?: string;
  error?: string;
}

// ========================================
// SPACE TIER CONFIGURATIONS
// ========================================

const SPACE_TIERS: Record<SpaceTierType, SpaceTier> = {
  team: {
    name: 'Team Space',
    description: 'Standard isolated workspace with restricted security',
    pssLevel: 'restricted',
    networkPolicy: 'deny-all',
    resourceQuota: { cpu: '2', memory: '4Gi', pods: 10 },
    allowPrivileged: false,
    allowHostPath: false
  },
  elevated: {
    name: 'Elevated Space (Joseph Scholer)',
    description: 'Enhanced workspace with baseline security and limited egress',
    pssLevel: 'baseline',
    networkPolicy: 'limited-egress',
    resourceQuota: { cpu: '4', memory: '8Gi', pods: 20 },
    allowPrivileged: false,
    allowHostPath: true,
    allowedOwners: ['joseph.scholer', 'jscholer', 'joseph']
  },
  admin: {
    name: 'Admin Space (Michael Hoch)',
    description: 'Full administrative access with privileged security',
    pssLevel: 'privileged',
    networkPolicy: 'allow-all',
    resourceQuota: { cpu: '8', memory: '16Gi', pods: 50 },
    allowPrivileged: true,
    allowHostPath: true,
    allowedOwners: ['michael.hoch', 'mhoch', 'michael', 'admin']
  }
};

const CLUSTER_NAME = 'joe-virtual-spaces';
const KIND_CONFIG_PATH = path.join(os.tmpdir(), 'joe-kind-config.yaml');

// ========================================
// KIND CLUSTER CONFIGURATION
// ========================================

const KIND_CLUSTER_CONFIG = `
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 8080
    protocol: TCP
  - containerPort: 443
    hostPort: 8443
    protocol: TCP
featureGates:
  PodSecurity: true
`;

// ========================================
// VIRTUAL SPACES SERVICE
// ========================================

class VirtualSpacesService {
  private spaces: Map<string, VirtualSpace> = new Map();
  private cleanupTimers: Map<string, NodeJS.Timeout> = new Map();

  constructor() {
    console.log('[J.O.E. Virtual Spaces] Service initialized');
  }

  // ========================================
  // CLUSTER MANAGEMENT
  // ========================================

  /**
   * Check if kind is installed
   */
  async isKindInstalled(): Promise<boolean> {
    try {
      await execAsync('kind version');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if kubectl is installed
   */
  async isKubectlInstalled(): Promise<boolean> {
    try {
      await execAsync('kubectl version --client');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get cluster status
   */
  async getClusterStatus(): Promise<ClusterInfo> {
    try {
      // Check if kind is installed
      if (!await this.isKindInstalled()) {
        return {
          status: 'not-installed',
          name: CLUSTER_NAME,
          nodes: 0,
          error: 'kind is not installed. Install from https://kind.sigs.k8s.io/'
        };
      }

      // Check if cluster exists
      const { stdout } = await execAsync('kind get clusters');
      const clusters = stdout.trim().split('\n').filter(c => c);

      if (!clusters.includes(CLUSTER_NAME)) {
        return {
          status: 'offline',
          name: CLUSTER_NAME,
          nodes: 0
        };
      }

      // Get cluster info
      try {
        const { stdout: nodesOutput } = await execAsync(
          `kubectl get nodes --context kind-${CLUSTER_NAME} -o json`
        );
        const nodes = JSON.parse(nodesOutput);
        const nodeCount = nodes.items?.length || 0;

        // Get version
        const { stdout: versionOutput } = await execAsync(
          `kubectl version --context kind-${CLUSTER_NAME} -o json`
        );
        const version = JSON.parse(versionOutput);

        return {
          status: 'ready',
          name: CLUSTER_NAME,
          nodes: nodeCount,
          version: version.serverVersion?.gitVersion || 'unknown'
        };
      } catch {
        return {
          status: 'error',
          name: CLUSTER_NAME,
          nodes: 0,
          error: 'Cluster exists but is not responding'
        };
      }
    } catch (error) {
      return {
        status: 'error',
        name: CLUSTER_NAME,
        nodes: 0,
        error: String(error)
      };
    }
  }

  /**
   * Ensure the kind cluster exists, create if not
   */
  async ensureClusterExists(): Promise<ClusterInfo> {
    console.log('[J.O.E. Virtual Spaces] Ensuring cluster exists...');

    const status = await this.getClusterStatus();

    if (status.status === 'not-installed') {
      throw new Error('kind is not installed. Please install kind first.');
    }

    if (status.status === 'ready') {
      console.log('[J.O.E. Virtual Spaces] Cluster already running');
      return status;
    }

    // Create cluster
    console.log('[J.O.E. Virtual Spaces] Creating kind cluster...');

    // Write config file
    fs.writeFileSync(KIND_CONFIG_PATH, KIND_CLUSTER_CONFIG);

    try {
      await execAsync(`kind create cluster --config ${KIND_CONFIG_PATH}`, {
        timeout: 300000 // 5 minute timeout
      });

      console.log('[J.O.E. Virtual Spaces] Cluster created successfully');

      // Wait for cluster to be ready
      await this.waitForClusterReady();

      return await this.getClusterStatus();
    } catch (error) {
      console.error('[J.O.E. Virtual Spaces] Failed to create cluster:', error);
      throw error;
    }
  }

  /**
   * Wait for cluster to be ready
   */
  private async waitForClusterReady(maxRetries = 30): Promise<void> {
    for (let i = 0; i < maxRetries; i++) {
      try {
        await execAsync(`kubectl get nodes --context kind-${CLUSTER_NAME}`);
        console.log('[J.O.E. Virtual Spaces] Cluster is ready');
        return;
      } catch {
        console.log(`[J.O.E. Virtual Spaces] Waiting for cluster... (${i + 1}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
    throw new Error('Cluster did not become ready in time');
  }

  /**
   * Destroy the kind cluster
   */
  async destroyCluster(): Promise<void> {
    console.log('[J.O.E. Virtual Spaces] Destroying cluster...');

    // Clear all spaces
    for (const [id] of this.spaces) {
      this.clearCleanupTimer(id);
    }
    this.spaces.clear();

    try {
      await execAsync(`kind delete cluster --name ${CLUSTER_NAME}`);
      console.log('[J.O.E. Virtual Spaces] Cluster destroyed');
    } catch (error) {
      console.error('[J.O.E. Virtual Spaces] Failed to destroy cluster:', error);
      throw error;
    }
  }

  // ========================================
  // SPACE LIFECYCLE
  // ========================================

  /**
   * Create a new virtual space
   */
  async createSpace(config: CreateSpaceConfig): Promise<VirtualSpace> {
    console.log('[J.O.E. Virtual Spaces] Creating space:', config);

    // Validate tier access
    const tier = SPACE_TIERS[config.tier];
    if (tier.allowedOwners && !tier.allowedOwners.includes(config.owner.toLowerCase())) {
      throw new Error(`User ${config.owner} is not authorized to create ${tier.name}`);
    }

    // Ensure cluster exists
    const clusterStatus = await this.getClusterStatus();
    if (clusterStatus.status !== 'ready') {
      await this.ensureClusterExists();
    }

    const id = `vs-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const namespace = `joe-space-${id}`;
    const ttlMinutes = config.ttlMinutes || 60;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlMinutes * 60 * 1000);

    const space: VirtualSpace = {
      id,
      name: config.name,
      owner: config.owner,
      tier: config.tier,
      status: 'creating',
      namespace,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      ttlMinutes
    };

    this.spaces.set(id, space);

    try {
      // Create namespace with labels
      await this.createNamespace(namespace, config.tier);

      // Apply DoD hardening
      await this.applyHardening(namespace, config.tier);

      // Update status
      space.status = 'ready';
      this.spaces.set(id, space);

      // Set cleanup timer
      this.setCleanupTimer(id, ttlMinutes);

      console.log('[J.O.E. Virtual Spaces] Space created:', id);
      return space;
    } catch (error) {
      space.status = 'error';
      space.error = String(error);
      this.spaces.set(id, space);
      throw error;
    }
  }

  /**
   * Create namespace with Pod Security Standard labels
   */
  private async createNamespace(namespace: string, tierType: SpaceTierType): Promise<void> {
    const tier = SPACE_TIERS[tierType];

    const namespaceYaml = `
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
  labels:
    app.kubernetes.io/managed-by: joe-devsecops
    joe.darkwolf.io/tier: ${tierType}
    pod-security.kubernetes.io/enforce: ${tier.pssLevel}
    pod-security.kubernetes.io/audit: ${tier.pssLevel}
    pod-security.kubernetes.io/warn: ${tier.pssLevel}
`;

    const tempFile = path.join(os.tmpdir(), `ns-${namespace}.yaml`);
    fs.writeFileSync(tempFile, namespaceYaml);

    try {
      await execAsync(`kubectl apply -f ${tempFile} --context kind-${CLUSTER_NAME}`);
    } finally {
      fs.unlinkSync(tempFile);
    }
  }

  /**
   * Apply DoD hardening policies to namespace
   */
  private async applyHardening(namespace: string, tierType: SpaceTierType): Promise<void> {
    const tier = SPACE_TIERS[tierType];

    // Apply Network Policy
    await this.applyNetworkPolicy(namespace, tier.networkPolicy);

    // Apply Resource Quota
    await this.applyResourceQuota(namespace, tier.resourceQuota);

    // Apply Limit Range
    await this.applyLimitRange(namespace);

    console.log(`[J.O.E. Virtual Spaces] Hardening applied to ${namespace}`);
  }

  /**
   * Apply network policy based on tier
   */
  private async applyNetworkPolicy(namespace: string, policyType: NetworkPolicyType): Promise<void> {
    let policyYaml: string;

    switch (policyType) {
      case 'deny-all':
        policyYaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: ${namespace}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
`;
        break;

      case 'limited-egress':
        policyYaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: limited-egress
  namespace: ${namespace}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress: []
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
  - to:
    - ipBlock:
        cidr: 10.0.0.0/8
`;
        break;

      case 'allow-all':
        policyYaml = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
  namespace: ${namespace}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - {}
  egress:
  - {}
`;
        break;
    }

    const tempFile = path.join(os.tmpdir(), `netpol-${namespace}.yaml`);
    fs.writeFileSync(tempFile, policyYaml);

    try {
      await execAsync(`kubectl apply -f ${tempFile} --context kind-${CLUSTER_NAME}`);
    } finally {
      fs.unlinkSync(tempFile);
    }
  }

  /**
   * Apply resource quota
   */
  private async applyResourceQuota(
    namespace: string,
    quota: { cpu: string; memory: string; pods: number }
  ): Promise<void> {
    const quotaYaml = `
apiVersion: v1
kind: ResourceQuota
metadata:
  name: space-quota
  namespace: ${namespace}
spec:
  hard:
    requests.cpu: "${quota.cpu}"
    requests.memory: ${quota.memory}
    limits.cpu: "${parseInt(quota.cpu) * 2}"
    limits.memory: ${parseInt(quota.memory) * 2}Gi
    pods: "${quota.pods}"
    persistentvolumeclaims: "5"
    services: "10"
    secrets: "20"
    configmaps: "20"
`;

    const tempFile = path.join(os.tmpdir(), `quota-${namespace}.yaml`);
    fs.writeFileSync(tempFile, quotaYaml);

    try {
      await execAsync(`kubectl apply -f ${tempFile} --context kind-${CLUSTER_NAME}`);
    } finally {
      fs.unlinkSync(tempFile);
    }
  }

  /**
   * Apply limit range for default container limits
   */
  private async applyLimitRange(namespace: string): Promise<void> {
    const limitRangeYaml = `
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: ${namespace}
spec:
  limits:
  - default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    type: Container
`;

    const tempFile = path.join(os.tmpdir(), `limits-${namespace}.yaml`);
    fs.writeFileSync(tempFile, limitRangeYaml);

    try {
      await execAsync(`kubectl apply -f ${tempFile} --context kind-${CLUSTER_NAME}`);
    } finally {
      fs.unlinkSync(tempFile);
    }
  }

  /**
   * Destroy a virtual space
   */
  async destroySpace(spaceId: string): Promise<void> {
    console.log('[J.O.E. Virtual Spaces] Destroying space:', spaceId);

    const space = this.spaces.get(spaceId);
    if (!space) {
      throw new Error(`Space ${spaceId} not found`);
    }

    this.clearCleanupTimer(spaceId);

    space.status = 'destroying';
    this.spaces.set(spaceId, space);

    try {
      await execAsync(
        `kubectl delete namespace ${space.namespace} --context kind-${CLUSTER_NAME} --ignore-not-found`
      );

      space.status = 'destroyed';
      this.spaces.set(spaceId, space);

      // Remove from map after a delay
      setTimeout(() => this.spaces.delete(spaceId), 60000);

      console.log('[J.O.E. Virtual Spaces] Space destroyed:', spaceId);
    } catch (error) {
      space.status = 'error';
      space.error = String(error);
      this.spaces.set(spaceId, space);
      throw error;
    }
  }

  /**
   * List all spaces
   */
  async listSpaces(): Promise<VirtualSpace[]> {
    return Array.from(this.spaces.values());
  }

  /**
   * Get a specific space
   */
  getSpace(spaceId: string): VirtualSpace | undefined {
    return this.spaces.get(spaceId);
  }

  // ========================================
  // CODE OPERATIONS
  // ========================================

  /**
   * Import code into a space
   */
  async importCode(spaceId: string, source: CodeSource): Promise<ImportResult> {
    console.log('[J.O.E. Virtual Spaces] Importing code to space:', spaceId);

    const space = this.spaces.get(spaceId);
    if (!space) {
      throw new Error(`Space ${spaceId} not found`);
    }

    if (space.status !== 'ready') {
      throw new Error(`Space is not ready (status: ${space.status})`);
    }

    space.status = 'importing';
    space.codeSource = source;
    this.spaces.set(spaceId, space);

    try {
      let filesImported = 0;
      let importPath = '';

      if (source.type === 'git' && source.url) {
        // Clone git repository into a temporary directory
        const tempDir = path.join(os.tmpdir(), `joe-import-${spaceId}`);
        fs.mkdirSync(tempDir, { recursive: true });

        const branch = source.branch || 'main';
        await execAsync(`git clone --depth 1 --branch ${branch} ${source.url} ${tempDir}`, {
          timeout: 120000
        });

        // Count files
        const files = this.countFiles(tempDir);
        filesImported = files;
        importPath = tempDir;

      } else if (source.type === 'local' && source.path) {
        // Use local path directly
        if (!fs.existsSync(source.path)) {
          throw new Error(`Path does not exist: ${source.path}`);
        }
        filesImported = this.countFiles(source.path);
        importPath = source.path;

      } else if (source.type === 'upload' && source.path) {
        // Handle uploaded file/directory
        filesImported = this.countFiles(source.path);
        importPath = source.path;
      }

      space.status = 'ready';
      this.spaces.set(spaceId, space);

      return {
        success: true,
        filesImported,
        path: importPath
      };
    } catch (error) {
      space.status = 'error';
      space.error = String(error);
      this.spaces.set(spaceId, space);

      return {
        success: false,
        filesImported: 0,
        path: '',
        error: String(error)
      };
    }
  }

  /**
   * Count files in a directory
   */
  private countFiles(dir: string): number {
    let count = 0;
    const items = fs.readdirSync(dir);

    for (const item of items) {
      const fullPath = path.join(dir, item);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
        count += this.countFiles(fullPath);
      } else if (stat.isFile()) {
        count++;
      }
    }

    return count;
  }

  /**
   * Scan code in a space
   */
  async scanSpace(spaceId: string): Promise<SpaceScanResults> {
    console.log('[J.O.E. Virtual Spaces] Scanning space:', spaceId);

    const space = this.spaces.get(spaceId);
    if (!space) {
      throw new Error(`Space ${spaceId} not found`);
    }

    space.status = 'scanning';
    this.spaces.set(spaceId, space);

    const findings: ScanResult[] = [];

    try {
      // If code was imported, scan it
      if (space.codeSource?.path || space.codeSource?.type === 'git') {
        const scanPath = space.codeSource.path || path.join(os.tmpdir(), `joe-import-${spaceId}`);

        if (fs.existsSync(scanPath)) {
          // Run security scans (simplified - would integrate with existing scanners)
          const secretFindings = await this.scanForSecrets(scanPath);
          findings.push(...secretFindings);
        }
      }

      // Calculate summary
      const summary = {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length,
        total: findings.length
      };

      const results: SpaceScanResults = {
        scanTime: new Date().toISOString(),
        findings,
        summary,
        passed: summary.critical === 0 && summary.high === 0
      };

      space.scanResults = results;
      space.status = 'ready';
      this.spaces.set(spaceId, space);

      return results;
    } catch (error) {
      space.status = 'error';
      space.error = String(error);
      this.spaces.set(spaceId, space);
      throw error;
    }
  }

  /**
   * Scan for secrets (basic implementation)
   */
  private async scanForSecrets(scanPath: string): Promise<ScanResult[]> {
    const findings: ScanResult[] = [];
    const secretPatterns = [
      { pattern: /api[_-]?key\s*[:=]\s*['"][^'"]{20,}['"]/gi, name: 'API Key' },
      { pattern: /password\s*[:=]\s*['"][^'"]{8,}['"]/gi, name: 'Password' },
      { pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g, name: 'Private Key' },
      { pattern: /ghp_[a-zA-Z0-9]{36}/g, name: 'GitHub Token' }
    ];

    const scanFiles = (dir: string) => {
      const items = fs.readdirSync(dir);

      for (const item of items) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
          scanFiles(fullPath);
        } else if (stat.isFile() && /\.(ts|tsx|js|jsx|py|json|yaml|yml|env)$/.test(item)) {
          try {
            const content = fs.readFileSync(fullPath, 'utf-8');

            for (const { pattern, name } of secretPatterns) {
              if (pattern.test(content)) {
                findings.push({
                  id: `secret-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                  title: `Potential ${name} detected`,
                  severity: 'high',
                  tool: 'J.O.E. Secret Scanner',
                  description: `Found potential hardcoded ${name.toLowerCase()} in file`,
                  remediation: 'Move secrets to environment variables or a secrets manager',
                  file: path.relative(scanPath, fullPath)
                });
              }
            }
          } catch {
            // Skip files that can't be read
          }
        }
      }
    };

    if (fs.existsSync(scanPath)) {
      scanFiles(scanPath);
    }

    return findings;
  }

  /**
   * Export artifacts from a space
   */
  async exportArtifacts(spaceId: string, artifacts: string[]): Promise<ExportResult> {
    console.log('[J.O.E. Virtual Spaces] Exporting artifacts from space:', spaceId);

    const space = this.spaces.get(spaceId);
    if (!space) {
      throw new Error(`Space ${spaceId} not found`);
    }

    // Check if scan passed
    if (!space.scanResults?.passed) {
      return {
        success: false,
        exportPath: '',
        artifacts: [],
        error: 'Cannot export: Security scan did not pass'
      };
    }

    space.status = 'exporting';
    this.spaces.set(spaceId, space);

    try {
      const exportDir = path.join(os.tmpdir(), `joe-export-${spaceId}`);
      fs.mkdirSync(exportDir, { recursive: true });

      // Copy artifacts to export directory
      const exportedArtifacts: string[] = [];
      for (const artifact of artifacts) {
        const srcPath = path.join(space.codeSource?.path || '', artifact);
        if (fs.existsSync(srcPath)) {
          const destPath = path.join(exportDir, artifact);
          fs.mkdirSync(path.dirname(destPath), { recursive: true });
          fs.copyFileSync(srcPath, destPath);
          exportedArtifacts.push(artifact);
        }
      }

      space.status = 'ready';
      this.spaces.set(spaceId, space);

      return {
        success: true,
        exportPath: exportDir,
        artifacts: exportedArtifacts
      };
    } catch (error) {
      space.status = 'error';
      space.error = String(error);
      this.spaces.set(spaceId, space);

      return {
        success: false,
        exportPath: '',
        artifacts: [],
        error: String(error)
      };
    }
  }

  // ========================================
  // CLEANUP & HELPERS
  // ========================================

  /**
   * Set cleanup timer for ephemeral space
   */
  private setCleanupTimer(spaceId: string, ttlMinutes: number): void {
    const timer = setTimeout(async () => {
      console.log(`[J.O.E. Virtual Spaces] Auto-destroying expired space: ${spaceId}`);
      try {
        await this.destroySpace(spaceId);
      } catch (error) {
        console.error(`[J.O.E. Virtual Spaces] Failed to auto-destroy space ${spaceId}:`, error);
      }
    }, ttlMinutes * 60 * 1000);

    this.cleanupTimers.set(spaceId, timer);
  }

  /**
   * Clear cleanup timer
   */
  private clearCleanupTimer(spaceId: string): void {
    const timer = this.cleanupTimers.get(spaceId);
    if (timer) {
      clearTimeout(timer);
      this.cleanupTimers.delete(spaceId);
    }
  }

  /**
   * Extend space TTL
   */
  async extendSpace(spaceId: string, additionalMinutes: number): Promise<VirtualSpace> {
    const space = this.spaces.get(spaceId);
    if (!space) {
      throw new Error(`Space ${spaceId} not found`);
    }

    this.clearCleanupTimer(spaceId);

    const newExpiry = new Date(Date.now() + additionalMinutes * 60 * 1000);
    space.expiresAt = newExpiry.toISOString();
    space.ttlMinutes = additionalMinutes;

    this.setCleanupTimer(spaceId, additionalMinutes);
    this.spaces.set(spaceId, space);

    return space;
  }

  /**
   * Get available tiers
   */
  getTiers(): Record<SpaceTierType, SpaceTier> {
    return SPACE_TIERS;
  }

  /**
   * Check if user can create a specific tier
   */
  canCreateTier(username: string, tierType: SpaceTierType): boolean {
    const tier = SPACE_TIERS[tierType];
    if (!tier.allowedOwners) {
      return true;
    }
    return tier.allowedOwners.includes(username.toLowerCase());
  }
}

// Export singleton instance
export const virtualSpacesService = new VirtualSpacesService();
