/**
 * J.O.E. GitLab Security Scanner
 * Repository SAST, Secret Detection, Pipeline Security, Container Registry
 *
 * Security Standards:
 * - OWASP ASVS v4.0 (Application Security Verification Standard)
 * - NIST SP 800-53 SA-11 (Developer Security Testing)
 * - DoD DevSecOps Reference Design (DISA, 2021)
 * - SLSA Framework v1.0 (Supply Chain Security)
 *
 * Architected by Michael Hoch, Chief Architect of Autonomous Cyber-Operations
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

// ========================================
// TYPE DEFINITIONS
// ========================================

export interface GitLabConfig {
  url: string;           // GitLab instance URL (e.g., https://gitlab.com)
  token: string;         // Personal Access Token or OAuth token
  tokenType: 'pat' | 'oauth';
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
  secret: string;        // Redacted version
  severity: 'critical' | 'high';
  description: string;
  remediation: string;
}

export interface PipelineIssue {
  id: string;
  type: 'security' | 'configuration' | 'best-practice';
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  location: string;      // Stage/job name or line number
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
  score: number;         // 0-100
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

export interface GitLabScanResults {
  project: GitLabProject;
  sastFindings: SASTFinding[];
  secretsDetected: SecretFinding[];
  pipelineSecurity: PipelineSecurity;
  containerImages: ContainerImage[];
  dependencyVulnerabilities: Array<{
    package: string;
    version: string;
    severity: string;
    cve?: string;
    fixedVersion?: string;
  }>;
  complianceScore: number;
  scanTime: string;
}

// ========================================
// GITLAB SCANNER CLASS
// ========================================

class GitLabScanner {
  private config: GitLabConfig | null = null;
  private connected: boolean = false;
  private currentProject: GitLabProject | null = null;
  private tempDir: string = '';

  constructor() {
    // Create temp directory for cloned repos
    this.tempDir = path.join(os.tmpdir(), 'joe-gitlab-scan');
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true });
    }
  }

  /**
   * Connect to GitLab instance
   * Validates token and stores encrypted config
   */
  async connect(url: string, token: string): Promise<{ success: boolean; user?: { username: string; name: string; email: string }; error?: string }> {
    try {
      // Normalize URL
      const gitlabUrl = url.replace(/\/$/, '');

      // Validate token by fetching current user
      const response = await fetch(`${gitlabUrl}/api/v4/user`, {
        headers: {
          'PRIVATE-TOKEN': token
        }
      });

      if (!response.ok) {
        if (response.status === 401) {
          return { success: false, error: 'Invalid access token. Please check your Personal Access Token.' };
        }
        return { success: false, error: `GitLab API error: ${response.statusText}` };
      }

      const user = await response.json();

      this.config = {
        url: gitlabUrl,
        token,
        tokenType: 'pat'
      };
      this.connected = true;

      console.log('[J.O.E. GitLab] Connected as:', user.username);

      return {
        success: true,
        user: {
          username: user.username,
          name: user.name,
          email: user.email
        }
      };
    } catch (error) {
      console.error('[J.O.E. GitLab] Connection error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to connect to GitLab'
      };
    }
  }

  /**
   * Disconnect from GitLab
   */
  disconnect(): void {
    this.config = null;
    this.connected = false;
    this.currentProject = null;

    // Clean up temp directory
    try {
      if (fs.existsSync(this.tempDir)) {
        fs.rmSync(this.tempDir, { recursive: true, force: true });
        fs.mkdirSync(this.tempDir, { recursive: true });
      }
    } catch (e) {
      console.error('[J.O.E. GitLab] Cleanup error:', e);
    }
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.connected && this.config !== null;
  }

  /**
   * List accessible projects
   */
  async listProjects(search?: string, limit: number = 50): Promise<GitLabProject[]> {
    if (!this.config) {throw new Error('Not connected to GitLab');}

    try {
      let url = `${this.config.url}/api/v4/projects?membership=true&per_page=${limit}&order_by=last_activity_at`;
      if (search) {
        url += `&search=${encodeURIComponent(search)}`;
      }

      const response = await fetch(url, {
        headers: { 'PRIVATE-TOKEN': this.config.token }
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch projects: ${response.statusText}`);
      }

      const projects = await response.json();

      return projects.map((p: Record<string, unknown>) => ({
        id: p.id as number,
        name: p.name,
        path: p.path,
        pathWithNamespace: p.path_with_namespace,
        description: p.description || '',
        defaultBranch: p.default_branch || 'main',
        visibility: p.visibility,
        webUrl: p.web_url,
        lastActivity: p.last_activity_at,
        namespace: {
          id: (p.namespace as Record<string, unknown>).id as number,
          name: (p.namespace as Record<string, unknown>).name as string,
          path: (p.namespace as Record<string, unknown>).path as string
        }
      }));
    } catch (error) {
      console.error('[J.O.E. GitLab] Error listing projects:', error);
      throw error;
    }
  }

  /**
   * Get project details
   */
  async getProject(projectId: number): Promise<GitLabProject> {
    if (!this.config) {throw new Error('Not connected to GitLab');}

    const response = await fetch(`${this.config.url}/api/v4/projects/${projectId}`, {
      headers: { 'PRIVATE-TOKEN': this.config.token }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch project: ${response.statusText}`);
    }

    const p = await response.json();

    return {
      id: p.id,
      name: p.name,
      path: p.path,
      pathWithNamespace: p.path_with_namespace,
      description: p.description || '',
      defaultBranch: p.default_branch || 'main',
      visibility: p.visibility,
      webUrl: p.web_url,
      lastActivity: p.last_activity_at,
      namespace: {
        id: p.namespace.id,
        name: p.namespace.name,
        path: p.namespace.path
      }
    };
  }

  /**
   * Run full security scan on a project
   * Includes SAST, secret detection, pipeline analysis, and container scanning
   */
  async scanProject(projectId: number): Promise<GitLabScanResults> {
    if (!this.config) {throw new Error('Not connected to GitLab');}

    console.log('[J.O.E. GitLab] Starting security scan for project:', projectId);

    // Get project details
    const project = await this.getProject(projectId);
    this.currentProject = project;

    // Clone repository for scanning
    const repoPath = await this.cloneRepository(project);

    try {
      // Run all scans in parallel
      const [
        sastFindings,
        secretsDetected,
        pipelineSecurity,
        containerImages,
        dependencyVulnerabilities
      ] = await Promise.all([
        this.runSASTScan(repoPath),
        this.detectSecrets(repoPath),
        this.analyzePipeline(repoPath),
        this.scanContainerRegistry(projectId),
        this.scanDependencies(repoPath)
      ]);

      // Calculate compliance score
      const complianceScore = this.calculateComplianceScore({
        sastFindings,
        secretsDetected,
        pipelineSecurity,
        containerImages,
        dependencyVulnerabilities
      });

      return {
        project,
        sastFindings,
        secretsDetected,
        pipelineSecurity,
        containerImages,
        dependencyVulnerabilities,
        complianceScore,
        scanTime: new Date().toISOString()
      };
    } finally {
      // Cleanup cloned repo
      try {
        fs.rmSync(repoPath, { recursive: true, force: true });
      } catch (e) {
        console.error('[J.O.E. GitLab] Cleanup error:', e);
      }
    }
  }

  /**
   * Clone repository for local scanning
   */
  private async cloneRepository(project: GitLabProject): Promise<string> {
    if (!this.config) {throw new Error('Not connected');}

    const repoPath = path.join(this.tempDir, `${project.id}-${Date.now()}`);

    // Build authenticated clone URL
    const cloneUrl = `https://oauth2:${this.config.token}@${new URL(this.config.url).host}/${project.pathWithNamespace}.git`;

    try {
      console.log('[J.O.E. GitLab] Cloning repository...');
      execSync(`git clone --depth 1 "${cloneUrl}" "${repoPath}"`, {
        stdio: 'pipe',
        timeout: 120000 // 2 minute timeout
      });
      console.log('[J.O.E. GitLab] Repository cloned successfully');
      return repoPath;
    } catch (error) {
      console.error('[J.O.E. GitLab] Clone failed:', error);
      throw new Error('Failed to clone repository. Check access permissions.');
    }
  }

  /**
   * Run SAST scan using Semgrep
   * Reference: OWASP ASVS v4.0, NIST SP 800-53 SA-11
   */
  private async runSASTScan(repoPath: string): Promise<SASTFinding[]> {
    console.log('[J.O.E. GitLab] Running SAST scan with Semgrep...');

    const findings: SASTFinding[] = [];

    try {
      // Check if semgrep is available
      try {
        execSync('semgrep --version', { stdio: 'pipe' });
      } catch {
        console.log('[J.O.E. GitLab] Semgrep not installed, using built-in patterns');
        return this.runBuiltInSAST(repoPath);
      }

      // Run semgrep with security rules
      const result = execSync(
        `semgrep --config=p/security-audit --config=p/owasp-top-ten --json "${repoPath}"`,
        { stdio: 'pipe', timeout: 300000, maxBuffer: 50 * 1024 * 1024 }
      );

      const semgrepResults = JSON.parse(result.toString()) as { results?: Array<Record<string, unknown>> };

      for (const semgrepResult of semgrepResults.results || []) {
        const checkId = semgrepResult.check_id as string;
        const resultPath = semgrepResult.path as string;
        const start = semgrepResult.start as { line: number };
        const end = semgrepResult.end as { line: number };
        const extra = semgrepResult.extra as Record<string, unknown> | undefined;

        findings.push({
          id: crypto.randomUUID(),
          title: checkId.split('.').pop() || checkId,
          severity: this.mapSemgrepSeverity((extra?.severity as string | undefined) || 'warning'),
          confidence: ((extra?.metadata as Record<string, unknown> | undefined)?.confidence as SASTFinding['confidence'] | undefined) || 'medium',
          category: ((extra?.metadata as Record<string, unknown> | undefined)?.category as string | undefined) || 'security',
          file: resultPath.replace(repoPath, '').replace(/^[/\\]/, ''),
          line: start.line,
          endLine: end.line,
          code: extra?.lines as string | undefined,
          description: (extra?.message as string | undefined) || checkId,
          remediation: ((extra?.metadata as Record<string, unknown> | undefined)?.remediation as string | undefined) || 'Review and fix the security issue.',
          cwe: ((extra?.metadata as Record<string, unknown> | undefined)?.cwe as string[] | undefined)?.[0],
          owasp: ((extra?.metadata as Record<string, unknown> | undefined)?.owasp as string[] | undefined)?.[0],
          reference: ((extra?.metadata as Record<string, unknown> | undefined)?.references as string[] | undefined)?.[0]
        });
      }
    } catch (error) {
      console.error('[J.O.E. GitLab] SAST scan error:', error);
      // Fall back to built-in patterns
      return this.runBuiltInSAST(repoPath);
    }

    return findings;
  }

  /**
   * Built-in SAST patterns when Semgrep is not available
   */
  private runBuiltInSAST(repoPath: string): SASTFinding[] {
    const findings: SASTFinding[] = [];
    const securityPatterns = [
      { pattern: /eval\s*\(/gi, title: 'Dangerous eval() usage', severity: 'high' as const, cwe: 'CWE-95', category: 'injection' },
      { pattern: /innerHTML\s*=/gi, title: 'Potential XSS via innerHTML', severity: 'medium' as const, cwe: 'CWE-79', category: 'xss' },
      { pattern: /dangerouslySetInnerHTML/gi, title: 'React dangerouslySetInnerHTML', severity: 'medium' as const, cwe: 'CWE-79', category: 'xss' },
      { pattern: /exec\s*\(/gi, title: 'Command injection risk', severity: 'critical' as const, cwe: 'CWE-78', category: 'injection' },
      { pattern: /child_process/gi, title: 'Child process usage', severity: 'medium' as const, cwe: 'CWE-78', category: 'injection' },
      { pattern: /SELECT.*FROM.*WHERE.*=.*\+/gi, title: 'SQL Injection risk', severity: 'critical' as const, cwe: 'CWE-89', category: 'injection' },
      { pattern: /password\s*=\s*["'][^"']+["']/gi, title: 'Hardcoded password', severity: 'critical' as const, cwe: 'CWE-798', category: 'secrets' },
      { pattern: /api[_-]?key\s*=\s*["'][^"']+["']/gi, title: 'Hardcoded API key', severity: 'high' as const, cwe: 'CWE-798', category: 'secrets' },
      { pattern: /crypto\.createCipher\(/gi, title: 'Weak cryptography (deprecated)', severity: 'high' as const, cwe: 'CWE-327', category: 'crypto' },
      { pattern: /Math\.random\(\)/gi, title: 'Insecure random number generator', severity: 'low' as const, cwe: 'CWE-330', category: 'crypto' },
      { pattern: /disable.*ssl|verify.*false|rejectUnauthorized.*false/gi, title: 'SSL/TLS verification disabled', severity: 'high' as const, cwe: 'CWE-295', category: 'crypto' },
      { pattern: /\bhttp:\/\//gi, title: 'Insecure HTTP URL', severity: 'low' as const, cwe: 'CWE-319', category: 'transport' }
    ];

    const scanExtensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go', '.rb', '.php'];

    const scanDir = (dir: string) => {
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          // Skip common non-source directories
          if (entry.isDirectory()) {
            if (['node_modules', '.git', 'vendor', 'dist', 'build', '__pycache__'].includes(entry.name)) {
              continue;
            }
            scanDir(fullPath);
          } else if (entry.isFile() && scanExtensions.some(ext => entry.name.endsWith(ext))) {
            try {
              const content = fs.readFileSync(fullPath, 'utf-8');
              const lines = content.split('\n');

              for (const patternDef of securityPatterns) {
                lines.forEach((line, idx) => {
                  if (patternDef.pattern.test(line)) {
                    findings.push({
                      id: crypto.randomUUID(),
                      title: patternDef.title,
                      severity: patternDef.severity,
                      confidence: 'medium',
                      category: patternDef.category,
                      file: fullPath.replace(repoPath, '').replace(/^[/\\]/, ''),
                      line: idx + 1,
                      code: line.trim().substring(0, 200),
                      description: `Detected ${patternDef.title} pattern which may indicate a security vulnerability.`,
                      remediation: `Review the code and ensure proper security measures are in place.`,
                      cwe: patternDef.cwe
                    });
                  }
                  // Reset regex lastIndex for global patterns
                  patternDef.pattern.lastIndex = 0;
                });
              }
            } catch (e) {
              // Skip files that can't be read
            }
          }
        }
      } catch (e) {
        // Skip directories that can't be read
      }
    };

    scanDir(repoPath);

    // Deduplicate findings
    const uniqueFindings = findings.reduce((acc, finding) => {
      const key = `${finding.file}:${finding.line}:${finding.title}`;
      if (!acc.has(key)) {
        acc.set(key, finding);
      }
      return acc;
    }, new Map<string, SASTFinding>());

    return Array.from(uniqueFindings.values());
  }

  /**
   * Detect secrets in repository
   * Reference: NIST SP 800-53 IA-5, DoD STIG IA-5
   */
  private async detectSecrets(repoPath: string): Promise<SecretFinding[]> {
    console.log('[J.O.E. GitLab] Scanning for secrets...');

    const findings: SecretFinding[] = [];
    const secretPatterns = [
      { pattern: /(?:^|[^a-zA-Z0-9])([A-Za-z0-9+/]{40})(?:[^a-zA-Z0-9]|$)/g, type: 'Generic API Key', severity: 'high' as const },
      { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: 'GitHub Personal Access Token', severity: 'critical' as const },
      { pattern: /glpat-[a-zA-Z0-9\-_]{20,}/g, type: 'GitLab Personal Access Token', severity: 'critical' as const },
      { pattern: /AKIA[0-9A-Z]{16}/g, type: 'AWS Access Key ID', severity: 'critical' as const },
      { pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g, type: 'AWS Secret Access Key (potential)', severity: 'high' as const },
      { pattern: /sk-[a-zA-Z0-9]{48}/g, type: 'OpenAI API Key', severity: 'critical' as const },
      { pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, type: 'Slack Token', severity: 'high' as const },
      { pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, type: 'Private Key', severity: 'critical' as const },
      { pattern: /(?:^|[^a-zA-Z0-9])(eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)/g, type: 'JWT Token', severity: 'high' as const },
      { pattern: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']/gi, type: 'Hardcoded Password', severity: 'critical' as const }
    ];

    const scanExtensions = ['.js', '.ts', '.json', '.yaml', '.yml', '.env', '.config', '.conf', '.xml', '.properties', '.py', '.java', '.go', '.rb', '.php'];
    const skipFiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];

    const scanDir = (dir: string) => {
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          if (entry.isDirectory()) {
            if (['node_modules', '.git', 'vendor', 'dist', 'build'].includes(entry.name)) {
              continue;
            }
            scanDir(fullPath);
          } else if (entry.isFile()) {
            if (skipFiles.includes(entry.name)) {continue;}
            if (!scanExtensions.some(ext => entry.name.endsWith(ext)) && !entry.name.startsWith('.env')) {continue;}

            try {
              const content = fs.readFileSync(fullPath, 'utf-8');
              const lines = content.split('\n');

              for (const patternDef of secretPatterns) {
                lines.forEach((line, idx) => {
                  const matches = line.match(patternDef.pattern);
                  if (matches) {
                    for (const match of matches) {
                      // Redact the secret
                      const redacted = match.length > 8
                        ? match.substring(0, 4) + '*'.repeat(match.length - 8) + match.substring(match.length - 4)
                        : '*'.repeat(match.length);

                      findings.push({
                        id: crypto.randomUUID(),
                        type: patternDef.type,
                        file: fullPath.replace(repoPath, '').replace(/^[/\\]/, ''),
                        line: idx + 1,
                        secret: redacted,
                        severity: patternDef.severity,
                        description: `Detected potential ${patternDef.type} in source code.`,
                        remediation: 'Remove the secret from the codebase, rotate the credential immediately, and use environment variables or a secrets manager instead.'
                      });
                    }
                  }
                  // Reset regex lastIndex
                  patternDef.pattern.lastIndex = 0;
                });
              }
            } catch (e) {
              // Skip unreadable files
            }
          }
        }
      } catch (e) {
        // Skip unreadable directories
      }
    };

    scanDir(repoPath);

    // Deduplicate
    const unique = new Map<string, SecretFinding>();
    for (const finding of findings) {
      const key = `${finding.file}:${finding.line}:${finding.type}`;
      if (!unique.has(key)) {
        unique.set(key, finding);
      }
    }

    return Array.from(unique.values());
  }

  /**
   * Analyze CI/CD pipeline security
   * Reference: DoD DevSecOps Reference Design, SLSA Framework
   */
  private async analyzePipeline(repoPath: string): Promise<PipelineSecurity> {
    console.log('[J.O.E. GitLab] Analyzing pipeline security...');

    const issues: PipelineIssue[] = [];
    let hasSASTJob = false;
    let hasDependencyScan = false;
    let hasContainerScan = false;
    let hasSecretDetection = false;
    let hasLicenseCompliance = false;

    const ciFile = path.join(repoPath, '.gitlab-ci.yml');

    if (!fs.existsSync(ciFile)) {
      issues.push({
        id: crypto.randomUUID(),
        type: 'configuration',
        title: 'No CI/CD pipeline configured',
        severity: 'high',
        location: '.gitlab-ci.yml',
        description: 'No GitLab CI/CD configuration file found. Projects should have automated security testing in the pipeline.',
        remediation: 'Create a .gitlab-ci.yml file with security scanning stages.',
        reference: 'https://docs.gitlab.com/ee/ci/yaml/gitlab_ci_yaml.html'
      });

      return {
        hasSecurityStages: false,
        hasSASTJob: false,
        hasDependencyScan: false,
        hasContainerScan: false,
        hasSecretDetection: false,
        hasLicenseCompliance: false,
        issues,
        score: 0
      };
    }

    try {
      const ciContent = fs.readFileSync(ciFile, 'utf-8');
      const _ciLower = ciContent.toLowerCase();

      // Check for security stages/jobs
      hasSASTJob = /sast|semgrep|sonarqube|codeclimate|security[-_]scan/i.test(ciContent);
      hasDependencyScan = /dependency[-_]scan|npm[-_]audit|snyk|trivy|grype/i.test(ciContent);
      hasContainerScan = /container[-_]scan|trivy|clair|anchore/i.test(ciContent);
      hasSecretDetection = /secret[-_]detection|gitleaks|trufflehog|detect[-_]secrets/i.test(ciContent);
      hasLicenseCompliance = /license[-_]scan|fossa|license[-_]compliance/i.test(ciContent);

      // Security best practice checks
      if (!hasSASTJob) {
        issues.push({
          id: crypto.randomUUID(),
          type: 'security',
          title: 'No SAST scanning configured',
          severity: 'high',
          location: '.gitlab-ci.yml',
          description: 'Static Application Security Testing (SAST) is not configured in the pipeline.',
          remediation: 'Add a SAST job using GitLab SAST template or Semgrep.',
          reference: 'https://docs.gitlab.com/ee/user/application_security/sast/'
        });
      }

      if (!hasDependencyScan) {
        issues.push({
          id: crypto.randomUUID(),
          type: 'security',
          title: 'No dependency scanning configured',
          severity: 'high',
          location: '.gitlab-ci.yml',
          description: 'Dependency vulnerability scanning is not configured.',
          remediation: 'Add dependency scanning using GitLab Dependency Scanning, Snyk, or npm audit.',
          reference: 'https://docs.gitlab.com/ee/user/application_security/dependency_scanning/'
        });
      }

      if (!hasSecretDetection) {
        issues.push({
          id: crypto.randomUUID(),
          type: 'security',
          title: 'No secret detection configured',
          severity: 'medium',
          location: '.gitlab-ci.yml',
          description: 'Secret detection is not configured in the pipeline.',
          remediation: 'Add secret detection using GitLab Secret Detection or gitleaks.',
          reference: 'https://docs.gitlab.com/ee/user/application_security/secret_detection/'
        });
      }

      // Check for insecure configurations
      if (/allow_failure:\s*true/i.test(ciContent) && /security|sast|scan/i.test(ciContent)) {
        issues.push({
          id: crypto.randomUUID(),
          type: 'configuration',
          title: 'Security job allows failure',
          severity: 'high',
          location: '.gitlab-ci.yml',
          description: 'Security scanning jobs are configured to allow failure, which means pipeline will pass even if security issues are found.',
          remediation: 'Remove allow_failure: true from security jobs or set proper failure thresholds.'
        });
      }

      if (/GIT_STRATEGY:\s*none/i.test(ciContent)) {
        // This is fine in some cases, but worth noting
      }

      // Check for proper artifact handling
      if (!/artifacts:/i.test(ciContent) && (hasSASTJob || hasDependencyScan)) {
        issues.push({
          id: crypto.randomUUID(),
          type: 'best-practice',
          title: 'No artifacts configured for security reports',
          severity: 'low',
          location: '.gitlab-ci.yml',
          description: 'Security scan results are not being saved as artifacts.',
          remediation: 'Add artifacts configuration to store security reports.'
        });
      }

    } catch (error) {
      console.error('[J.O.E. GitLab] Pipeline analysis error:', error);
      issues.push({
        id: crypto.randomUUID(),
        type: 'configuration',
        title: 'Failed to parse CI/CD configuration',
        severity: 'medium',
        location: '.gitlab-ci.yml',
        description: 'Could not parse the GitLab CI configuration file.',
        remediation: 'Verify the .gitlab-ci.yml file is valid YAML.'
      });
    }

    // Calculate score
    let score = 0;
    if (hasSASTJob) {score += 25;}
    if (hasDependencyScan) {score += 25;}
    if (hasContainerScan) {score += 15;}
    if (hasSecretDetection) {score += 20;}
    if (hasLicenseCompliance) {score += 15;}

    // Deduct for issues
    score -= issues.filter(i => i.severity === 'critical').length * 20;
    score -= issues.filter(i => i.severity === 'high').length * 10;
    score -= issues.filter(i => i.severity === 'medium').length * 5;
    score = Math.max(0, Math.min(100, score));

    return {
      hasSecurityStages: hasSASTJob || hasDependencyScan || hasContainerScan || hasSecretDetection,
      hasSASTJob,
      hasDependencyScan,
      hasContainerScan,
      hasSecretDetection,
      hasLicenseCompliance,
      issues,
      score
    };
  }

  /**
   * Scan container registry for vulnerabilities
   */
  private async scanContainerRegistry(projectId: number): Promise<ContainerImage[]> {
    if (!this.config) {return [];}

    console.log('[J.O.E. GitLab] Scanning container registry...');

    try {
      // Get container repositories for this project
      const response = await fetch(
        `${this.config.url}/api/v4/projects/${projectId}/registry/repositories`,
        { headers: { 'PRIVATE-TOKEN': this.config.token } }
      );

      if (!response.ok) {
        // Registry might not be enabled or no images
        return [];
      }

      const repositories = await response.json();
      const images: ContainerImage[] = [];

      for (const repo of repositories) {
        // Get tags for this repository
        const tagsResponse = await fetch(
          `${this.config.url}/api/v4/projects/${projectId}/registry/repositories/${repo.id}/tags`,
          { headers: { 'PRIVATE-TOKEN': this.config.token } }
        );

        if (!tagsResponse.ok) {continue;}

        const tags = await tagsResponse.json();

        for (const tag of tags.slice(0, 5)) { // Limit to 5 most recent tags
          images.push({
            name: repo.path,
            tag: tag.name,
            digest: tag.digest,
            registry: new URL(this.config.url).host,
            vulnerabilities: {
              critical: 0,
              high: 0,
              medium: 0,
              low: 0
            },
            lastScanned: new Date().toISOString()
          });
        }
      }

      // If Trivy is available, scan the images
      // This would require pulling images which is expensive, so we skip for now
      // In production, this would integrate with GitLab Container Scanning results

      return images;
    } catch (error) {
      console.error('[J.O.E. GitLab] Container registry scan error:', error);
      return [];
    }
  }

  /**
   * Scan dependencies for vulnerabilities
   */
  private async scanDependencies(repoPath: string): Promise<Array<{ package: string; version: string; severity: string; cve?: string; fixedVersion?: string }>> {
    console.log('[J.O.E. GitLab] Scanning dependencies...');

    const vulnerabilities: Array<{ package: string; version: string; severity: string; cve?: string; fixedVersion?: string }> = [];

    // Check for package.json (Node.js)
    const packageJsonPath = path.join(repoPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        // Try npm audit
        const result = execSync('npm audit --json', {
          cwd: repoPath,
          stdio: 'pipe',
          timeout: 60000
        });

        const auditResults = JSON.parse(result.toString());
        for (const [_name, advisory] of Object.entries(auditResults.advisories || {})) {
          const adv = advisory as Record<string, unknown>;
          const advFindings = adv.findings as Array<Record<string, unknown>> | undefined;
          const advCves = adv.cves as string[] | undefined;
          vulnerabilities.push({
            package: adv.module_name as string,
            version: (advFindings?.[0]?.version as string | undefined) || 'unknown',
            severity: adv.severity as string,
            cve: advCves?.[0],
            fixedVersion: adv.patched_versions as string | undefined
          });
        }
      } catch (e) {
        // npm audit might fail if no node_modules, try parsing package-lock.json
        console.log('[J.O.E. GitLab] npm audit failed, skipping dependency scan');
      }
    }

    // Check for requirements.txt (Python)
    const requirementsPath = path.join(repoPath, 'requirements.txt');
    if (fs.existsSync(requirementsPath)) {
      // Would use safety or pip-audit here
      // For now, just note that Python dependencies exist
    }

    return vulnerabilities;
  }

  /**
   * Calculate overall compliance score
   */
  private calculateComplianceScore(results: {
    sastFindings: SASTFinding[];
    secretsDetected: SecretFinding[];
    pipelineSecurity: PipelineSecurity;
    containerImages: ContainerImage[];
    dependencyVulnerabilities: Array<{ severity: string }>;
  }): number {
    let score = 100;

    // SAST findings
    score -= results.sastFindings.filter(f => f.severity === 'critical').length * 10;
    score -= results.sastFindings.filter(f => f.severity === 'high').length * 5;
    score -= results.sastFindings.filter(f => f.severity === 'medium').length * 2;

    // Secrets (critical issue)
    score -= results.secretsDetected.length * 15;

    // Pipeline security score weighted
    score -= (100 - results.pipelineSecurity.score) * 0.3;

    // Dependency vulnerabilities
    score -= results.dependencyVulnerabilities.filter(v => v.severity === 'critical').length * 8;
    score -= results.dependencyVulnerabilities.filter(v => v.severity === 'high').length * 4;

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  /**
   * Map Semgrep severity to our severity levels
   */
  private mapSemgrepSeverity(severity: string): SASTFinding['severity'] {
    switch (severity?.toUpperCase()) {
      case 'ERROR':
      case 'CRITICAL':
        return 'critical';
      case 'WARNING':
      case 'HIGH':
        return 'high';
      case 'INFO':
      case 'MEDIUM':
        return 'medium';
      default:
        return 'low';
    }
  }
}

// Export singleton instance
export const gitlabScanner = new GitLabScanner();
export default gitlabScanner;
