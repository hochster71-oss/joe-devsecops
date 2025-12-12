import { contextBridge, ipcRenderer } from 'electron';

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // App info
  getAppInfo: () => ipcRenderer.invoke('get-app-info'),

  // Window controls
  minimizeWindow: () => ipcRenderer.invoke('minimize-window'),
  maximizeWindow: () => ipcRenderer.invoke('maximize-window'),
  closeWindow: () => ipcRenderer.invoke('close-window'),

  // Tray status
  updateTrayStatus: (status: { level: string; count: number }) =>
    ipcRenderer.invoke('update-tray-status', status),

  // Event listeners
  onRunScan: (callback: () => void) => {
    ipcRenderer.on('run-scan', callback);
    return () => ipcRenderer.removeListener('run-scan', callback);
  },

  // Database operations (will be implemented)
  database: {
    query: (sql: string, params?: unknown[]) =>
      ipcRenderer.invoke('db-query', sql, params),
    run: (sql: string, params?: unknown[]) =>
      ipcRenderer.invoke('db-run', sql, params),
    get: (sql: string, params?: unknown[]) =>
      ipcRenderer.invoke('db-get', sql, params),
    all: (sql: string, params?: unknown[]) =>
      ipcRenderer.invoke('db-all', sql, params)
  },

  // Auth operations (DoD STIG / NIST 800-53 compliant)
  auth: {
    login: (username: string, password: string) =>
      ipcRenderer.invoke('auth-login', username, password),
    logout: () => ipcRenderer.invoke('auth-logout'),
    getCurrentUser: () => ipcRenderer.invoke('auth-get-current-user'),
    changePassword: (oldPassword: string, newPassword: string) =>
      ipcRenderer.invoke('auth-change-password', oldPassword, newPassword),
    // 2FA operations (TOTP/Google Authenticator)
    verify2FA: (code: string) =>
      ipcRenderer.invoke('auth-verify-2fa', code),
    setup2FA: () =>
      ipcRenderer.invoke('auth-setup-2fa'),
    confirm2FASetup: (code: string) =>
      ipcRenderer.invoke('auth-confirm-2fa-setup', code),
    disable2FA: () =>
      ipcRenderer.invoke('auth-disable-2fa'),
    get2FAStatus: () =>
      ipcRenderer.invoke('auth-get-2fa-status'),
    // Security audit and session management
    getAuditLog: () =>
      ipcRenderer.invoke('auth-get-audit-log'),
    getSessionStatus: () =>
      ipcRenderer.invoke('auth-get-session-status')
  },

  // Scanner operations
  scanner: {
    runSemgrep: (path: string) => ipcRenderer.invoke('scanner-semgrep', path),
    runTrivy: (path: string) => ipcRenderer.invoke('scanner-trivy', path),
    runSnyk: (path: string) => ipcRenderer.invoke('scanner-snyk', path),
    runAllScans: (path: string) => ipcRenderer.invoke('scanner-run-all', path)
  },

  // SBOM operations
  sbom: {
    generate: (path: string, format: string) =>
      ipcRenderer.invoke('sbom-generate', path, format),
    parse: (sbomPath: string) => ipcRenderer.invoke('sbom-parse', sbomPath)
  },

  // Compliance operations
  compliance: {
    getControls: () => ipcRenderer.invoke('compliance-get-controls'),
    evaluateControl: (controlId: string) =>
      ipcRenderer.invoke('compliance-evaluate', controlId),
    generateReport: () => ipcRenderer.invoke('compliance-report')
  },

  // Ollama AI operations
  ollama: {
    chat: (message: string, context?: string) =>
      ipcRenderer.invoke('ollama-chat', message, context),
    streamChat: (message: string, context?: string) => {
      ipcRenderer.send('ollama-stream-start', message, context);
      return {
        onChunk: (callback: (chunk: string) => void) => {
          ipcRenderer.on('ollama-stream-chunk', (_, chunk) => callback(chunk));
        },
        onEnd: (callback: () => void) => {
          ipcRenderer.on('ollama-stream-end', callback);
        },
        cancel: () => ipcRenderer.send('ollama-stream-cancel')
      };
    },
    getModels: () => ipcRenderer.invoke('ollama-get-models'),
    setModel: (model: string) => ipcRenderer.invoke('ollama-set-model', model)
  },

  // File system operations
  fs: {
    selectDirectory: () => ipcRenderer.invoke('fs-select-directory'),
    selectFile: (filters?: { name: string; extensions: string[] }[]) =>
      ipcRenderer.invoke('fs-select-file', filters),
    readFile: (filePath: string) => ipcRenderer.invoke('fs-read-file', filePath),
    writeFile: (filePath: string, content: string) =>
      ipcRenderer.invoke('fs-write-file', filePath, content)
  },

  // Security scanning operations - REAL scans, not simulated
  security: {
    runAudit: () => ipcRenderer.invoke('security-run-audit'),
    autoFix: () => ipcRenderer.invoke('security-auto-fix'),
    // Advanced scanning features
    semgrepScan: () => ipcRenderer.invoke('security-semgrep-scan'),
    dockerScan: (imageName: string) => ipcRenderer.invoke('security-docker-scan', imageName),
    cveLookup: (cveId: string) => ipcRenderer.invoke('security-cve-lookup', cveId),
    gitHistoryScan: () => ipcRenderer.invoke('security-git-history-scan'),
    eslintScan: () => ipcRenderer.invoke('security-eslint-scan'),
    generateSarif: (findings: unknown[]) => ipcRenderer.invoke('security-generate-sarif', findings)
  },

  // Export operations - Save files to user-selected location
  export: {
    saveFile: (options: {
      title?: string;
      defaultPath?: string;
      filters?: { name: string; extensions: string[] }[];
      content: string;
    }) => ipcRenderer.invoke('export-save-file', options),

    savePDF: (options: {
      title?: string;
      defaultPath?: string;
      reportData: unknown;
    }) => ipcRenderer.invoke('export-save-pdf', options),

    openFile: (filePath: string) => ipcRenderer.invoke('export-open-file', filePath),

    showInFolder: (filePath: string) => ipcRenderer.invoke('export-show-in-folder', filePath)
  },

  // Kubernetes Security Operations
  // CIS Benchmark v1.8 | NSA/CISA Hardening Guide | NIST SP 800-190
  kubernetes: {
    getContexts: () => ipcRenderer.invoke('k8s-get-contexts'),
    connect: (config: { name: string; context: string; kubeconfigPath?: string; namespace?: string }) =>
      ipcRenderer.invoke('k8s-connect', config),
    disconnect: () => ipcRenderer.invoke('k8s-disconnect'),
    runAudit: (namespace?: string) => ipcRenderer.invoke('k8s-run-audit', namespace),
    getPods: (namespace?: string) => ipcRenderer.invoke('k8s-get-pods', namespace),
    scanImages: (namespace?: string) => ipcRenderer.invoke('k8s-scan-images', namespace),
    analyzeRBAC: () => ipcRenderer.invoke('k8s-analyze-rbac'),
    checkPolicies: () => ipcRenderer.invoke('k8s-check-policies')
  },

  // GitLab Security Operations
  // OWASP ASVS | NIST SP 800-53 SA-11 | SLSA Framework
  gitlab: {
    connect: (url: string, token: string) => ipcRenderer.invoke('gitlab-connect', url, token),
    disconnect: () => ipcRenderer.invoke('gitlab-disconnect'),
    listProjects: (search?: string) => ipcRenderer.invoke('gitlab-list-projects', search),
    getProject: (projectId: number) => ipcRenderer.invoke('gitlab-get-project', projectId),
    scanProject: (projectId: number) => ipcRenderer.invoke('gitlab-scan-project', projectId)
  },

  // Threat Intelligence Operations
  // EPSS (FIRST.org) | CISA KEV | NVD Enrichment
  threatIntel: {
    getEPSS: (cveId: string) => ipcRenderer.invoke('threatintel-get-epss', cveId),
    getEPSSBatch: (cveIds: string[]) => ipcRenderer.invoke('threatintel-get-epss-batch', cveIds),
    getKEVCatalog: (forceRefresh?: boolean) => ipcRenderer.invoke('threatintel-get-kev-catalog', forceRefresh),
    checkKEV: (cveId: string) => ipcRenderer.invoke('threatintel-check-kev', cveId),
    getKEVStats: () => ipcRenderer.invoke('threatintel-get-kev-stats'),
    searchKEV: (query: string) => ipcRenderer.invoke('threatintel-search-kev', query),
    analyzeCVE: (cveId: string) => ipcRenderer.invoke('threatintel-analyze-cve', cveId),
    analyzeCVEsBatch: (cveIds: string[]) => ipcRenderer.invoke('threatintel-analyze-cves-batch', cveIds),
    clearCache: () => ipcRenderer.invoke('threatintel-clear-cache')
  },

  // SBOM (Software Bill of Materials) Operations
  // Supply Chain Security & Dependency Analysis
  sbom: {
    generate: (projectPath: string) => ipcRenderer.invoke('sbom-generate', projectPath),
    analyze: (sbom: unknown) => ipcRenderer.invoke('sbom-analyze', sbom),
    export: (sbom: unknown, format: 'json' | 'xml', outputPath: string) =>
      ipcRenderer.invoke('sbom-export', sbom, format, outputPath),
    selectProject: () => ipcRenderer.invoke('sbom-select-project')
  },

  // Secret Scanner Operations
  // Hardcoded Credential & Sensitive Data Detection
  secretScanner: {
    scanDirectory: (dirPath: string, options?: unknown) =>
      ipcRenderer.invoke('secrets-scan-directory', dirPath, options),
    scanContent: (content: string, filePath?: string) =>
      ipcRenderer.invoke('secrets-scan-content', content, filePath),
    selectDirectory: () => ipcRenderer.invoke('secrets-select-directory')
  },

  // Secure Vault Operations
  // AES-256-GCM Encrypted Secret Storage
  vault: {
    exists: () => ipcRenderer.invoke('vault-exists'),
    isUnlocked: () => ipcRenderer.invoke('vault-is-unlocked'),
    initialize: (masterPassword: string) => ipcRenderer.invoke('vault-initialize', masterPassword),
    unlock: (masterPassword: string) => ipcRenderer.invoke('vault-unlock', masterPassword),
    lock: () => ipcRenderer.invoke('vault-lock'),
    addSecret: (name: string, value: string, type: string, metadata?: unknown) =>
      ipcRenderer.invoke('vault-add-secret', name, value, type, metadata),
    getSecret: (id: string) => ipcRenderer.invoke('vault-get-secret', id),
    updateSecret: (id: string, newValue: string) => ipcRenderer.invoke('vault-update-secret', id, newValue),
    deleteSecret: (id: string) => ipcRenderer.invoke('vault-delete-secret', id),
    listEntries: () => ipcRenderer.invoke('vault-list-entries'),
    getStats: () => ipcRenderer.invoke('vault-get-stats'),
    changePassword: (currentPassword: string, newPassword: string) =>
      ipcRenderer.invoke('vault-change-password', currentPassword, newPassword),
    getAuditLog: () => ipcRenderer.invoke('vault-get-audit-log'),
    export: () => ipcRenderer.invoke('vault-export')
  }
});

// Type definitions for the renderer
export interface ElectronAPI {
  getAppInfo: () => Promise<{ name: string; version: string; company: string; developer: string }>;
  minimizeWindow: () => Promise<void>;
  maximizeWindow: () => Promise<void>;
  closeWindow: () => Promise<void>;
  updateTrayStatus: (status: { level: string; count: number }) => Promise<void>;
  onRunScan: (callback: () => void) => () => void;
  database: {
    query: (sql: string, params?: unknown[]) => Promise<unknown>;
    run: (sql: string, params?: unknown[]) => Promise<unknown>;
    get: (sql: string, params?: unknown[]) => Promise<unknown>;
    all: (sql: string, params?: unknown[]) => Promise<unknown[]>;
  };
  auth: {
    login: (username: string, password: string) => Promise<{
      success: boolean;
      user?: unknown;
      error?: string;
      require2FA?: boolean;
      phone?: string;
      requirePasswordChange?: boolean;
      passwordExpired?: boolean;
      twoFactorEnabled?: boolean;
      sessionToken?: string;
      locked?: boolean;
      remainingTime?: number;
      remainingAttempts?: number;
    }>;
    logout: () => Promise<void>;
    getCurrentUser: () => Promise<unknown | null>;
    changePassword: (oldPassword: string, newPassword: string) => Promise<{ success: boolean; error?: string; expiresAt?: string }>;
    // 2FA operations (TOTP/Google Authenticator)
    verify2FA: (code: string) => Promise<{
      success: boolean;
      user?: unknown;
      error?: string;
      requirePasswordChange?: boolean;
      passwordExpired?: boolean;
    }>;
    setup2FA: () => Promise<{ success: boolean; error?: string; message?: string; qrCode?: string; secret?: string }>;
    confirm2FASetup: (code: string) => Promise<{ success: boolean; error?: string; message?: string }>;
    disable2FA: () => Promise<{ success: boolean; error?: string; message?: string }>;
    get2FAStatus: () => Promise<{ enabled: boolean; hasSecret?: boolean }>;
    // Security audit and session management
    getAuditLog: () => Promise<{
      success: boolean;
      error?: string;
      log?: Array<{
        timestamp: string;
        event: string;
        username?: string;
        success: boolean;
        details?: string;
        severity: 'INFO' | 'WARNING' | 'CRITICAL';
      }>;
    }>;
    getSessionStatus: () => Promise<{
      valid: boolean;
      remainingTime?: number;
      expiresAt?: string;
    }>;
  };
  scanner: {
    runSemgrep: (path: string) => Promise<unknown[]>;
    runTrivy: (path: string) => Promise<unknown[]>;
    runSnyk: (path: string) => Promise<unknown[]>;
    runAllScans: (path: string) => Promise<unknown[]>;
  };
  sbom: {
    generate: (path: string, format: string) => Promise<string>;
    parse: (sbomPath: string) => Promise<unknown[]>;
  };
  compliance: {
    getControls: () => Promise<unknown[]>;
    evaluateControl: (controlId: string) => Promise<unknown>;
    generateReport: () => Promise<string>;
  };
  ollama: {
    chat: (message: string, context?: string) => Promise<string>;
    streamChat: (message: string, context?: string) => {
      onChunk: (callback: (chunk: string) => void) => void;
      onEnd: (callback: () => void) => void;
      cancel: () => void;
    };
    getModels: () => Promise<string[]>;
    setModel: (model: string) => Promise<void>;
  };
  fs: {
    selectDirectory: () => Promise<string | null>;
    selectFile: (filters?: { name: string; extensions: string[] }[]) => Promise<string | null>;
    readFile: (filePath: string) => Promise<string>;
    writeFile: (filePath: string, content: string) => Promise<void>;
  };
  security: {
    runAudit: () => Promise<{
      riskScore: { overall: number; critical: number; high: number; medium: number; low: number; info: number };
      compliance: { framework: string; score: number; level: number; totalControls: number; compliant: number; partiallyCompliant: number; nonCompliant: number; notAssessed: number };
      sbomStats: {
        totalComponents: number;
        libraries: number;
        frameworks: number;
        vulnerableComponents: number;
        lastGenerated: string | null;
        libraryDetails?: Array<{
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
        }>;
      };
      findings: Array<{ id: string; title: string; severity: string; tool: string; timestamp: string; description?: string; remediation?: string; file?: string; line?: number }>;
      scanTime: string;
    }>;
    autoFix: () => Promise<{ success: boolean; fixed: string[]; failed: string[] }>;
    // Advanced scanning features
    semgrepScan: () => Promise<Array<{ id: string; title: string; severity: string; tool: string; timestamp: string; description?: string; remediation?: string; file?: string; line?: number }>>;
    dockerScan: (imageName: string) => Promise<Array<{ id: string; title: string; severity: string; tool: string; timestamp: string; description?: string; remediation?: string; file?: string; line?: number }>>;
    cveLookup: (cveId: string) => Promise<{ id: string; description: string; severity: string; cvss: number; references: string[]; publishedDate: string; exploitAvailable: boolean } | null>;
    gitHistoryScan: () => Promise<Array<{ id: string; title: string; severity: string; tool: string; timestamp: string; description?: string; remediation?: string; file?: string; line?: number }>>;
    eslintScan: () => Promise<Array<{ id: string; title: string; severity: string; tool: string; timestamp: string; description?: string; remediation?: string; file?: string; line?: number }>>;
    generateSarif: (findings: unknown[]) => Promise<object>;
  };
  export: {
    saveFile: (options: {
      title?: string;
      defaultPath?: string;
      filters?: { name: string; extensions: string[] }[];
      content: string;
    }) => Promise<{ success: boolean; filePath?: string; error?: string }>;
    savePDF: (options: {
      title?: string;
      defaultPath?: string;
      reportData: unknown;
    }) => Promise<{ success: boolean; filePath?: string; error?: string }>;
    openFile: (filePath: string) => Promise<{ success: boolean; error?: string }>;
    showInFolder: (filePath: string) => Promise<{ success: boolean; error?: string }>;
  };
  kubernetes: {
    getContexts: () => Promise<string[]>;
    connect: (config: { name: string; context: string; kubeconfigPath?: string; namespace?: string }) => Promise<{
      success: boolean;
      cluster?: {
        name: string;
        context: string;
        server: string;
        version?: string;
        nodeCount: number;
        namespaceCount: number;
        podCount: number;
        connected: boolean;
      };
      error?: string;
    }>;
    disconnect: () => Promise<void>;
    runAudit: (namespace?: string) => Promise<{
      cluster: {
        name: string;
        context: string;
        server: string;
        version?: string;
        nodeCount: number;
        namespaceCount: number;
        podCount: number;
        connected: boolean;
      };
      cisBenchmark: {
        version: string;
        totalChecks: number;
        passed: number;
        failed: number;
        warnings: number;
        findings: Array<{
          id: string;
          section: string;
          title: string;
          status: 'PASS' | 'FAIL' | 'WARN' | 'INFO';
          severity: string;
          description: string;
          remediation: string;
          reference: string;
        }>;
        scanTime: string;
      };
      podSecurity: {
        totalPods: number;
        privilegedPods: number;
        baselinePods: number;
        restrictedPods: number;
        violations: Array<{
          namespace: string;
          pod: string;
          container: string;
          profile: string;
          violations: string[];
          severity: string;
        }>;
      };
      rbacAnalysis: {
        totalServiceAccounts: number;
        overprivilegedAccounts: Array<{
          subject: string;
          subjectKind: string;
          namespace?: string;
          permissions: string[];
          risk: string;
          description: string;
          recommendation: string;
        }>;
        clusterAdminBindings: number;
        wildcardPermissions: Array<unknown>;
        serviceAccountRisks: Array<unknown>;
      };
      networkPolicies: {
        totalPolicies: number;
        namespacesWithPolicies: number;
        namespacesWithoutPolicies: string[];
        defaultDenyIngress: number;
        defaultDenyEgress: number;
        gaps: Array<unknown>;
        coverage: number;
      };
      containerImages: Array<{
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
      }>;
      secretsExposure: {
        totalSecrets: number;
        secretsInDefaultNamespace: number;
        secretsWithWeakEncoding: number;
        envVarSecrets: number;
        findings: Array<unknown>;
      };
      resourceQuotas: {
        namespacesWithQuotas: number;
        namespacesWithoutQuotas: string[];
        namespacesWithLimitRanges: number;
        podsWithoutLimits: number;
        podsWithoutRequests: number;
        findings: Array<unknown>;
      };
      complianceScore: number;
      scanTime: string;
    }>;
    getPods: (namespace?: string) => Promise<{
      totalPods: number;
      privilegedPods: number;
      baselinePods: number;
      restrictedPods: number;
      violations: Array<{
        namespace: string;
        pod: string;
        container: string;
        profile: string;
        violations: string[];
        severity: string;
      }>;
    }>;
    scanImages: (namespace?: string) => Promise<Array<{
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
    }>>;
    analyzeRBAC: () => Promise<{
      totalServiceAccounts: number;
      overprivilegedAccounts: Array<{
        subject: string;
        subjectKind: string;
        namespace?: string;
        permissions: string[];
        risk: string;
        description: string;
        recommendation: string;
      }>;
      clusterAdminBindings: number;
      wildcardPermissions: Array<unknown>;
      serviceAccountRisks: Array<unknown>;
    }>;
    checkPolicies: () => Promise<{
      totalPolicies: number;
      namespacesWithPolicies: number;
      namespacesWithoutPolicies: string[];
      defaultDenyIngress: number;
      defaultDenyEgress: number;
      gaps: Array<unknown>;
      coverage: number;
    }>;
  };
  gitlab: {
    connect: (url: string, token: string) => Promise<{
      success: boolean;
      user?: {
        username: string;
        name: string;
        email: string;
      };
      error?: string;
    }>;
    disconnect: () => Promise<void>;
    listProjects: (search?: string) => Promise<Array<{
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
    }>>;
    getProject: (projectId: number) => Promise<{
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
    }>;
    scanProject: (projectId: number) => Promise<{
      project: {
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
      };
      sastFindings: Array<{
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
      }>;
      secretsDetected: Array<{
        id: string;
        type: string;
        file: string;
        line: number;
        secret: string;
        severity: 'critical' | 'high';
        description: string;
        remediation: string;
      }>;
      pipelineSecurity: {
        hasSecurityStages: boolean;
        hasSASTJob: boolean;
        hasDependencyScan: boolean;
        hasContainerScan: boolean;
        hasSecretDetection: boolean;
        hasLicenseCompliance: boolean;
        issues: Array<{
          id: string;
          type: 'security' | 'configuration' | 'best-practice';
          title: string;
          severity: 'critical' | 'high' | 'medium' | 'low';
          location: string;
          description: string;
          remediation: string;
          reference?: string;
        }>;
        score: number;
      };
      containerImages: Array<{
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
      }>;
      dependencyVulnerabilities: Array<{
        package: string;
        version: string;
        severity: string;
        cve?: string;
        fixedVersion?: string;
      }>;
      complianceScore: number;
      scanTime: string;
    }>;
  };
  threatIntel: {
    getEPSS: (cveId: string) => Promise<{
      cve: string;
      epss: number;
      percentile: number;
      date: string;
    } | null>;
    getEPSSBatch: (cveIds: string[]) => Promise<Record<string, {
      cve: string;
      epss: number;
      percentile: number;
      date: string;
    }>>;
    getKEVCatalog: (forceRefresh?: boolean) => Promise<{
      title: string;
      catalogVersion: string;
      dateReleased: string;
      count: number;
      vulnerabilities: Array<{
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
      }>;
    } | null>;
    checkKEV: (cveId: string) => Promise<{
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
    } | null>;
    getKEVStats: () => Promise<{
      totalCount: number;
      lastUpdated: string;
      byVendor: Record<string, number>;
      ransomwareRelated: number;
      recentlyAdded: Array<{
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
      }>;
    }>;
    searchKEV: (query: string) => Promise<Array<{
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
    }>>;
    analyzeCVE: (cveId: string) => Promise<{
      cve: string;
      epss?: {
        cve: string;
        epss: number;
        percentile: number;
        date: string;
      };
      kev?: {
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
      };
      nvdData?: {
        description: string;
        cvssV3Score: number;
        cvssV3Severity: string;
        cvssV2Score?: number;
        publishedDate: string;
        lastModified: string;
        references: string[];
        cwes: string[];
      };
      priorityScore: number;
      priorityRating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      recommendation: string;
    }>;
    analyzeCVEsBatch: (cveIds: string[]) => Promise<Array<{
      cve: string;
      epss?: {
        cve: string;
        epss: number;
        percentile: number;
        date: string;
      };
      kev?: {
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
      };
      nvdData?: {
        description: string;
        cvssV3Score: number;
        cvssV3Severity: string;
        cvssV2Score?: number;
        publishedDate: string;
        lastModified: string;
        references: string[];
        cwes: string[];
      };
      priorityScore: number;
      priorityRating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      recommendation: string;
    }>>;
    clearCache: () => Promise<{ success: boolean }>;
  };
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
