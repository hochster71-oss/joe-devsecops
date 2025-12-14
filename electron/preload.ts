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
    autoFix: (findings?: Array<{ id: string; title: string; severity: string; tool: string; timestamp: string; description?: string; remediation?: string; file?: string; line?: number }>) =>
      ipcRenderer.invoke('security-auto-fix', findings),
    generatePoam: (findings: Array<{ id: string; title: string; severity: string; tool: string; timestamp: string; description?: string; remediation?: string; file?: string; line?: number }>) =>
      ipcRenderer.invoke('security-generate-poam', findings),
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
  },

  // =============================================================================
  // AI TOUCHPOINT SYSTEM
  // Space-Grade Security Intelligence with Framework Citations
  // NASA-STD-8719 | DO-178C | NIST CSF 2.0 | MITRE ATT&CK
  // =============================================================================
  aiTouchpoint: {
    // Query AI for touchpoint context (non-streaming)
    query: (context: {
      elementType: string;
      elementId: string;
      dataContext: unknown;
      requestedFrameworks: string[];
      depth: 'tooltip' | 'panel' | 'deepdive';
      sessionId: string;
      timestamp: number;
    }) => ipcRenderer.invoke('ai-touchpoint-query', context),

    // Stream AI response for real-time display
    streamQuery: (context: {
      elementType: string;
      elementId: string;
      dataContext: unknown;
      requestedFrameworks: string[];
      depth: 'tooltip' | 'panel' | 'deepdive';
      sessionId: string;
      timestamp: number;
    }) => {
      const requestId = `stream-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      ipcRenderer.send('ai-touchpoint-stream-start', { ...context, requestId });

      return {
        onChunk: (callback: (chunk: { type: string; content: string; index: number }) => void) => {
          const handler = (_: unknown, data: { requestId: string; chunk: { type: string; content: string; index: number } }) => {
            if (data.requestId === requestId) {
              callback(data.chunk);
            }
          };
          ipcRenderer.on('ai-touchpoint-stream-chunk', handler);
          return () => ipcRenderer.removeListener('ai-touchpoint-stream-chunk', handler);
        },
        onComplete: (callback: (response: unknown) => void) => {
          const handler = (_: unknown, data: { requestId: string; response: unknown }) => {
            if (data.requestId === requestId) {
              callback(data.response);
            }
          };
          ipcRenderer.on('ai-touchpoint-stream-complete', handler);
          return () => ipcRenderer.removeListener('ai-touchpoint-stream-complete', handler);
        },
        onError: (callback: (error: Error) => void) => {
          const handler = (_: unknown, data: { requestId: string; error: string }) => {
            if (data.requestId === requestId) {
              callback(new Error(data.error));
            }
          };
          ipcRenderer.on('ai-touchpoint-stream-error', handler);
          return () => ipcRenderer.removeListener('ai-touchpoint-stream-error', handler);
        },
        cancel: () => ipcRenderer.send('ai-touchpoint-stream-cancel', requestId),
        isPaused: false,
        pause: () => ipcRenderer.send('ai-touchpoint-stream-pause', requestId),
        resume: () => ipcRenderer.send('ai-touchpoint-stream-resume', requestId)
      };
    },

    // Analyze security metric
    analyzeMetric: (metricName: string, value: number, trend: 'up' | 'down' | 'stable', context?: unknown) =>
      ipcRenderer.invoke('ai-touchpoint-analyze-metric', { metricName, value, trend, context }),

    // Generate attack path diagram
    generateAttackPath: (vulnerability: { id: string; title: string; severity: string; description: string }) =>
      ipcRenderer.invoke('ai-touchpoint-generate-attack-path', vulnerability)
  },

  // =============================================================================
  // ANALYTICS & SELF-LEARNING ENGINE
  // SQLite-powered interaction tracking for continuous improvement
  // =============================================================================
  analytics: {
    // Track user interaction
    track: (event: {
      type: string;
      elementType: string;
      elementId?: string;
      durationMs?: number;
      context?: Record<string, unknown>;
    }) => ipcRenderer.invoke('analytics-track', event),

    // Rate AI response quality (1-5)
    rate: (queryId: string, rating: number) =>
      ipcRenderer.invoke('analytics-rate', queryId, rating),

    // Get user behavior profile
    getProfile: () => ipcRenderer.invoke('analytics-get-profile'),

    // Get analytics insights with optional timeframe
    getInsights: (timeframe?: { start: number; end: number }) =>
      ipcRenderer.invoke('analytics-get-insights', timeframe),

    // Get detected security patterns
    getPatterns: (severity?: string) => ipcRenderer.invoke('analytics-get-patterns', severity),

    // Get learning insights
    getLearningInsights: () => ipcRenderer.invoke('analytics-get-learning-insights'),

    // Get interaction statistics
    getStats: () => ipcRenderer.invoke('analytics-get-stats'),

    // Cleanup old data
    cleanup: (daysToKeep?: number) => ipcRenderer.invoke('analytics-cleanup', daysToKeep)
  },

  // ========================================
  // SPACE-GRADE COMPLIANCE API
  // NASA-STD-8719.13 | DO-178C | Common Criteria
  // ========================================
  spaceCompliance: {
    // Register project for compliance assessment
    registerProject: (config: {
      name: string;
      type: 'spacecraft' | 'avionics' | 'ground-system' | 'mission-control' | 'general';
      primaryFramework: 'NASA-STD-8719' | 'DO-178C' | 'Common-Criteria';
      targetLevel: string;
      description?: string;
    }) => ipcRenderer.invoke('space-compliance-register-project', config),

    // Get project details
    getProject: (projectId: string) => ipcRenderer.invoke('space-compliance-get-project', projectId),

    // List all projects
    listProjects: () => ipcRenderer.invoke('space-compliance-list-projects'),

    // NASA Safety Assessment
    assessNASA: (params: {
      projectName: string;
      assessor: string;
      hazardAnalysis: {
        lossOfLife: boolean;
        severeInjury: boolean;
        missionCritical: boolean;
        propertyDamage: 'none' | 'minor' | 'major' | 'critical';
      };
      safetyMetrics: {
        hazardsIdentified: number;
        hazardsMitigated: number;
        openSafetyIssues: number;
        safetyReviewsCompleted: number;
        independentReviewsCompleted: number;
      };
      existingControls: string[];
    }) => ipcRenderer.invoke('space-compliance-assess-nasa', params),

    // DO-178C Assessment
    assessDO178C: (params: {
      projectName: string;
      assessor: string;
      failureCondition: 'catastrophic' | 'hazardous' | 'major' | 'minor' | 'no-effect';
      coverageMetrics: {
        statementCoverage: number;
        branchCoverage: number;
        mcdcCoverage: number;
        requirementsCoverage: number;
        testCaseCoverage: number;
      };
      documentationStatus: Record<string, boolean>;
      verificationActivities: string[];
    }) => ipcRenderer.invoke('space-compliance-assess-do178c', params),

    // Common Criteria Assessment
    assessCommonCriteria: (params: {
      projectName: string;
      assessor: string;
      targetEAL: 'EAL-1' | 'EAL-2' | 'EAL-3' | 'EAL-4' | 'EAL-5' | 'EAL-6' | 'EAL-7';
      assuranceComponents: Record<string, 'satisfied' | 'partial' | 'not-satisfied'>;
      securityFunctions: string[];
    }) => ipcRenderer.invoke('space-compliance-assess-cc', params),

    // Get assessment by ID
    getAssessment: (assessmentId: string) =>
      ipcRenderer.invoke('space-compliance-get-assessment', assessmentId),

    // List all assessments
    listAssessments: () => ipcRenderer.invoke('space-compliance-list-assessments'),

    // Get framework information
    getFrameworkInfo: (framework: 'NASA-STD-8719' | 'DO-178C' | 'Common-Criteria') =>
      ipcRenderer.invoke('space-compliance-get-framework-info', framework),

    // Get cross-framework mappings
    getMappings: (framework: string, controlId: string) =>
      ipcRenderer.invoke('space-compliance-get-mappings', framework, controlId),

    // Generate unified compliance report
    generateUnifiedReport: (assessmentIds: string[]) =>
      ipcRenderer.invoke('space-compliance-unified-report', assessmentIds)
  },

  // ========================================
  // NOTIFICATION SERVICE API
  // Real-time Alerts | Slack | Teams | Email
  // ========================================
  notifications: {
    send: (payload: {
      title: string;
      message: string;
      severity: string;
      channels: string[];
      metadata?: unknown;
    }) => ipcRenderer.invoke('notification-send', payload),

    configureChannel: (channel: string, config: unknown) =>
      ipcRenderer.invoke('notification-configure-channel', channel, config),

    getChannelConfig: (channel: string) =>
      ipcRenderer.invoke('notification-get-channel-config', channel),

    testChannel: (channel: string) =>
      ipcRenderer.invoke('notification-test-channel', channel),

    addRule: (rule: {
      name: string;
      conditions: { severity?: string[]; type?: string[]; framework?: string[] };
      channels: string[];
      throttleMinutes?: number;
      enabled?: boolean;
    }) => ipcRenderer.invoke('notification-add-rule', rule),

    removeRule: (ruleId: string) =>
      ipcRenderer.invoke('notification-remove-rule', ruleId),

    getRules: () => ipcRenderer.invoke('notification-get-rules'),

    processFinding: (finding: unknown) =>
      ipcRenderer.invoke('notification-process-finding', finding)
  },

  // ========================================
  // IAC SECURITY SCANNER API
  // Terraform | CloudFormation | Kubernetes | Docker | Ansible
  // ========================================
  iac: {
    selectDirectory: () => ipcRenderer.invoke('iac-select-directory'),

    scanDirectory: (dirPath: string, options?: { recursive?: boolean }) =>
      ipcRenderer.invoke('iac-scan-directory', dirPath, options),

    scanFile: (filePath: string) =>
      ipcRenderer.invoke('iac-scan-file', filePath),

    getSupportedTypes: () => ipcRenderer.invoke('iac-get-supported-types'),

    getRules: (iacType?: string) =>
      ipcRenderer.invoke('iac-get-rules', iacType),

    // GAP-002 FIX: Add rule enable/disable methods
    enableRule: (ruleId: string) =>
      ipcRenderer.invoke('iac-enable-rule', ruleId),

    disableRule: (ruleId: string) =>
      ipcRenderer.invoke('iac-disable-rule', ruleId)
  },

  // ========================================
  // API SECURITY SCANNER API
  // OpenAPI/Swagger | OWASP API Top 10 2023
  // ========================================
  apiSecurity: {
    selectSpecFile: () => ipcRenderer.invoke('api-security-select-spec'),

    scanSpec: (specPath: string) =>
      ipcRenderer.invoke('api-security-scan-spec', specPath),

    scanFromUrl: (url: string) =>
      ipcRenderer.invoke('api-security-scan-url', url),

    // GAP-001 FIX: Add directory scanning for batch API spec analysis
    scanDirectory: (dirPath: string, options?: { recursive?: boolean }) =>
      ipcRenderer.invoke('api-security-scan-directory', dirPath, options),

    getOWASPCategories: () =>
      ipcRenderer.invoke('api-security-get-owasp-categories'),

    getRules: () => ipcRenderer.invoke('api-security-get-rules')
  },

  // ========================================
  // SIEM CONNECTOR API
  // Splunk | Elastic | Sentinel | QRadar
  // ========================================
  siem: {
    configure: (platform: string, config: unknown) =>
      ipcRenderer.invoke('siem-configure', platform, config),

    getConfig: (platform: string) =>
      ipcRenderer.invoke('siem-get-config', platform),

    testConnection: (platform: string) =>
      ipcRenderer.invoke('siem-test-connection', platform),

    sendEvent: (platform: string, event: unknown) =>
      ipcRenderer.invoke('siem-send-event', platform, event),

    sendBatch: (platform: string, events: unknown[]) =>
      ipcRenderer.invoke('siem-send-batch', platform, events),

    exportFindings: (platform: string, findings: unknown[]) =>
      ipcRenderer.invoke('siem-export-findings', platform, findings),

    getPlatforms: () => ipcRenderer.invoke('siem-get-platforms')
  },

  // ========================================
  // TICKETING INTEGRATION API
  // Jira | ServiceNow | Azure Boards | GitHub | Linear
  // ========================================
  ticketing: {
    configure: (platform: string, config: unknown) =>
      ipcRenderer.invoke('ticketing-configure', platform, config),

    getConfig: (platform: string) =>
      ipcRenderer.invoke('ticketing-get-config', platform),

    testConnection: (platform: string) =>
      ipcRenderer.invoke('ticketing-test-connection', platform),

    createTicket: (platform: string, finding: unknown) =>
      ipcRenderer.invoke('ticketing-create-ticket', platform, finding),

    createBulkTickets: (platform: string, findings: unknown[]) =>
      ipcRenderer.invoke('ticketing-create-bulk', platform, findings),

    updateStatus: (platform: string, ticketId: string, status: string, comment?: string) =>
      ipcRenderer.invoke('ticketing-update-status', platform, ticketId, status, comment),

    getTicket: (platform: string, ticketId: string) =>
      ipcRenderer.invoke('ticketing-get-ticket', platform, ticketId),

    syncStatus: (platform: string, ticketId: string) =>
      ipcRenderer.invoke('ticketing-sync-status', platform, ticketId),

    getPlatforms: () => ipcRenderer.invoke('ticketing-get-platforms')
  },

  // ========================================
  // VIRTUAL SPACES API
  // DoD-Hardened Kubernetes Namespaces for Secure Code Analysis
  // Kind Cluster | Pod Security Standards | Network Policies | RBAC
  // ========================================
  virtualSpaces: {
    // Cluster lifecycle
    getClusterStatus: () => ipcRenderer.invoke('vs-cluster-status'),
    initCluster: () => ipcRenderer.invoke('vs-init-cluster'),
    destroyCluster: () => ipcRenderer.invoke('vs-destroy-cluster'),

    // Space lifecycle
    createSpace: (config: { name: string; owner: string; tier: 'team' | 'elevated' | 'admin'; ttlMinutes?: number }) =>
      ipcRenderer.invoke('vs-create-space', config),
    destroySpace: (spaceId: string) => ipcRenderer.invoke('vs-destroy-space', spaceId),
    listSpaces: () => ipcRenderer.invoke('vs-list-spaces'),
    getSpace: (spaceId: string) => ipcRenderer.invoke('vs-get-space', spaceId),

    // Code operations
    importCode: (spaceId: string, source: { type: 'git' | 'upload'; url?: string; path?: string }) =>
      ipcRenderer.invoke('vs-import-code', spaceId, source),
    exportArtifacts: (spaceId: string, artifacts: string[]) =>
      ipcRenderer.invoke('vs-export-artifacts', spaceId, artifacts),

    // Security scanning
    scanSpace: (spaceId: string) => ipcRenderer.invoke('vs-scan-space', spaceId),

    // Space management
    extendSpace: (spaceId: string, additionalMinutes: number) =>
      ipcRenderer.invoke('vs-extend-space', spaceId, additionalMinutes),

    // Tier information
    getTiers: () => ipcRenderer.invoke('vs-get-tiers'),
    canCreateTier: (tier: string, owner: string) =>
      ipcRenderer.invoke('vs-can-create-tier', tier, owner)
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
    autoFix: (findings?: Array<{ id: string; title: string; severity: string; tool: string; timestamp: string; description?: string; remediation?: string; file?: string; line?: number }>) => Promise<{
      success: boolean;
      fixed: Array<{ id: string; title: string; action: string }>;
      failed: Array<{ id: string; title: string; reason: string }>;
      poam: Array<{ id: string; title: string; severity: string; reason: string; milestoneDays: number }>;
    }>;
    generatePoam: (findings: Array<{ id: string; title: string; severity: string; tool: string; timestamp: string; description?: string; remediation?: string; file?: string; line?: number }>) => Promise<{
      poamId: string;
      generatedAt: string;
      items: Array<{
        id: string;
        weakness: string;
        severity: string;
        responsibleParty: string;
        resources: string;
        scheduledCompletionDate: string;
        milestones: Array<{ description: string; dueDate: string }>;
        status: 'Open' | 'In Progress' | 'Completed';
      }>;
      summary: { total: number; critical: number; high: number; medium: number; low: number };
    }>;
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
  // SBOM Operations (Supply Chain)
  sbom: {
    generate: (projectPath: string) => Promise<unknown>;
    analyze: (sbom: unknown) => Promise<unknown>;
    export: (sbom: unknown, format: 'json' | 'xml', outputPath: string) => Promise<{ success: boolean; filePath?: string; error?: string }>;
    selectProject: () => Promise<string | null>;
  };
  // Secret Scanner
  secretScanner: {
    scanDirectory: (dirPath: string, options?: unknown) => Promise<Array<{
      id: string;
      type: string;
      file: string;
      line: number;
      severity: 'critical' | 'high' | 'medium' | 'low';
      secret: string;
      description: string;
      remediation: string;
    }>>;
    scanContent: (content: string, filePath?: string) => Promise<Array<{
      type: string;
      line: number;
      severity: string;
      match: string;
    }>>;
    selectDirectory: () => Promise<string | null>;
  };
  // Secure Vault
  vault: {
    exists: () => Promise<boolean>;
    isUnlocked: () => Promise<boolean>;
    initialize: (masterPassword: string) => Promise<{ success: boolean; error?: string }>;
    unlock: (masterPassword: string) => Promise<{ success: boolean; error?: string }>;
    lock: () => Promise<{ success: boolean }>;
    addSecret: (name: string, value: string, type: string, metadata?: unknown) => Promise<{ success: boolean; id?: string; error?: string }>;
    getSecret: (id: string) => Promise<{ success: boolean; value?: string; error?: string }>;
    updateSecret: (id: string, newValue: string) => Promise<{ success: boolean; error?: string }>;
    deleteSecret: (id: string) => Promise<{ success: boolean; error?: string }>;
    listEntries: () => Promise<Array<{
      id: string;
      name: string;
      type: string;
      createdAt: string;
      updatedAt: string;
      metadata?: unknown;
    }>>;
    getStats: () => Promise<{
      totalSecrets: number;
      byType: Record<string, number>;
      lastAccess?: string;
    }>;
    changePassword: (currentPassword: string, newPassword: string) => Promise<{ success: boolean; error?: string }>;
    getAuditLog: () => Promise<Array<{
      timestamp: string;
      action: string;
      secretName?: string;
      success: boolean;
    }>>;
    export: () => Promise<{ success: boolean; filePath?: string; error?: string }>;
  };
  // AI Touchpoint
  aiTouchpoint: {
    query: (context: {
      elementType: string;
      elementId: string;
      dataContext: unknown;
      requestedFrameworks: string[];
      depth: 'tooltip' | 'panel' | 'deepdive';
      sessionId: string;
      timestamp: number;
    }) => Promise<{
      overview: string;
      citations: Array<{ framework: string; controlId: string; title: string; relevance: number }>;
      attackPath?: string;
      remediation?: string;
      riskScore?: number;
    }>;
    streamQuery: (context: {
      elementType: string;
      elementId: string;
      dataContext: unknown;
      requestedFrameworks: string[];
      depth: 'tooltip' | 'panel' | 'deepdive';
      sessionId: string;
      timestamp: number;
    }) => {
      onChunk: (callback: (chunk: { type: string; content: string; index: number }) => void) => () => void;
      onComplete: (callback: (response: unknown) => void) => () => void;
      onError: (callback: (error: Error) => void) => () => void;
      cancel: () => void;
      isPaused: boolean;
      pause: () => void;
      resume: () => void;
    };
    analyzeMetric: (metricName: string, value: number, trend: 'up' | 'down' | 'stable', context?: unknown) => Promise<{
      analysis: string;
      recommendation: string;
      citations: Array<{ framework: string; controlId: string }>;
    }>;
    generateAttackPath: (vulnerability: { id: string; title: string; severity: string; description: string }) => Promise<{
      mermaidDiagram: string;
      steps: Array<{ step: number; description: string; technique?: string }>;
    }>;
  };
  // Analytics
  analytics: {
    track: (event: {
      type: string;
      elementType: string;
      elementId?: string;
      durationMs?: number;
      context?: Record<string, unknown>;
    }) => Promise<{ success: boolean }>;
    rate: (queryId: string, rating: number) => Promise<{ success: boolean }>;
    getProfile: () => Promise<{
      expertiseLevel: string;
      preferredFrameworks: string[];
      commonQueries: string[];
    }>;
    getInsights: (timeframe?: { start: number; end: number }) => Promise<{
      totalInteractions: number;
      averageSessionLength: number;
      topElements: Array<{ elementType: string; count: number }>;
    }>;
    getPatterns: (severity?: string) => Promise<Array<{
      patternType: string;
      severity: string;
      description: string;
      recommendedActions: string[];
    }>>;
    getLearningInsights: () => Promise<{
      topRatedResponses: Array<{ queryId: string; rating: number; prompt: string }>;
      improvementAreas: string[];
    }>;
    getStats: () => Promise<{
      totalQueries: number;
      averageRating: number;
      responseTimeMs: number;
    }>;
    cleanup: (daysToKeep?: number) => Promise<{ success: boolean; deletedCount: number }>;
  };
  // Space Compliance
  spaceCompliance: {
    registerProject: (config: {
      name: string;
      type: 'spacecraft' | 'avionics' | 'ground-system' | 'mission-control' | 'general';
      primaryFramework: 'NASA-STD-8719' | 'DO-178C' | 'Common-Criteria';
      targetLevel: string;
      description?: string;
    }) => Promise<{ success: boolean; projectId?: string; error?: string }>;
    getProject: (projectId: string) => Promise<unknown>;
    listProjects: () => Promise<Array<{ id: string; name: string; type: string; framework: string }>>;
    assessNASA: (params: unknown) => Promise<{
      category: string;
      score: number;
      findings: Array<{ control: string; status: string; description: string }>;
      recommendations: string[];
    }>;
    assessDO178C: (params: unknown) => Promise<{
      dalLevel: string;
      coverageScore: number;
      objectives: Array<{ id: string; status: string; description: string }>;
      gaps: string[];
    }>;
    assessCommonCriteria: (params: unknown) => Promise<{
      ealLevel: string;
      assuranceScore: number;
      components: Array<{ id: string; status: string; description: string }>;
      recommendations: string[];
    }>;
    getAssessment: (assessmentId: string) => Promise<unknown>;
    listAssessments: () => Promise<Array<{ id: string; framework: string; score: number; date: string }>>;
    getFrameworkInfo: (framework: 'NASA-STD-8719' | 'DO-178C' | 'Common-Criteria') => Promise<{
      name: string;
      version: string;
      description: string;
      levels: Array<{ id: string; name: string; description: string }>;
    }>;
    getMappings: (framework: string, controlId: string) => Promise<Array<{
      targetFramework: string;
      targetControlId: string;
      mappingType: 'equivalent' | 'partial' | 'related';
    }>>;
    generateUnifiedReport: (assessmentIds: string[]) => Promise<{
      success: boolean;
      report?: unknown;
      error?: string;
    }>;
  };
  // Notification Service
  notifications: {
    send: (payload: {
      title: string;
      message: string;
      severity: string;
      channels: string[];
      metadata?: unknown;
    }) => Promise<{ success: boolean; results?: unknown; error?: string }>;
    configureChannel: (channel: string, config: unknown) => Promise<{ success: boolean; error?: string }>;
    getChannelConfig: (channel: string) => Promise<unknown>;
    testChannel: (channel: string) => Promise<{ success: boolean; error?: string }>;
    addRule: (rule: {
      name: string;
      conditions: { severity?: string[]; type?: string[]; framework?: string[] };
      channels: string[];
      throttleMinutes?: number;
      enabled?: boolean;
    }) => Promise<{ success: boolean; ruleId?: string; error?: string }>;
    removeRule: (ruleId: string) => Promise<{ success: boolean; error?: string }>;
    getRules: () => Promise<Array<unknown>>;
    processFinding: (finding: unknown) => Promise<{ success: boolean; error?: string }>;
  };
  // IaC Scanner
  iac: {
    selectDirectory: () => Promise<string | null>;
    scanDirectory: (dirPath: string, options?: { recursive?: boolean }) => Promise<{
      success: boolean;
      results?: {
        scanId: string;
        timestamp: string;
        duration: number;
        iacType: string;
        filesScanned: number;
        findings: Array<{
          id: string;
          ruleId: string;
          title: string;
          description: string;
          severity: string;
          category: string;
          resource?: string;
          file: string;
          line: number;
          remediation: string;
        }>;
        summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
        passedChecks: number;
        failedChecks: number;
      };
      error?: string;
    }>;
    scanFile: (filePath: string) => Promise<{ success: boolean; results?: unknown; error?: string }>;
    getSupportedTypes: () => Promise<string[]>;
    getRules: (iacType?: string) => Promise<Array<unknown>>;
    // GAP-002 FIX: Enable/disable rule methods
    enableRule: (ruleId: string) => Promise<{ success: boolean; error?: string }>;
    disableRule: (ruleId: string) => Promise<{ success: boolean; error?: string }>;
  };
  // API Security Scanner
  apiSecurity: {
    selectSpecFile: () => Promise<string | null>;
    scanSpec: (specPath: string) => Promise<{
      success: boolean;
      results?: {
        scanId: string;
        timestamp: string;
        duration: number;
        specFile: string;
        apiTitle: string;
        apiVersion: string;
        baseUrl?: string;
        endpointsAnalyzed: number;
        endpoints: Array<{
          path: string;
          method: string;
          summary?: string;
          security?: string[];
        }>;
        findings: Array<{
          id: string;
          ruleId: string;
          title: string;
          description: string;
          severity: string;
          owaspCategory: string;
          endpoint?: string;
          method?: string;
          remediation: string;
        }>;
        summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
        securityScore: number;
        owaspCoverage: Record<string, { findings: number; status: string }>;
      };
      error?: string;
    }>;
    scanFromUrl: (url: string) => Promise<{ success: boolean; results?: unknown; error?: string }>;
    // GAP-001 FIX: Directory scanning method
    scanDirectory: (dirPath: string, options?: { recursive?: boolean }) => Promise<{ success: boolean; results?: unknown[]; error?: string }>;
    getOWASPCategories: () => Promise<Record<string, { name: string; description: string }>>;
    getRules: () => Promise<Array<unknown>>;
  };
  // SIEM Connector
  siem: {
    configure: (platform: string, config: unknown) => Promise<{ success: boolean; error?: string }>;
    getConfig: (platform: string) => Promise<unknown>;
    testConnection: (platform: string) => Promise<{ success: boolean; error?: string }>;
    sendEvent: (platform: string, event: unknown) => Promise<{ success: boolean; error?: string }>;
    sendBatch: (platform: string, events: unknown[]) => Promise<{ success: boolean; error?: string }>;
    exportFindings: (platform: string, findings: unknown[]) => Promise<{ success: boolean; error?: string }>;
    getPlatforms: () => Promise<string[]>;
  };
  // Ticketing Integration
  ticketing: {
    configure: (platform: string, config: unknown) => Promise<{ success: boolean; error?: string }>;
    getConfig: (platform: string) => Promise<unknown>;
    testConnection: (platform: string) => Promise<{ success: boolean; error?: string }>;
    createTicket: (platform: string, finding: unknown) => Promise<{
      success: boolean;
      ticket?: { ticketId: string; ticketUrl: string; status: string };
      error?: string;
    }>;
    createBulkTickets: (platform: string, findings: unknown[]) => Promise<{
      success: boolean;
      tickets?: Array<{ ticketId: string; ticketUrl: string }>;
      error?: string;
    }>;
    updateStatus: (platform: string, ticketId: string, status: string, comment?: string) => Promise<{ success: boolean; error?: string }>;
    getTicket: (platform: string, ticketId: string) => Promise<{ success: boolean; ticket?: unknown; error?: string }>;
    syncStatus: (platform: string, ticketId: string) => Promise<{ success: boolean; status?: string; error?: string }>;
    getPlatforms: () => Promise<string[]>;
  };
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
