/**
 * J.O.E. DevSecOps Arsenal - Electron API Type Declarations
 * Dark Wolf Solutions - Space-Grade Security Platform
 *
 * This file provides comprehensive type declarations for all
 * Electron IPC APIs exposed via contextBridge.
 */

// =============================================================================
// ELECTRON API TYPE DEFINITIONS
// =============================================================================

interface ElectronAPI {
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

  sbomBasic: {
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
    setModel: (model: string) => Promise<unknown>;
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
    runAudit: (namespace?: string) => Promise<unknown>;
    getPods: (namespace?: string) => Promise<unknown>;
    scanImages: (namespace?: string) => Promise<unknown>;
    analyzeRBAC: () => Promise<unknown>;
    checkPolicies: () => Promise<unknown>;
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
    getProject: (projectId: number) => Promise<unknown>;
    scanProject: (projectId: number) => Promise<unknown>;
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
    getKEVCatalog: (forceRefresh?: boolean) => Promise<unknown>;
    checkKEV: (cveId: string) => Promise<unknown>;
    getKEVStats: () => Promise<unknown>;
    searchKEV: (query: string) => Promise<unknown>;
    analyzeCVE: (cveId: string) => Promise<unknown>;
    analyzeCVEsBatch: (cveIds: string[]) => Promise<unknown>;
    clearCache: () => Promise<{ success: boolean }>;
  };

  sbom: {
    generate: (projectPath: string) => Promise<{
      bomFormat: string;
      specVersion: string;
      serialNumber: string;
      version: number;
      metadata: {
        timestamp: string;
        tools: { name: string; version: string }[];
        component?: { name: string; version: string; type: string };
      };
      components: Array<{
        name: string;
        version: string;
        type: string;
        purl?: string;
        licenses: string[];
        vulnerabilities?: { id: string; severity: string }[];
        riskScore?: number;
      }>;
    } | null>;
    analyze: (sbom: unknown) => Promise<{
      totalComponents: number;
      directDependencies: number;
      transitiveDependencies: number;
      licenseBreakdown: Record<string, number>;
      vulnerabilitySummary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        total: number;
      };
      riskScore: number;
      outdatedComponents: Array<{
        name: string;
        version: string;
        type: string;
        purl?: string;
        licenses: string[];
        vulnerabilities?: { id: string; severity: string }[];
        riskScore?: number;
      }>;
      licensingRisks: Array<{
        name: string;
        version: string;
        type: string;
        purl?: string;
        licenses: string[];
        vulnerabilities?: { id: string; severity: string }[];
        riskScore?: number;
      }>;
      recommendations: string[];
    } | null>;
    export: (sbom: unknown, format: 'json' | 'xml', outputPath: string) => Promise<{ success: boolean; filePath?: string; error?: string }>;
    selectProject: () => Promise<string | null>;
  };

  secretScanner: {
    scanDirectory: (dirPath: string, options?: unknown) => Promise<{
      scannedFiles: number;
      skippedFiles: number;
      findings: Array<{
        id: string;
        type: string;
        severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
        file: string;
        line: number;
        maskedMatch: string;
        description: string;
        recommendation: string;
        entropy?: number;
      }>;
      scanDuration: number;
      summary: { critical: number; high: number; medium: number; low: number; total: number };
    } | null>;
    scanContent: (content: string, filePath?: string) => Promise<Array<{
      type: string;
      line: number;
      severity: string;
      match: string;
    }>>;
    selectDirectory: () => Promise<string | null>;
  };

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
      metadata: {
        createdAt: string;
        updatedAt: string;
        sourceFile?: string;
        sourceLine?: number;
        description?: string;
        tags?: string[];
      };
    }>>;
    getStats: () => Promise<{
      totalEntries: number;
      byType: Record<string, number>;
      lastUpdated: string;
      vaultSize: number;
      isLocked: boolean;
    } | null>;
    changePassword: (currentPassword: string, newPassword: string) => Promise<{ success: boolean; error?: string }>;
    getAuditLog: () => Promise<Array<{
      timestamp: string;
      action: string;
      secretName?: string;
      success: boolean;
    }>>;
    export: () => Promise<{ success: boolean; filePath?: string; error?: string }>;
  };

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

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  iac: {
    scanDirectory: (path: string) => Promise<any>;
    scanFile: (path: string) => Promise<any[]>;
    getRules: () => Promise<any[]>;
    enableRule: (ruleId: string) => Promise<void>;
    disableRule: (ruleId: string) => Promise<void>;
    selectDirectory: () => Promise<string | null>;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  apiSecurity: {
    scanSpec: (filePath: string) => Promise<any>;
    scanDirectory: (dirPath: string) => Promise<any[]>;
    getOWASPTop10: () => Promise<any[]>;
    selectSpecFile: () => Promise<string | null>;
  };

  notifications: {
    getHistory: () => Promise<unknown[]>;
    getAlertRules: () => Promise<unknown[]>;
    createAlertRule: (rule: unknown) => Promise<void>;
    updateAlertRule: (id: string, updates: unknown) => Promise<void>;
    deleteAlertRule: (id: string) => Promise<void>;
    getChannelConfig: () => Promise<unknown>;
    updateChannelConfig: (channel: string, config: unknown) => Promise<void>;
    configureChannel: (channel: string, config: unknown) => Promise<{ success: boolean; error?: string }>;
    testChannel: (channel: string) => Promise<{ success: boolean; error?: string }>;
    send: (payload: unknown) => Promise<void>;
  };

  siem: {
    connect: (platform: string, config: unknown) => Promise<{ success: boolean; error?: string }>;
    disconnect: (platform: string) => Promise<void>;
    testConnection: (platform: string) => Promise<{ success: boolean; error?: string }>;
    configure: (platform: string, config: unknown) => Promise<{ success: boolean; error?: string }>;
  };

  ticketing: {
    connect: (platform: string, config: unknown) => Promise<{ success: boolean; error?: string }>;
    disconnect: (platform: string) => Promise<void>;
    testConnection: (platform: string) => Promise<{ success: boolean; error?: string }>;
    configure: (platform: string, config: unknown) => Promise<{ success: boolean; error?: string }>;
  };

  virtualSpaces: {
    getClusterStatus: () => Promise<{
      status: 'offline' | 'starting' | 'ready' | 'error' | 'not-installed';
      name: string;
      nodes: number;
      version?: string;
      error?: string;
    }>;
    initCluster: () => Promise<{
      status: 'offline' | 'starting' | 'ready' | 'error' | 'not-installed';
      name: string;
      nodes: number;
      version?: string;
      error?: string;
    }>;
    destroyCluster: () => Promise<void>;
    createSpace: (config: {
      name: string;
      owner: string;
      tier: 'team' | 'elevated' | 'admin';
      ttlMinutes?: number;
    }) => Promise<{
      id: string;
      name: string;
      owner: string;
      tier: 'team' | 'elevated' | 'admin';
      status: 'creating' | 'ready' | 'scanning' | 'importing' | 'exporting' | 'destroying' | 'destroyed' | 'error';
      namespace: string;
      createdAt: string;
      expiresAt: string;
      ttlMinutes: number;
      codeSource?: { type: 'git' | 'upload' | 'local'; url?: string; branch?: string; path?: string };
      scanResults?: {
        scanTime: string;
        findings: Array<{ id: string; title: string; severity: string; tool: string; description?: string; remediation?: string; file?: string; line?: number }>;
        summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
        passed: boolean;
      };
      error?: string;
    }>;
    destroySpace: (spaceId: string) => Promise<void>;
    listSpaces: () => Promise<Array<{
      id: string;
      name: string;
      owner: string;
      tier: 'team' | 'elevated' | 'admin';
      status: 'creating' | 'ready' | 'scanning' | 'importing' | 'exporting' | 'destroying' | 'destroyed' | 'error';
      namespace: string;
      createdAt: string;
      expiresAt: string;
      ttlMinutes: number;
      codeSource?: { type: 'git' | 'upload' | 'local'; url?: string; branch?: string; path?: string };
      scanResults?: {
        scanTime: string;
        findings: Array<{ id: string; title: string; severity: string; tool: string; description?: string; remediation?: string; file?: string; line?: number }>;
        summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
        passed: boolean;
      };
      error?: string;
    }>>;
    importCode: (spaceId: string, source: { type: 'git' | 'upload' | 'local'; url?: string; branch?: string; path?: string }) => Promise<{
      success: boolean;
      filesImported: number;
      path: string;
      error?: string;
    }>;
    exportArtifacts: (spaceId: string, artifacts: string[]) => Promise<{
      success: boolean;
      exportPath: string;
      artifacts: string[];
      error?: string;
    }>;
    scanSpace: (spaceId: string) => Promise<{
      scanTime: string;
      findings: Array<{ id: string; title: string; severity: string; tool: string; description?: string; remediation?: string; file?: string; line?: number }>;
      summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
      passed: boolean;
    }>;
    extendSpace: (spaceId: string, additionalMinutes: number) => Promise<{
      id: string;
      name: string;
      owner: string;
      tier: 'team' | 'elevated' | 'admin';
      status: 'creating' | 'ready' | 'scanning' | 'importing' | 'exporting' | 'destroying' | 'destroyed' | 'error';
      namespace: string;
      createdAt: string;
      expiresAt: string;
      ttlMinutes: number;
    }>;
    getTiers: () => Promise<Record<'team' | 'elevated' | 'admin', {
      name: string;
      description: string;
      pssLevel: 'restricted' | 'baseline' | 'privileged';
      networkPolicy: 'deny-all' | 'limited-egress' | 'allow-all';
      resourceQuota: { cpu: string; memory: string; pods: number };
      allowPrivileged: boolean;
      allowHostPath: boolean;
      allowedOwners?: string[];
    }>>;
    canCreateTier: (tier: 'team' | 'elevated' | 'admin', owner: string) => Promise<boolean>;
  };

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
}

// =============================================================================
// GLOBAL WINDOW TYPE AUGMENTATION
// =============================================================================

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}

// Needed to make this file a module
export {};
