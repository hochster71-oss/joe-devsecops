/**
 * Global type declarations for Electron API
 * Exposes the preload script's electronAPI to the renderer
 */

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
    login: (username: string, password: string) => Promise<{ success: boolean; user?: unknown; token?: string; error?: string }>;
    logout: () => Promise<void>;
    getCurrentUser: () => Promise<unknown | null>;
    changePassword: (oldPassword: string, newPassword: string) => Promise<{ success: boolean; error?: string }>;
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
      riskScore: {
        overall: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
      };
      compliance: {
        framework: string;
        score: number;
        level: number;
        totalControls: number;
        compliant: number;
        partiallyCompliant: number;
        nonCompliant: number;
        notAssessed: number;
      };
      sbomStats: {
        totalComponents: number;
        libraries: number;
        frameworks: number;
        vulnerableComponents: number;
        lastGenerated: string | null;
      };
      findings: Array<{
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
      scanTime: string;
    }>;
    autoFix: () => Promise<{ success: boolean; fixed: string[]; failed: string[] }>;
  };
}

declare global {
  interface Window {
    electronAPI?: ElectronAPI;
  }
}

export {};
