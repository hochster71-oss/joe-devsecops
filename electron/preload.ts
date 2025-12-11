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

  // Auth operations
  auth: {
    login: (username: string, password: string) =>
      ipcRenderer.invoke('auth-login', username, password),
    logout: () => ipcRenderer.invoke('auth-logout'),
    getCurrentUser: () => ipcRenderer.invoke('auth-get-current-user'),
    changePassword: (oldPassword: string, newPassword: string) =>
      ipcRenderer.invoke('auth-change-password', oldPassword, newPassword)
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
    autoFix: () => ipcRenderer.invoke('security-auto-fix')
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
    login: (username: string, password: string) => Promise<{ success: boolean; user?: unknown; error?: string }>;
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
      riskScore: { overall: number; critical: number; high: number; medium: number; low: number; info: number };
      compliance: { framework: string; score: number; level: number; totalControls: number; compliant: number; partiallyCompliant: number; nonCompliant: number; notAssessed: number };
      sbomStats: { totalComponents: number; libraries: number; frameworks: number; vulnerableComponents: number; lastGenerated: string | null };
      findings: Array<{ id: string; title: string; severity: string; tool: string; timestamp: string; description?: string; remediation?: string; file?: string; line?: number }>;
      scanTime: string;
    }>;
    autoFix: () => Promise<{ success: boolean; fixed: string[]; failed: string[] }>;
  };
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
