import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Search,
  Filter,
  Download,
  RefreshCw,
  AlertTriangle,
  AlertCircle,
  Info,
  ChevronDown,
  ExternalLink,
  Shield,
  Bug,
  Clock,
  FileCode,
  CheckCircle,
  XCircle,
  Target,
  Zap,
  Bot,
  Sparkles,
  Wand2,
  Copy,
  Play,
  Terminal,
  BookOpen
} from 'lucide-react';
import Modal from '../components/common/Modal';

/**
 * Security Findings View - J.O.E. DevSecOps Platform
 *
 * Comprehensive vulnerability management with:
 * - Real-time filtering and search
 * - CVSS/EPSS scoring visualization
 * - CVE/CWE reference integration
 * - Detailed remediation guidance
 *
 * Reference: OWASP Vulnerability Management Guide
 * https://owasp.org/www-project-vulnerability-management-guide/
 */

interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  tool: string;
  file: string;
  line: number;
  cweId?: string;
  cveId?: string;
  description: string;
  recommendation: string;
  timestamp: string;
  status: 'open' | 'investigating' | 'resolved' | 'false-positive';
  cvss?: number;
  epss?: number;
  affectedVersions?: string;
  fixedVersion?: string;
  references?: string[];
}

interface AiFix {
  explanation: string;
  steps: string[];
  codeChanges: {
    file: string;
    before: string;
    after: string;
    language: string;
  }[];
  commands?: string[];
  autoFixAvailable: boolean;
  confidence: number;
  estimatedEffort: 'low' | 'medium' | 'high';
}

// AI-generated fixes for each finding
const aiFixes: Record<string, AiFix> = {
  '1': { // Hardcoded credentials
    explanation: 'J.O.E. detected hardcoded development credentials in the authentication store. These must be removed and replaced with a secure credential management system before production deployment.',
    steps: [
      'Remove hardcoded MOCK_USERS array from authStore.ts',
      'Integrate with enterprise identity provider (LDAP/SSO)',
      'Implement secure session management with electron-store',
      'Add environment-based configuration for auth endpoints'
    ],
    codeChanges: [
      {
        file: 'src/renderer/store/authStore.ts',
        language: 'typescript',
        before: `const MOCK_USERS = [
  { username: 'mhoch', password: 'admin123', role: 'admin' },
  { username: 'jscholer', password: 'user123', role: 'user' }
];`,
        after: `// Remove hardcoded credentials - integrate with SSO
import { ipcRenderer } from 'electron';

const authenticateUser = async (credentials: LoginCredentials) => {
  return await ipcRenderer.invoke('auth:login', credentials);
};`
      }
    ],
    commands: ['npm install electron-store', 'npm install @azure/identity'],
    autoFixAvailable: false,
    confidence: 0.95,
    estimatedEffort: 'medium'
  },
  '2': { // nodeIntegration enabled
    explanation: 'J.O.E. recommends disabling nodeIntegration to follow Electron security best practices. This prevents renderer processes from accessing Node.js APIs directly, reducing attack surface.',
    steps: [
      'Disable nodeIntegration in BrowserWindow webPreferences',
      'Enable contextIsolation for secure IPC',
      'Create preload script for safe API exposure',
      'Update renderer code to use exposed APIs'
    ],
    codeChanges: [
      {
        file: 'src/main.ts',
        language: 'typescript',
        before: `webPreferences: {
  nodeIntegration: true,
  contextIsolation: false,
  preload: path.join(__dirname, 'preload.js')
}`,
        after: `webPreferences: {
  nodeIntegration: false,
  contextIsolation: true,
  sandbox: true,
  preload: path.join(__dirname, 'preload.js'),
  webSecurity: true
}`
      },
      {
        file: 'src/preload.ts',
        language: 'typescript',
        before: '// No preload script',
        after: `import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('electronAPI', {
  invoke: (channel: string, ...args: unknown[]) => {
    const validChannels = ['scan:run', 'sbom:generate', 'ai:query'];
    if (validChannels.includes(channel)) {
      return ipcRenderer.invoke(channel, ...args);
    }
    throw new Error(\`Invalid channel: \${channel}\`);
  }
});`
      }
    ],
    autoFixAvailable: true,
    confidence: 0.92,
    estimatedEffort: 'medium'
  },
  '3': { // Ollama endpoint validation
    explanation: 'J.O.E. identified that the Ollama API endpoint should be validated to prevent SSRF attacks. Add URL validation and implement an allowlist of permitted hosts.',
    steps: [
      'Add URL validation function for Ollama endpoint',
      'Implement host allowlist (localhost only by default)',
      'Add request timeout and response size limits',
      'Move endpoint configuration to settings'
    ],
    codeChanges: [
      {
        file: 'src/services/ollamaService.ts',
        language: 'typescript',
        before: `const OLLAMA_ENDPOINT = 'http://localhost:11434';

export async function queryOllama(prompt: string) {
  const response = await fetch(\`\${OLLAMA_ENDPOINT}/api/generate\`);
  // ...
}`,
        after: `const ALLOWED_HOSTS = ['localhost', '127.0.0.1'];
const OLLAMA_ENDPOINT = process.env.OLLAMA_ENDPOINT || 'http://localhost:11434';

function validateEndpoint(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ALLOWED_HOSTS.includes(parsed.hostname);
  } catch {
    return false;
  }
}

export async function queryOllama(prompt: string) {
  if (!validateEndpoint(OLLAMA_ENDPOINT)) {
    throw new Error('Invalid Ollama endpoint');
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  const response = await fetch(\`\${OLLAMA_ENDPOINT}/api/generate\`, {
    signal: controller.signal
  });
  clearTimeout(timeout);
  // ...
}`
      }
    ],
    autoFixAvailable: true,
    confidence: 0.88,
    estimatedEffort: 'low'
  },
  '4': { // Missing CSP
    explanation: 'J.O.E. recommends adding a Content Security Policy to prevent XSS attacks. This restricts which resources can be loaded and executed.',
    steps: [
      'Define CSP directives in main process',
      'Configure session webRequest handler',
      'Add CSP meta tag as fallback',
      'Test with strict CSP to identify violations'
    ],
    codeChanges: [
      {
        file: 'src/main.ts',
        language: 'typescript',
        before: `// No CSP configured`,
        after: `import { session } from 'electron';

// Configure Content Security Policy
session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      ...details.responseHeaders,
      'Content-Security-Policy': [
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "connect-src 'self' http://localhost:11434"
      ]
    }
  });
});`
      }
    ],
    autoFixAvailable: true,
    confidence: 0.90,
    estimatedEffort: 'low'
  },
  '5': { // Insecure state persistence
    explanation: 'Zustand state should be encrypted when persisting sensitive data. Use electron-store with encryption for secure persistence.',
    steps: [
      'Install electron-store for encrypted storage',
      'Configure Zustand persist middleware with electron-store',
      'Clear sensitive state on logout',
      'Add session timeout handling'
    ],
    codeChanges: [
      {
        file: 'src/renderer/store/authStore.ts',
        language: 'typescript',
        before: `export const useAuthStore = create<AuthStore>((set) => ({
  user: null,
  // ...
}));`,
        after: `import { persist } from 'zustand/middleware';

export const useAuthStore = create<AuthStore>()(
  persist(
    (set) => ({
      user: null,
      // ...
      logout: () => {
        set({ user: null, isAuthenticated: false });
        sessionStorage.clear();
      }
    }),
    {
      name: 'joe-auth',
      storage: createSecureStorage(), // Uses electron-store
      partialize: (state) => ({ user: state.user }) // Only persist non-sensitive
    }
  )
);`
      }
    ],
    commands: ['npm install electron-store'],
    autoFixAvailable: false,
    confidence: 0.85,
    estimatedEffort: 'medium'
  },
  '6': { // Console logging
    explanation: 'Development console.log statements should be removed or disabled in production to prevent information leakage.',
    steps: [
      'Install a proper logging library (winston or pino)',
      'Configure log levels based on environment',
      'Replace console.log with logger calls',
      'Add log rotation for production'
    ],
    codeChanges: [
      {
        file: 'src/renderer/views/AiAssistantView.tsx',
        language: 'typescript',
        before: `console.log('User message:', message);
console.log('AI response:', response);`,
        after: `import { logger } from '../utils/logger';

// Only log in development
if (process.env.NODE_ENV === 'development') {
  logger.debug('AI interaction', { messageLength: message.length });
}`
      }
    ],
    commands: ['npm install winston'],
    autoFixAvailable: true,
    confidence: 0.95,
    estimatedEffort: 'low'
  },
  '7': { // External link handling
    explanation: 'External URLs should be validated before opening to prevent open redirect attacks. Use Electron shell.openExternal with proper validation.',
    steps: [
      'Create URL validation utility',
      'Implement domain allowlist for external links',
      'Use shell.openExternal via IPC',
      'Add user confirmation for unknown domains'
    ],
    codeChanges: [
      {
        file: 'src/renderer/utils/externalLinks.ts',
        language: 'typescript',
        before: `// Direct window.open usage
<a href={url} target="_blank">`,
        after: `const ALLOWED_DOMAINS = [
  'attack.mitre.org',
  'nvd.nist.gov',
  'cwe.mitre.org',
  'owasp.org'
];

export function openExternalLink(url: string): void {
  try {
    const parsed = new URL(url);
    if (ALLOWED_DOMAINS.some(d => parsed.hostname.endsWith(d))) {
      window.electronAPI.invoke('shell:openExternal', url);
    } else {
      console.warn('Blocked external link:', url);
    }
  } catch {
    console.error('Invalid URL:', url);
  }
}`
      }
    ],
    autoFixAvailable: true,
    confidence: 0.87,
    estimatedEffort: 'low'
  },
  '8': { // XSS in AI chat
    explanation: 'AI responses should be sanitized before rendering to prevent XSS attacks. Use DOMPurify for safe HTML rendering.',
    steps: [
      'Install DOMPurify for HTML sanitization',
      'Sanitize all AI responses before rendering',
      'Use markdown renderer with XSS protection',
      'Add input validation for user messages'
    ],
    codeChanges: [
      {
        file: 'src/renderer/views/AiAssistantView.tsx',
        language: 'typescript',
        before: `<div dangerouslySetInnerHTML={{ __html: response }} />`,
        after: `import DOMPurify from 'dompurify';
import { marked } from 'marked';

const sanitizedHtml = DOMPurify.sanitize(
  marked.parse(response),
  { ALLOWED_TAGS: ['p', 'code', 'pre', 'strong', 'em', 'ul', 'li', 'ol'] }
);

<div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />`
      }
    ],
    commands: ['npm install dompurify @types/dompurify marked'],
    autoFixAvailable: true,
    confidence: 0.93,
    estimatedEffort: 'low'
  }
};

// J.O.E. Self-Assessment Findings
// These findings are from scanning the J.O.E. DevSecOps Arsenal codebase itself
const mockFindings: Finding[] = [
  {
    id: '1',
    title: 'Hardcoded credentials in authentication store',
    severity: 'critical',
    tool: 'GitGuardian',
    file: 'src/renderer/store/authStore.ts',
    line: 15,
    cweId: 'CWE-798',
    description: 'Development credentials (mhoch/admin123, jscholer/user123) are hardcoded in the authentication store. These should be removed before production deployment.',
    recommendation: 'Remove hardcoded credentials. Implement secure credential storage using electron-store with encryption or integrate with enterprise SSO/LDAP.',
    timestamp: new Date(Date.now() - 1800000).toISOString(),
    status: 'open',
    cvss: 9.1,
    epss: 0.85,
    references: ['https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password']
  },
  {
    id: '2',
    title: 'Electron nodeIntegration enabled',
    severity: 'high',
    tool: 'Semgrep',
    file: 'src/main.ts',
    line: 28,
    cweId: 'CWE-94',
    description: 'nodeIntegration is enabled in BrowserWindow webPreferences. This allows renderer processes to access Node.js APIs, increasing attack surface.',
    recommendation: 'Disable nodeIntegration and use contextIsolation with preload scripts for IPC communication. Follow Electron security best practices.',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    status: 'investigating',
    cvss: 7.5,
    epss: 0.62,
    references: ['https://www.electronjs.org/docs/latest/tutorial/security']
  },
  {
    id: '3',
    title: 'Ollama API endpoint not validated',
    severity: 'medium',
    tool: 'CodeQL',
    file: 'src/services/ollamaService.ts',
    line: 12,
    cweId: 'CWE-918',
    description: 'The Ollama API endpoint (localhost:11434) is hardcoded without proper validation. SSRF attacks possible if endpoint is user-configurable.',
    recommendation: 'Validate Ollama endpoint URL. Implement allowlist for permitted hosts. Add request timeout and size limits.',
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    status: 'open',
    cvss: 5.3,
    epss: 0.28,
    references: ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery']
  },
  {
    id: '4',
    title: 'Missing Content Security Policy',
    severity: 'medium',
    tool: 'Trivy',
    file: 'src/main.ts',
    line: 1,
    cweId: 'CWE-693',
    description: 'Electron app does not define a Content Security Policy. This makes the application vulnerable to XSS attacks.',
    recommendation: 'Add CSP meta tag or configure session.defaultSession.webRequest to enforce Content Security Policy.',
    timestamp: new Date(Date.now() - 10800000).toISOString(),
    status: 'open',
    cvss: 5.4,
    epss: 0.15,
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
  },
  {
    id: '5',
    title: 'Zustand store not persisted securely',
    severity: 'low',
    tool: 'Semgrep',
    file: 'src/renderer/store/dashboardStore.ts',
    line: 8,
    cweId: 'CWE-922',
    description: 'Application state including user session data may be stored insecurely in memory or localStorage.',
    recommendation: 'Use electron-store with encryption for sensitive data persistence. Clear sensitive state on logout.',
    timestamp: new Date(Date.now() - 14400000).toISOString(),
    status: 'resolved',
    cvss: 3.7,
    epss: 0.08
  },
  {
    id: '6',
    title: 'Development console logging enabled',
    severity: 'low',
    tool: 'Semgrep',
    file: 'src/renderer/views/AiAssistantView.tsx',
    line: 45,
    cweId: 'CWE-532',
    description: 'Console.log statements may leak sensitive information in production builds. User inputs and AI responses are logged.',
    recommendation: 'Remove or disable console.log in production. Use a logging library with log levels (debug, info, warn, error).',
    timestamp: new Date(Date.now() - 18000000).toISOString(),
    status: 'open',
    cvss: 2.4,
    epss: 0.03
  },
  {
    id: '7',
    title: 'Insecure external link handling',
    severity: 'medium',
    tool: 'CodeQL',
    file: 'src/renderer/components/charts/MitreHeatmap.tsx',
    line: 180,
    cweId: 'CWE-601',
    description: 'External links (attack.mitre.org) open without validation. Potential for open redirect if URLs are dynamically generated.',
    recommendation: 'Validate external URLs before opening. Use shell.openExternal with proper validation in Electron.',
    timestamp: new Date(Date.now() - 21600000).toISOString(),
    status: 'investigating',
    cvss: 4.7,
    epss: 0.12
  },
  {
    id: '8',
    title: 'Missing input sanitization in AI chat',
    severity: 'high',
    tool: 'Snyk',
    file: 'src/renderer/views/AiAssistantView.tsx',
    line: 78,
    cweId: 'CWE-79',
    description: 'User messages sent to Ollama AI are not sanitized. AI responses rendered with dangerouslySetInnerHTML could execute malicious scripts.',
    recommendation: 'Sanitize AI responses with DOMPurify before rendering. Implement markdown-safe rendering.',
    timestamp: new Date(Date.now() - 25200000).toISOString(),
    status: 'open',
    cvss: 6.8,
    epss: 0.35,
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html']
  }
];

export default function FindingsView() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isExporting, setIsExporting] = useState(false);

  // AI Fix states
  const [showAiFix, setShowAiFix] = useState(false);
  const [isGeneratingFix, setIsGeneratingFix] = useState(false);
  const [currentAiFix, setCurrentAiFix] = useState<AiFix | null>(null);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [isApplyingFix, setIsApplyingFix] = useState(false);
  const [fixApplied, setFixApplied] = useState(false);

  const filteredFindings = mockFindings.filter(finding => {
    const matchesSearch = finding.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.file.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.tool.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = selectedSeverity === 'all' || finding.severity === selectedSeverity;
    const matchesStatus = selectedStatus === 'all' || finding.status === selectedStatus;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const getSeverityConfig = (severity: string) => {
    switch (severity) {
      case 'critical':
        return { icon: AlertTriangle, color: 'text-alert-critical', bg: 'bg-alert-critical/10', border: 'border-alert-critical/30' };
      case 'high':
        return { icon: AlertCircle, color: 'text-alert-high', bg: 'bg-alert-high/10', border: 'border-alert-high/30' };
      case 'medium':
        return { icon: AlertCircle, color: 'text-alert-warning', bg: 'bg-alert-warning/10', border: 'border-alert-warning/30' };
      default:
        return { icon: Info, color: 'text-dws-green', bg: 'bg-dws-green/10', border: 'border-dws-green/30' };
    }
  };

  const getStatusConfig = (status: string) => {
    switch (status) {
      case 'open':
        return { icon: AlertCircle, color: 'text-alert-critical', bg: 'bg-alert-critical/10' };
      case 'investigating':
        return { icon: Clock, color: 'text-alert-warning', bg: 'bg-alert-warning/10' };
      case 'resolved':
        return { icon: CheckCircle, color: 'text-dws-green', bg: 'bg-dws-green/10' };
      case 'false-positive':
        return { icon: XCircle, color: 'text-gray-500', bg: 'bg-gray-500/10' };
      default:
        return { icon: AlertCircle, color: 'text-gray-500', bg: 'bg-gray-500/10' };
    }
  };

  const handleExport = async () => {
    setIsExporting(true);
    await new Promise(resolve => setTimeout(resolve, 1500));
    setIsExporting(false);
  };

  const severityCounts = {
    critical: mockFindings.filter(f => f.severity === 'critical').length,
    high: mockFindings.filter(f => f.severity === 'high').length,
    medium: mockFindings.filter(f => f.severity === 'medium').length,
    low: mockFindings.filter(f => f.severity === 'low').length
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-2xl font-bold text-white flex items-center gap-3">
            <Bug className="text-joe-blue" />
            Security Findings
          </h1>
          <p className="text-gray-400 mt-1">Review and remediate security vulnerabilities</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleExport}
            disabled={isExporting}
            className="btn-secondary flex items-center gap-2"
            type="button"
          >
            <Download size={16} className={isExporting ? 'animate-bounce' : ''} />
            {isExporting ? 'Exporting...' : 'Export'}
          </button>
          <button className="btn-primary flex items-center gap-2" type="button">
            <RefreshCw size={16} />
            Rescan
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="glass-card p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="relative flex-1 min-w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
            <input
              type="text"
              placeholder="Search findings by title, file, or tool..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input-field pl-10"
            />
          </div>

          <div className="flex items-center gap-2">
            <Filter size={18} className="text-gray-500" />
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="input-field w-auto"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical ({severityCounts.critical})</option>
              <option value="high">High ({severityCounts.high})</option>
              <option value="medium">Medium ({severityCounts.medium})</option>
              <option value="low">Low ({severityCounts.low})</option>
            </select>
          </div>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="input-field w-auto"
            aria-label="Filter by status"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false-positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Stats Summary - Clickable */}
      <div className="grid grid-cols-4 gap-4">
        {(['critical', 'high', 'medium', 'low'] as const).map(severity => {
          const count = severityCounts[severity];
          const config = getSeverityConfig(severity);
          const Icon = config.icon;
          return (
            <button
              key={severity}
              onClick={() => setSelectedSeverity(selectedSeverity === severity ? 'all' : severity)}
              className={`glass-card p-4 ${config.bg} border ${config.border} transition-all hover:scale-105 ${
                selectedSeverity === severity ? 'ring-2 ring-joe-blue' : ''
              }`}
              type="button"
            >
              <div className="flex items-center gap-2 mb-1">
                <Icon size={16} className={config.color} />
                <span className={`text-xs uppercase font-medium ${config.color}`}>{severity}</span>
              </div>
              <p className={`text-2xl font-bold ${config.color}`}>{count}</p>
            </button>
          );
        })}
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <div className="glass-card p-8 text-center">
            <Shield className="mx-auto text-dws-green mb-4" size={48} />
            <p className="text-white font-medium">No findings match your criteria</p>
            <p className="text-gray-500 text-sm mt-1">Try adjusting your filters</p>
          </div>
        ) : (
          filteredFindings.map((finding, index) => {
            const config = getSeverityConfig(finding.severity);
            const statusConfig = getStatusConfig(finding.status);
            const Icon = config.icon;
            const isExpanded = expandedFinding === finding.id;

            return (
              <motion.div
                key={finding.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                className={`glass-card overflow-hidden ${config.border} border`}
              >
                <button
                  onClick={() => setExpandedFinding(isExpanded ? null : finding.id)}
                  className="w-full p-4 flex items-center gap-4 text-left hover:bg-dws-card/30 transition-colors"
                  type="button"
                >
                  <div className={`p-2 rounded-lg ${config.bg}`}>
                    <Icon size={20} className={config.color} />
                  </div>

                  <div className="flex-1 min-w-0">
                    <p className="text-white font-medium truncate">{finding.title}</p>
                    <div className="flex items-center gap-3 mt-1 text-sm">
                      <span className={`uppercase font-medium ${config.color}`}>{finding.severity}</span>
                      <span className="text-gray-500">{finding.tool}</span>
                      <span className="text-gray-600 font-mono text-xs">{finding.file}:{finding.line}</span>
                      <span className={`px-2 py-0.5 rounded-full text-xs ${statusConfig.bg} ${statusConfig.color}`}>
                        {finding.status}
                      </span>
                    </div>
                  </div>

                  {finding.cvss && (
                    <div className="text-right mr-4">
                      <p className={`text-lg font-bold ${finding.cvss >= 9 ? 'text-alert-critical' : finding.cvss >= 7 ? 'text-alert-high' : finding.cvss >= 4 ? 'text-alert-warning' : 'text-dws-green'}`}>
                        {finding.cvss}
                      </p>
                      <p className="text-xs text-gray-500">CVSS</p>
                    </div>
                  )}

                  <ChevronDown
                    size={20}
                    className={`text-gray-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                  />
                </button>

                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="border-t border-dws-border p-4 bg-dws-dark/50"
                  >
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-gray-500 text-sm mb-1">Description</p>
                        <p className="text-gray-300">{finding.description}</p>
                      </div>
                      <div>
                        <p className="text-gray-500 text-sm mb-1">Recommendation</p>
                        <p className="text-gray-300">{finding.recommendation}</p>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 mt-4 pt-4 border-t border-dws-border">
                      {finding.cveId && (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${finding.cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-joe-blue text-sm flex items-center gap-1 hover:underline"
                        >
                          {finding.cveId} <ExternalLink size={12} />
                        </a>
                      )}
                      {finding.cweId && (
                        <a
                          href={`https://cwe.mitre.org/data/definitions/${finding.cweId.replace('CWE-', '')}.html`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-gray-400 text-sm flex items-center gap-1 hover:text-joe-blue"
                        >
                          {finding.cweId} <ExternalLink size={12} />
                        </a>
                      )}
                      <button
                        onClick={() => setSelectedFinding(finding)}
                        className="ml-auto btn-secondary text-sm py-1.5"
                        type="button"
                      >
                        View Details
                      </button>
                      <button className="btn-primary text-sm py-1.5" type="button">
                        Mark as Resolved
                      </button>
                    </div>
                  </motion.div>
                )}
              </motion.div>
            );
          })
        )}
      </div>

      {/* Finding Detail Modal */}
      <Modal
        isOpen={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
        title={selectedFinding?.title}
        subtitle={`${selectedFinding?.tool} | ${selectedFinding?.file}:${selectedFinding?.line}`}
        size="xl"
        headerIcon={<Bug size={24} />}
        variant={selectedFinding?.severity === 'critical' ? 'critical' : selectedFinding?.severity === 'high' ? 'warning' : 'info'}
        footer={
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-3">
              {selectedFinding?.cveId && (
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${selectedFinding.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-joe-blue text-sm flex items-center gap-1 hover:underline"
                >
                  {selectedFinding.cveId} <ExternalLink size={14} />
                </a>
              )}
              {selectedFinding?.cweId && (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${selectedFinding.cweId.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-gray-400 text-sm flex items-center gap-1 hover:text-joe-blue"
                >
                  {selectedFinding.cweId} <ExternalLink size={14} />
                </a>
              )}
            </div>
            <div className="flex items-center gap-3">
              <button className="btn-secondary" type="button" onClick={() => setSelectedFinding(null)}>
                Close
              </button>
              <button className="btn-primary" type="button">
                Mark as Resolved
              </button>
            </div>
          </div>
        }
      >
        {selectedFinding && (
          <div className="space-y-6">
            {/* Severity & Score Cards */}
            <div className="grid grid-cols-4 gap-4">
              <div className={`glass-card p-4 ${getSeverityConfig(selectedFinding.severity).bg} border ${getSeverityConfig(selectedFinding.severity).border}`}>
                <Target className={getSeverityConfig(selectedFinding.severity).color} size={20} />
                <p className="text-gray-400 text-sm mt-2">Severity</p>
                <p className={`text-xl font-bold uppercase ${getSeverityConfig(selectedFinding.severity).color}`}>
                  {selectedFinding.severity}
                </p>
              </div>
              {selectedFinding.cvss && (
                <div className="glass-card p-4">
                  <Zap className="text-alert-warning" size={20} />
                  <p className="text-gray-400 text-sm mt-2">CVSS Score</p>
                  <p className={`text-xl font-bold ${selectedFinding.cvss >= 9 ? 'text-alert-critical' : selectedFinding.cvss >= 7 ? 'text-alert-high' : 'text-alert-warning'}`}>
                    {selectedFinding.cvss}/10
                  </p>
                </div>
              )}
              {selectedFinding.epss && (
                <div className="glass-card p-4">
                  <AlertTriangle className="text-joe-blue" size={20} />
                  <p className="text-gray-400 text-sm mt-2">EPSS Score</p>
                  <p className="text-xl font-bold text-joe-blue">
                    {(selectedFinding.epss * 100).toFixed(1)}%
                  </p>
                </div>
              )}
              <div className={`glass-card p-4 ${getStatusConfig(selectedFinding.status).bg}`}>
                <Clock className={getStatusConfig(selectedFinding.status).color} size={20} />
                <p className="text-gray-400 text-sm mt-2">Status</p>
                <p className={`text-xl font-bold capitalize ${getStatusConfig(selectedFinding.status).color}`}>
                  {selectedFinding.status}
                </p>
              </div>
            </div>

            {/* Location */}
            <div>
              <h4 className="font-semibold text-white mb-2 flex items-center gap-2">
                <FileCode size={16} className="text-joe-blue" />
                Affected Location
              </h4>
              <div className="p-3 bg-dws-dark rounded-lg font-mono text-sm">
                <span className="text-gray-500">File: </span>
                <span className="text-joe-blue">{selectedFinding.file}</span>
                <span className="text-gray-500 ml-4">Line: </span>
                <span className="text-alert-warning">{selectedFinding.line}</span>
              </div>
            </div>

            {/* Description */}
            <div>
              <h4 className="font-semibold text-white mb-2">Description</h4>
              <p className="text-gray-300">{selectedFinding.description}</p>
            </div>

            {/* Recommendation */}
            <div>
              <h4 className="font-semibold text-white mb-2 flex items-center gap-2">
                <CheckCircle size={16} className="text-dws-green" />
                Recommended Fix
              </h4>
              <div className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg">
                <p className="text-gray-300">{selectedFinding.recommendation}</p>
              </div>
            </div>

            {/* Version Info */}
            {(selectedFinding.affectedVersions || selectedFinding.fixedVersion) && (
              <div className="grid grid-cols-2 gap-4">
                {selectedFinding.affectedVersions && (
                  <div>
                    <h4 className="font-semibold text-white mb-2">Affected Versions</h4>
                    <p className="text-alert-critical font-mono">{selectedFinding.affectedVersions}</p>
                  </div>
                )}
                {selectedFinding.fixedVersion && (
                  <div>
                    <h4 className="font-semibold text-white mb-2">Fixed Version</h4>
                    <p className="text-dws-green font-mono">{selectedFinding.fixedVersion}</p>
                  </div>
                )}
              </div>
            )}

            {/* References */}
            {selectedFinding.references && selectedFinding.references.length > 0 && (
              <div>
                <h4 className="font-semibold text-white mb-2">References</h4>
                <div className="space-y-2">
                  {selectedFinding.references.map((ref, i) => (
                    <a
                      key={i}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-joe-blue text-sm hover:underline truncate"
                    >
                      <ExternalLink size={12} className="inline mr-2" />
                      {ref}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Timeline */}
            <div>
              <h4 className="font-semibold text-white mb-2">Detection Timeline</h4>
              <div className="flex items-center gap-3 text-sm text-gray-400">
                <div className="w-2 h-2 rounded-full bg-joe-blue" />
                <span>Detected: {new Date(selectedFinding.timestamp).toLocaleString()}</span>
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
