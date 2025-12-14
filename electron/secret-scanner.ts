/**
 * J.O.E. Secret Scanner Service
 *
 * Detects hardcoded secrets, API keys, passwords, and sensitive data in code
 * Based on patterns from TruffleHog, GitLeaks, and custom enterprise patterns
 */

import * as fs from 'fs';
import * as path from 'path';

// ========================================
// SECRET DETECTION INTERFACES
// ========================================

export interface SecretFinding {
  id: string;
  type: SecretType;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  file: string;
  line: number;
  column: number;
  match: string;
  maskedMatch: string;
  context: string;
  description: string;
  recommendation: string;
  entropy?: number;
  verified?: boolean;
}

export type SecretType =
  | 'AWS_ACCESS_KEY'
  | 'AWS_SECRET_KEY'
  | 'AZURE_CLIENT_SECRET'
  | 'GCP_SERVICE_ACCOUNT'
  | 'GITHUB_TOKEN'
  | 'GITLAB_TOKEN'
  | 'SLACK_TOKEN'
  | 'SLACK_WEBHOOK'
  | 'JWT_SECRET'
  | 'PRIVATE_KEY'
  | 'API_KEY'
  | 'DATABASE_URL'
  | 'PASSWORD'
  | 'BEARER_TOKEN'
  | 'BASIC_AUTH'
  | 'SSH_KEY'
  | 'STRIPE_KEY'
  | 'TWILIO_KEY'
  | 'SENDGRID_KEY'
  | 'NPM_TOKEN'
  | 'DOCKER_AUTH'
  | 'KUBERNETES_SECRET'
  | 'GENERIC_SECRET'
  | 'HIGH_ENTROPY';

export interface SecretPattern {
  type: SecretType;
  name: string;
  pattern: RegExp;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
}

export interface ScanResult {
  scannedFiles: number;
  skippedFiles: number;
  findings: SecretFinding[];
  scanDuration: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  byType: Record<SecretType, number>;
}

// ========================================
// SECRET PATTERNS DATABASE
// ========================================

const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  {
    type: 'AWS_ACCESS_KEY',
    name: 'AWS Access Key ID',
    pattern: /(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])/g,
    severity: 'CRITICAL',
    description: 'AWS Access Key ID detected',
    recommendation: 'Rotate the AWS access key immediately and use IAM roles or AWS Secrets Manager'
  },
  {
    type: 'AWS_SECRET_KEY',
    name: 'AWS Secret Access Key',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    severity: 'CRITICAL',
    description: 'Potential AWS Secret Access Key detected',
    recommendation: 'Rotate the AWS secret key immediately and use environment variables or secrets manager'
  },

  // Azure
  {
    type: 'AZURE_CLIENT_SECRET',
    name: 'Azure Client Secret',
    pattern: /(?:client[_-]?secret|azure[_-]?secret)['":\s]*[=:]\s*['"]?([a-zA-Z0-9~._-]{34,40})['"]?/gi,
    severity: 'CRITICAL',
    description: 'Azure Client Secret detected',
    recommendation: 'Rotate the Azure client secret and use Azure Key Vault'
  },

  // GCP
  {
    type: 'GCP_SERVICE_ACCOUNT',
    name: 'GCP Service Account Key',
    pattern: /"type"\s*:\s*"service_account"/g,
    severity: 'CRITICAL',
    description: 'GCP Service Account JSON key file detected',
    recommendation: 'Remove service account key and use Workload Identity or Secret Manager'
  },

  // GitHub
  {
    type: 'GITHUB_TOKEN',
    name: 'GitHub Token',
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
    severity: 'CRITICAL',
    description: 'GitHub Personal Access Token detected',
    recommendation: 'Revoke the token immediately and use fine-grained PATs with minimal scope'
  },

  // GitLab
  {
    type: 'GITLAB_TOKEN',
    name: 'GitLab Token',
    pattern: /glpat-[A-Za-z0-9_-]{20,}/g,
    severity: 'CRITICAL',
    description: 'GitLab Personal Access Token detected',
    recommendation: 'Revoke the token and use project/group access tokens with minimal scope'
  },

  // Slack
  {
    type: 'SLACK_TOKEN',
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    severity: 'HIGH',
    description: 'Slack API Token detected',
    recommendation: 'Rotate the Slack token and restrict its permissions'
  },
  {
    type: 'SLACK_WEBHOOK',
    name: 'Slack Webhook URL',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24}/g,
    severity: 'MEDIUM',
    description: 'Slack Webhook URL detected',
    recommendation: 'Regenerate the webhook URL and store it in environment variables'
  },

  // JWT
  {
    type: 'JWT_SECRET',
    name: 'JWT Secret',
    pattern: /(?:jwt[_-]?secret|jwt[_-]?key|secret[_-]?key)['":\s]*[=:]\s*['"]?([a-zA-Z0-9!@#$%^&*()_+-=]{16,})['"]?/gi,
    severity: 'CRITICAL',
    description: 'JWT Secret key detected',
    recommendation: 'Rotate the JWT secret immediately and use a secrets manager'
  },

  // Private Keys
  {
    type: 'PRIVATE_KEY',
    name: 'Private Key',
    pattern: /-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY( BLOCK)?-----/g,
    severity: 'CRITICAL',
    description: 'Private key detected in source code',
    recommendation: 'Remove private key from code and use a key management service'
  },
  {
    type: 'SSH_KEY',
    name: 'SSH Private Key',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    severity: 'CRITICAL',
    description: 'SSH private key detected',
    recommendation: 'Remove SSH key and use SSH certificate-based authentication'
  },

  // API Keys (Generic)
  {
    type: 'API_KEY',
    name: 'Generic API Key',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)['":\s]*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
    severity: 'HIGH',
    description: 'API key detected',
    recommendation: 'Remove API key from code and use environment variables or secrets manager'
  },

  // Database URLs
  {
    type: 'DATABASE_URL',
    name: 'Database Connection String',
    pattern: /(?:mongodb(?:\+srv)?|postgres|postgresql|mysql|redis|mssql):\/\/[^:\s]+:[^@\s]+@[^\s]+/gi,
    severity: 'CRITICAL',
    description: 'Database connection string with credentials detected',
    recommendation: 'Use environment variables for database credentials'
  },

  // Passwords
  {
    type: 'PASSWORD',
    name: 'Hardcoded Password',
    pattern: /(?:password|passwd|pwd|pass)['":\s]*[=:]\s*['"]([^'"]{8,})['"](?!\s*(?:\+|\.|\?))/gi,
    severity: 'HIGH',
    description: 'Hardcoded password detected',
    recommendation: 'Remove password and use a secrets manager or environment variables'
  },

  // Bearer Tokens
  {
    type: 'BEARER_TOKEN',
    name: 'Bearer Token',
    pattern: /[Bb]earer\s+[a-zA-Z0-9_-]{20,}/g,
    severity: 'HIGH',
    description: 'Bearer token detected',
    recommendation: 'Remove bearer token from code and implement proper token management'
  },

  // Basic Auth
  {
    type: 'BASIC_AUTH',
    name: 'Basic Auth Credentials',
    pattern: /[Bb]asic\s+[A-Za-z0-9+/=]{20,}/g,
    severity: 'HIGH',
    description: 'Basic authentication credentials detected',
    recommendation: 'Remove basic auth credentials and use OAuth or API keys'
  },

  // Stripe
  {
    type: 'STRIPE_KEY',
    name: 'Stripe API Key',
    pattern: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    severity: 'CRITICAL',
    description: 'Stripe secret key detected',
    recommendation: 'Rotate Stripe key immediately and use restricted API keys'
  },

  // Twilio
  {
    type: 'TWILIO_KEY',
    name: 'Twilio API Key',
    pattern: /SK[a-f0-9]{32}/g,
    severity: 'HIGH',
    description: 'Twilio API key detected',
    recommendation: 'Rotate Twilio key and use API keys with minimal permissions'
  },

  // SendGrid
  {
    type: 'SENDGRID_KEY',
    name: 'SendGrid API Key',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: 'HIGH',
    description: 'SendGrid API key detected',
    recommendation: 'Rotate SendGrid key and use API keys with minimal permissions'
  },

  // NPM
  {
    type: 'NPM_TOKEN',
    name: 'NPM Token',
    pattern: /npm_[A-Za-z0-9]{36}/g,
    severity: 'HIGH',
    description: 'NPM authentication token detected',
    recommendation: 'Revoke NPM token and use granular access tokens'
  },

  // Docker
  {
    type: 'DOCKER_AUTH',
    name: 'Docker Auth Config',
    pattern: /"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"/g,
    severity: 'HIGH',
    description: 'Docker registry authentication detected',
    recommendation: 'Use credential helpers instead of storing auth in config'
  },

  // Kubernetes
  {
    type: 'KUBERNETES_SECRET',
    name: 'Kubernetes Secret',
    pattern: /kind:\s*Secret[\s\S]*?data:[\s\S]*?[a-zA-Z0-9_-]+:\s*[A-Za-z0-9+/=]{20,}/gi,
    severity: 'HIGH',
    description: 'Kubernetes Secret manifest with encoded data detected',
    recommendation: 'Use sealed-secrets or external secrets operator'
  }
];

// Files to skip
const SKIP_EXTENSIONS = [
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.wav', '.avi', '.mov',
  '.zip', '.tar', '.gz', '.rar', '.7z',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.exe', '.dll', '.so', '.dylib',
  '.min.js', '.min.css', '.map',
  '.lock', '.sum'
];

const SKIP_DIRECTORIES = [
  // Development
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt',
  'vendor', 'venv', '__pycache__', '.pytest_cache', '.mypy_cache',
  'coverage', '.nyc_output', 'test-results', '.idea', '.vscode',
  // Windows System Directories
  '$Recycle.Bin', '$RECYCLE.BIN', 'System Volume Information',
  'Windows', 'Program Files', 'Program Files (x86)', 'ProgramData',
  'Recovery', 'Config.Msi', 'MSOCache', 'Documents and Settings',
  'PerfLogs', 'Intel', 'AMD', 'NVIDIA', 'hiberfil.sys', 'pagefile.sys',
  'swapfile.sys', 'DumpStack.log.tmp', 'bootmgr',
  // Linux/Unix System Directories
  'proc', 'sys', 'dev', 'run', 'snap', 'lost+found', 'boot', 'lib', 'lib64',
  // macOS System Directories
  'Library', 'System', 'Applications', 'Volumes', 'private', '.Spotlight-V100',
  '.fseventsd', '.Trashes', '.TemporaryItems'
];

// ========================================
// SECRET SCANNER SERVICE
// ========================================

class SecretScanner {
  private findingCounter = 0;

  /**
   * Scan a directory for secrets
   */
  async scanDirectory(dirPath: string, options: {
    recursive?: boolean;
    includePatterns?: string[];
    excludePatterns?: string[];
    maxFileSize?: number;
  } = {}): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: SecretFinding[] = [];
    let scannedFiles = 0;
    let skippedFiles = 0;

    const {
      recursive = true,
      maxFileSize = 1024 * 1024 // 1MB default
    } = options;

    const scanFile = async (filePath: string) => {
      const _ext = path.extname(filePath).toLowerCase();
      const _fileName = path.basename(filePath);

      // Skip binary and irrelevant files
      if (SKIP_EXTENSIONS.some(e => filePath.toLowerCase().endsWith(e))) {
        skippedFiles++;
        return;
      }

      try {
        const stats = fs.statSync(filePath);
        if (stats.size > maxFileSize) {
          skippedFiles++;
          return;
        }

        const content = fs.readFileSync(filePath, 'utf-8');
        const fileFindings = await this.scanContent(content, filePath);
        findings.push(...fileFindings);
        scannedFiles++;
      } catch (error) {
        skippedFiles++;
      }
    };

    const walkDir = async (dir: string) => {
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);

          // Skip directories that start with $ (Windows system)
          if (entry.name.startsWith('$') || entry.name.startsWith('.')) {
            if (entry.isDirectory()) {continue;}
          }

          if (entry.isDirectory()) {
            if (recursive && !SKIP_DIRECTORIES.includes(entry.name)) {
              await walkDir(fullPath);
            }
          } else {
            await scanFile(fullPath);
          }
        }
      } catch (error) {
        // Gracefully skip directories with permission errors
        if ((error as NodeJS.ErrnoException).code === 'EPERM' || (error as NodeJS.ErrnoException).code === 'EACCES' || (error as NodeJS.ErrnoException).code === 'EBUSY') {
          skippedFiles++;
          return;
        }
        // Re-throw other errors
        throw error;
      }
    };

    await walkDir(dirPath);

    // Calculate summary
    const summary = {
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      total: findings.length
    };

    // Count by type
    const byType: Record<SecretType, number> = {} as Record<SecretType, number>;
    for (const finding of findings) {
      byType[finding.type] = (byType[finding.type] || 0) + 1;
    }

    return {
      scannedFiles,
      skippedFiles,
      findings,
      scanDuration: Date.now() - startTime,
      summary,
      byType
    };
  }

  /**
   * Scan content for secrets
   */
  async scanContent(content: string, filePath: string = 'unknown'): Promise<SecretFinding[]> {
    const findings: SecretFinding[] = [];
    const lines = content.split('\n');

    for (const pattern of SECRET_PATTERNS) {
      // Reset regex lastIndex
      pattern.pattern.lastIndex = 0;

      let match;
      while ((match = pattern.pattern.exec(content)) !== null) {
        const matchStart = match.index;
        const matchText = match[0];

        // Calculate line and column
        let lineNum = 1;
        let lastNewline = 0;
        for (let i = 0; i < matchStart; i++) {
          if (content[i] === '\n') {
            lineNum++;
            lastNewline = i + 1;
          }
        }
        const column = matchStart - lastNewline + 1;

        // Get context (the line containing the match)
        const contextLine = lines[lineNum - 1] || '';

        // Check entropy for generic patterns
        let entropy: number | undefined;
        if (pattern.type === 'AWS_SECRET_KEY' || pattern.type === 'GENERIC_SECRET') {
          entropy = this.calculateEntropy(matchText);
          if (entropy < 3.5) {continue;} // Skip low-entropy matches
        }

        // Skip if it looks like a placeholder
        if (this.isLikelyPlaceholder(matchText)) {continue;}

        findings.push({
          id: `SEC-${++this.findingCounter}`,
          type: pattern.type,
          severity: pattern.severity,
          file: filePath,
          line: lineNum,
          column,
          match: matchText,
          maskedMatch: this.maskSecret(matchText),
          context: this.sanitizeContext(contextLine),
          description: pattern.description,
          recommendation: pattern.recommendation,
          entropy
        });
      }
    }

    // Check for high entropy strings that might be secrets
    const highEntropyFindings = this.detectHighEntropyStrings(content, filePath, lines);
    findings.push(...highEntropyFindings);

    return findings;
  }

  /**
   * Detect high-entropy strings that could be secrets
   */
  private detectHighEntropyStrings(content: string, filePath: string, lines: string[]): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const stringPattern = /['"]([A-Za-z0-9+/=_-]{32,})['"]|=\s*([A-Za-z0-9+/=_-]{32,})/g;

    let match;
    while ((match = stringPattern.exec(content)) !== null) {
      const value = match[1] || match[2];
      if (!value) {continue;}

      const entropy = this.calculateEntropy(value);
      if (entropy >= 4.5 && !this.isLikelyPlaceholder(value)) {
        // Calculate line number
        let lineNum = 1;
        for (let i = 0; i < match.index; i++) {
          if (content[i] === '\n') {lineNum++;}
        }

        // Skip if already found by pattern matching
        const alreadyFound = findings.some(f =>
          f.line === lineNum && f.match.includes(value.substring(0, 10))
        );
        if (alreadyFound) {continue;}

        findings.push({
          id: `SEC-${++this.findingCounter}`,
          type: 'HIGH_ENTROPY',
          severity: 'MEDIUM',
          file: filePath,
          line: lineNum,
          column: 1,
          match: value,
          maskedMatch: this.maskSecret(value),
          context: this.sanitizeContext(lines[lineNum - 1] || ''),
          description: 'High-entropy string detected (possible secret)',
          recommendation: 'Review this string - if it\'s a secret, move it to environment variables',
          entropy
        });
      }
    }

    return findings;
  }

  /**
   * Calculate Shannon entropy of a string
   */
  private calculateEntropy(str: string): number {
    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Check if a string is likely a placeholder
   */
  private isLikelyPlaceholder(str: string): boolean {
    const placeholderPatterns = [
      /^x+$/i,
      /^placeholder/i,
      /^example/i,
      /^your[_-]?/i,
      /^test[_-]?/i,
      /^sample/i,
      /^dummy/i,
      /^fake/i,
      /^\${/,
      /^<.*>$/,
      /^\[.*\]$/,
      /^{{.*}}$/
    ];

    return placeholderPatterns.some(p => p.test(str));
  }

  /**
   * Mask a secret for safe display
   */
  private maskSecret(secret: string): string {
    if (secret.length <= 8) {
      return '*'.repeat(secret.length);
    }
    return secret.substring(0, 4) + '*'.repeat(Math.min(20, secret.length - 8)) + secret.substring(secret.length - 4);
  }

  /**
   * Sanitize context line for display
   */
  private sanitizeContext(line: string): string {
    // Mask potential secrets in context
    return line.substring(0, 100) + (line.length > 100 ? '...' : '');
  }

  /**
   * Get severity color
   */
  getSeverityColor(severity: string): string {
    switch (severity) {
      case 'CRITICAL': return '#dc2626';
      case 'HIGH': return '#f97316';
      case 'MEDIUM': return '#eab308';
      case 'LOW': return '#22c55e';
      default: return '#6b7280';
    }
  }
}

export const secretScanner = new SecretScanner();
