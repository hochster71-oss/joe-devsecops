import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';
import { SecurityFinding, Severity } from '../types';
import { Logger } from '../utils/logger';

const execAsync = promisify(exec);

export interface SecretFinding {
    type: string;
    match: string;
    filePath: string;
    line: number;
    validity: 'valid' | 'invalid' | 'unknown';
}

export class GitGuardianService {
    private context: vscode.ExtensionContext;
    private apiKey: string | undefined;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    async initialize(): Promise<void> {
        // Try to get API key from secret storage
        this.apiKey = await this.context.secrets.get('joe.gitguardian.apiKey');
    }

    async setApiKey(apiKey: string): Promise<void> {
        await this.context.secrets.store('joe.gitguardian.apiKey', apiKey);
        this.apiKey = apiKey;
        Logger.info('GitGuardian API key stored securely');
    }

    async scanForSecrets(workspacePath: string): Promise<SecurityFinding[]> {
        Logger.info('Running GitGuardian secret scan...');

        // First try ggshield CLI
        try {
            return await this.runGgshield(workspacePath);
        } catch {
            Logger.warn('ggshield not available, falling back to pattern matching');
            return await this.runPatternScan(workspacePath);
        }
    }

    private async runGgshield(workspacePath: string): Promise<SecurityFinding[]> {
        const env = { ...process.env };
        if (this.apiKey) {
            env['GITGUARDIAN_API_KEY'] = this.apiKey;
        }

        const { stdout } = await execAsync(
            `ggshield secret scan path "${workspacePath}" --json --recursive`,
            { maxBuffer: 10 * 1024 * 1024, env }
        );

        const data = JSON.parse(stdout);
        const findings: SecurityFinding[] = [];

        for (const result of data.scans || []) {
            for (const incident of result.incidents || []) {
                findings.push({
                    id: `gg-${incident.type}-${Date.now()}`,
                    title: `Secret Detected: ${incident.type}`,
                    severity: this.mapValidity(incident.validity),
                    tool: 'GitGuardian',
                    filePath: result.filename,
                    line: incident.line_start,
                    description: `Found ${incident.type} secret. ${incident.validity === 'valid' ? 'This secret appears to be ACTIVE!' : ''}`,
                    recommendation: 'Rotate this credential immediately and remove from source code',
                    timestamp: new Date()
                });
            }
        }

        return findings;
    }

    private async runPatternScan(workspacePath: string): Promise<SecurityFinding[]> {
        // Fallback pattern-based scanning for common secrets
        const patterns: Array<{ name: string; regex: RegExp; severity: Severity }> = [
            { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: Severity.critical },
            { name: 'AWS Secret Key', regex: /[A-Za-z0-9/+=]{40}/g, severity: Severity.critical },
            { name: 'GitHub Token', regex: /ghp_[A-Za-z0-9]{36}/g, severity: Severity.critical },
            { name: 'GitHub OAuth', regex: /gho_[A-Za-z0-9]{36}/g, severity: Severity.critical },
            { name: 'Slack Token', regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, severity: Severity.critical },
            { name: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: Severity.critical },
            { name: 'Generic API Key', regex: /api[_-]?key['"]?\s*[:=]\s*['"][A-Za-z0-9]{20,}/gi, severity: Severity.high },
            { name: 'Generic Secret', regex: /secret['"]?\s*[:=]\s*['"][A-Za-z0-9]{20,}/gi, severity: Severity.high },
            { name: 'Password in Code', regex: /password['"]?\s*[:=]\s*['"][^'"]{8,}/gi, severity: Severity.high },
            { name: 'Bearer Token', regex: /bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/gi, severity: Severity.high },
            { name: 'JWT Token', regex: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g, severity: Severity.medium },
        ];

        const findings: SecurityFinding[] = [];
        const fs = await import('fs').then(m => m.promises);

        // Get all files (excluding common non-code directories)
        const files = await this.getFilesRecursively(workspacePath, [
            'node_modules', '.git', 'dist', 'out', 'build', '.vscode-test', 'coverage'
        ]);

        for (const file of files) {
            try {
                const content = await fs.readFile(file, 'utf-8');
                const lines = content.split('\n');

                for (const pattern of patterns) {
                    for (let i = 0; i < lines.length; i++) {
                        const matches = lines[i].match(pattern.regex);
                        if (matches) {
                            for (const match of matches) {
                                // Skip if it looks like a placeholder/example
                                if (this.isLikelyPlaceholder(match)) {continue;}

                                findings.push({
                                    id: `secret-${pattern.name}-${file}-${i}`,
                                    title: `Potential ${pattern.name}`,
                                    severity: pattern.severity,
                                    tool: 'J.O.E. Secret Scanner',
                                    filePath: file,
                                    line: i + 1,
                                    description: `Found potential ${pattern.name} in source code`,
                                    recommendation: 'Review this finding and remove/rotate if it\'s a real credential',
                                    timestamp: new Date()
                                });
                            }
                        }
                    }
                }
            } catch {
                // Skip files that can't be read
            }
        }

        return findings;
    }

    private async getFilesRecursively(dir: string, excludeDirs: string[]): Promise<string[]> {
        const fs = await import('fs').then(m => m.promises);
        const path = await import('path');
        const files: string[] = [];

        try {
            const entries = await fs.readdir(dir, { withFileTypes: true });

            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);

                if (entry.isDirectory()) {
                    if (!excludeDirs.includes(entry.name)) {
                        files.push(...await this.getFilesRecursively(fullPath, excludeDirs));
                    }
                } else if (entry.isFile()) {
                    // Only scan text-like files
                    const ext = path.extname(entry.name).toLowerCase();
                    const textExtensions = [
                        '.ts', '.js', '.tsx', '.jsx', '.py', '.rb', '.go', '.java',
                        '.cs', '.php', '.swift', '.kt', '.rs', '.c', '.cpp', '.h',
                        '.json', '.yaml', '.yml', '.xml', '.env', '.ini', '.cfg',
                        '.conf', '.properties', '.sh', '.bash', '.ps1', '.bat',
                        '.md', '.txt', '.sql', '.html', '.css', '.scss'
                    ];
                    if (textExtensions.includes(ext) || entry.name.startsWith('.')) {
                        files.push(fullPath);
                    }
                }
            }
        } catch {
            // Skip directories that can't be read
        }

        return files;
    }

    private isLikelyPlaceholder(value: string): boolean {
        const placeholderPatterns = [
            /^[xX]+$/,
            /^[0]+$/,
            /example/i,
            /placeholder/i,
            /your[_-]?(api[_-]?)?key/i,
            /insert[_-]?here/i,
            /change[_-]?me/i,
            /todo/i,
            /fixme/i,
            /test/i,
            /dummy/i,
            /fake/i,
            /mock/i,
            /sample/i
        ];

        return placeholderPatterns.some(p => p.test(value));
    }

    private mapValidity(validity: string): Severity {
        switch (validity) {
            case 'valid':
                return Severity.critical;
            case 'invalid':
                return Severity.low;
            default:
                return Severity.high;
        }
    }

    async scanOnSave(document: vscode.TextDocument): Promise<SecurityFinding[]> {
        const content = document.getText();
        const findings: SecurityFinding[] = [];

        // Quick pattern check for the current file
        const quickPatterns = [
            { name: 'AWS Key', regex: /AKIA[0-9A-Z]{16}/ },
            { name: 'Private Key', regex: /-----BEGIN.*PRIVATE KEY-----/ },
            { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9]{36}/ }
        ];

        for (const pattern of quickPatterns) {
            if (pattern.regex.test(content)) {
                findings.push({
                    id: `quickscan-${pattern.name}-${Date.now()}`,
                    title: `Potential ${pattern.name} detected!`,
                    severity: Severity.critical,
                    tool: 'J.O.E. Real-time Scanner',
                    filePath: document.uri.fsPath,
                    description: `A potential ${pattern.name} was detected in this file`,
                    recommendation: 'Do NOT commit this file until the secret is removed',
                    timestamp: new Date()
                });
            }
        }

        return findings;
    }
}
