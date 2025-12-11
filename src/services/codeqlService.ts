import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import { SecurityFinding, Severity } from '../types';
import { Logger } from '../utils/logger';

const execAsync = promisify(exec);

export interface CodeQLQuery {
    name: string;
    path: string;
    language: string;
}

export interface CodeQLRule {
    id: string;
    properties?: {
        tags?: string[];
    };
    help?: {
        text?: string;
    };
    shortDescription?: {
        text?: string;
    };
}

export class CodeQLService {
    private context: vscode.ExtensionContext;
    private codeqlPath: string | undefined;
    private databasePath: string | undefined;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    async initialize(): Promise<boolean> {
        try {
            const { stdout } = await execAsync('codeql version');
            Logger.info(`CodeQL found: ${stdout.trim()}`);
            return true;
        } catch {
            Logger.warn('CodeQL CLI not found in PATH');
            return false;
        }
    }

    async createDatabase(workspacePath: string, language: string): Promise<string> {
        Logger.info(`Creating CodeQL database for ${language}...`);

        const dbPath = path.join(workspacePath, '.joe', 'codeql-db');

        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'CodeQL',
                cancellable: false
            },
            async (progress) => {
                progress.report({ message: `Creating ${language} database...` });

                try {
                    await execAsync(
                        `codeql database create "${dbPath}" --language=${language} --source-root="${workspacePath}" --overwrite`,
                        { maxBuffer: 50 * 1024 * 1024, timeout: 600000 }
                    );
                    this.databasePath = dbPath;
                    Logger.info(`Database created at ${dbPath}`);
                } catch (error) {
                    Logger.error('Failed to create CodeQL database', error);
                    throw error;
                }
            }
        );

        return dbPath;
    }

    async runSecurityQueries(databasePath?: string): Promise<SecurityFinding[]> {
        const dbPath = databasePath || this.databasePath;
        if (!dbPath) {
            throw new Error('No CodeQL database available. Create one first.');
        }

        Logger.info('Running CodeQL security queries...');

        const findings: SecurityFinding[] = [];
        const resultsPath = path.join(path.dirname(dbPath), 'codeql-results.sarif');

        try {
            // Run security-extended suite
            await execAsync(
                `codeql database analyze "${dbPath}" --format=sarif-latest --output="${resultsPath}" -- codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`,
                { maxBuffer: 50 * 1024 * 1024, timeout: 1200000 }
            );

            // Parse SARIF results
            const fs = await import('fs').then(m => m.promises);
            const sarifContent = await fs.readFile(resultsPath, 'utf-8');
            const sarif = JSON.parse(sarifContent);

            for (const run of sarif.runs || []) {
                for (const result of run.results || []) {
                    const location = result.locations?.[0]?.physicalLocation;
                    findings.push({
                        id: `codeql-${result.ruleId}-${Date.now()}`,
                        title: result.message?.text || result.ruleId,
                        severity: this.mapSeverity(result.level),
                        tool: 'CodeQL',
                        filePath: location?.artifactLocation?.uri,
                        line: location?.region?.startLine,
                        description: result.message?.text || '',
                        cweId: this.extractCwe(result.ruleId, run.tool?.driver?.rules),
                        recommendation: this.getRecommendation(result.ruleId, run.tool?.driver?.rules),
                        timestamp: new Date()
                    });
                }
            }
        } catch (error) {
            Logger.error('CodeQL analysis failed', error);
            // Return partial results or empty
        }

        return findings;
    }

    async runCustomQuery(queryPath: string, databasePath?: string): Promise<SecurityFinding[]> {
        const dbPath = databasePath || this.databasePath;
        if (!dbPath) {
            throw new Error('No CodeQL database available');
        }

        Logger.info(`Running custom query: ${queryPath}`);

        const resultsPath = path.join(path.dirname(dbPath), 'custom-query-results.bqrs');
        const findings: SecurityFinding[] = [];

        try {
            await execAsync(
                `codeql query run --database="${dbPath}" --output="${resultsPath}" "${queryPath}"`,
                { maxBuffer: 20 * 1024 * 1024 }
            );

            // TODO: Decode and process custom query results
            // const { stdout } = await execAsync(
            //     `codeql bqrs decode --format=json "${resultsPath}"`,
            //     { maxBuffer: 20 * 1024 * 1024 }
            // );
            // const results = JSON.parse(stdout);
            // Structure depends on query output columns
            // TODO: Implement processing of custom query results

        } catch (error) {
            Logger.error('Custom query failed', error);
        }

        return findings;
    }

    async detectLanguage(workspacePath: string): Promise<string[]> {
        const languages: Set<string> = new Set();

        const languageMap: Record<string, string[]> = {
            'javascript': ['.js', '.jsx', '.ts', '.tsx', '.mjs'],
            'python': ['.py'],
            'java': ['.java'],
            'csharp': ['.cs'],
            'cpp': ['.cpp', '.cc', '.cxx', '.c', '.h', '.hpp'],
            'go': ['.go'],
            'ruby': ['.rb'],
            'swift': ['.swift']
        };

        const files = await this.getFilesRecursively(workspacePath);

        for (const file of files) {
            const ext = path.extname(file).toLowerCase();
            for (const [lang, exts] of Object.entries(languageMap)) {
                if (exts.includes(ext)) {
                    languages.add(lang);
                }
            }
        }

        return Array.from(languages);
    }

    private async getFilesRecursively(dir: string): Promise<string[]> {
        const fs = await import('fs').then(m => m.promises);
        const files: string[] = [];
        const excludeDirs = ['node_modules', '.git', 'dist', 'out', 'build', 'vendor'];

        try {
            const entries = await fs.readdir(dir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (entry.isDirectory() && !excludeDirs.includes(entry.name)) {
                    files.push(...await this.getFilesRecursively(fullPath));
                } else if (entry.isFile()) {
                    files.push(fullPath);
                }
            }
        } catch { /* skip */ }

        return files;
    }

    private mapSeverity(level: string): Severity {
        switch (level) {
            case 'error':
                return Severity.critical;
            case 'warning':
                return Severity.high;
            case 'note':
                return Severity.medium;
            default:
                return Severity.low;
        }
    }

    private extractCwe(ruleId: string, rules?: CodeQLRule[]): string | undefined {
        if (!rules) {return undefined;}
        const rule = rules.find(r => r.id === ruleId);
        const cweTags = rule?.properties?.tags?.filter((t: string) => t.startsWith('cwe-'));
        return cweTags?.[0]?.toUpperCase();
    }

    private getRecommendation(ruleId: string, rules?: CodeQLRule[]): string | undefined {
        if (!rules) {return undefined;}
        const rule = rules.find(r => r.id === ruleId);
        return rule?.help?.text || rule?.shortDescription?.text;
    }

    getAvailableQueries(): CodeQLQuery[] {
        return [
            { name: 'Security Extended', path: 'codeql-suites/javascript-security-extended.qls', language: 'javascript' },
            { name: 'Security & Quality', path: 'codeql-suites/javascript-security-and-quality.qls', language: 'javascript' },
            { name: 'OWASP Top 10', path: 'Security/CWE', language: 'javascript' },
            { name: 'Code Injection', path: 'Security/CWE-094', language: 'javascript' },
            { name: 'SQL Injection', path: 'Security/CWE-089', language: 'javascript' },
            { name: 'XSS', path: 'Security/CWE-079', language: 'javascript' },
            { name: 'Path Traversal', path: 'Security/CWE-022', language: 'javascript' }
        ];
    }
}
