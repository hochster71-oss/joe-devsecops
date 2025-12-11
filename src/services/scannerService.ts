import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';
import { SecurityFinding, ScanResult, Severity } from '../types';
import { Config } from '../utils/config';
import { Logger } from '../utils/logger';

const execAsync = promisify(exec);

export interface SemgrepResult {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    check_id: string;
    extra?: {
        message?: string;
        severity?: string;
        metadata?: {
            cwe?: string[];
        };
    };
    path: string;
    start?: {
        line: number;
        col: number;
    };
    end?: {
        line: number;
        col: number;
    };
}

export interface SnykVulnerability {
    id: string;
    title: string;
    severity: string;
    from?: string[];
    description?: string;
    identifiers?: {
        // eslint-disable-next-line @typescript-eslint/naming-convention
        CVE?: string[];
        // eslint-disable-next-line @typescript-eslint/naming-convention
        CWE?: string[];
    };
    fixedIn?: string;
}

export class ScannerService {
    private context: vscode.ExtensionContext;
    private findings: SecurityFinding[] = [];

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    async runAllScans(): Promise<ScanResult[]> {
        const results: ScanResult[] = [];
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

        if (!workspaceFolder) {
            throw new Error('No workspace folder open');
        }

        // Run enabled scanners
        if (Config.semgrepEnabled) {
            results.push(await this.runSemgrep(workspaceFolder));
        }

        if (Config.trivyEnabled) {
            results.push(await this.runTrivy(workspaceFolder));
        }

        if (Config.snykEnabled && Config.snykApiKey) {
            results.push(await this.runSnyk(workspaceFolder));
        }

        // Aggregate findings
        this.findings = results.flatMap(r => r.findings);

        return results;
    }

    private async runSemgrep(workspacePath: string): Promise<ScanResult> {
        Logger.info('Running Semgrep scan...');

        try {
            const { stdout } = await execAsync(
                `semgrep scan --json --config auto "${workspacePath}"`,
                { maxBuffer: 10 * 1024 * 1024 }
            );

            const data = JSON.parse(stdout);
            const findings: SecurityFinding[] = (data.results || []).map((r: SemgrepResult) => ({
                id: r.check_id,
                title: r.extra?.message || r.check_id,
                severity: this.mapSeverity(r.extra?.severity || 'INFO'),
                tool: 'Semgrep',
                filePath: r.path,
                line: r.start?.line,
                description: r.extra?.message || '',
                cweId: r.extra?.metadata?.cwe?.[0],
                timestamp: new Date()
            }));

            return { tool: 'Semgrep', timestamp: new Date(), findings, success: true };
        } catch (error) {
            Logger.error('Semgrep scan failed', error);
            return {
                tool: 'Semgrep',
                timestamp: new Date(),
                findings: [],
                success: false,
                error: String(error)
            };
        }
    }

    private async runTrivy(workspacePath: string): Promise<ScanResult> {
        Logger.info('Running Trivy scan...');

        try {
            const { stdout } = await execAsync(
                `trivy fs --format json "${workspacePath}"`,
                { maxBuffer: 10 * 1024 * 1024 }
            );

            const data = JSON.parse(stdout);
            const findings: SecurityFinding[] = [];

            for (const result of data.Results || []) {
                for (const vuln of result.Vulnerabilities || []) {
                    findings.push({
                        id: vuln.VulnerabilityID,
                        title: `${vuln.PkgName}@${vuln.InstalledVersion}`,
                        severity: this.mapSeverity(vuln.Severity),
                        tool: 'Trivy',
                        filePath: result.Target,
                        description: vuln.Description || vuln.Title,
                        cveId: vuln.VulnerabilityID,
                        recommendation: vuln.FixedVersion ? `Upgrade to ${vuln.FixedVersion}` : undefined,
                        timestamp: new Date()
                    });
                }
            }

            return { tool: 'Trivy', timestamp: new Date(), findings, success: true };
        } catch (error) {
            Logger.error('Trivy scan failed', error);
            return {
                tool: 'Trivy',
                timestamp: new Date(),
                findings: [],
                success: false,
                error: String(error)
            };
        }
    }

    private async runSnyk(workspacePath: string): Promise<ScanResult> {
        Logger.info('Running Snyk scan...');

        try {
            const { stdout } = await execAsync(
                `snyk test --json "${workspacePath}"`,
                {
                    maxBuffer: 10 * 1024 * 1024,
                    // eslint-disable-next-line @typescript-eslint/naming-convention
                    env: { ...process.env, SNYK_TOKEN: Config.snykApiKey }
                }
            );

            const data = JSON.parse(stdout);
            const findings: SecurityFinding[] = (data.vulnerabilities || []).map((v: SnykVulnerability) => ({
                id: v.id,
                title: v.title,
                severity: this.mapSeverity(v.severity),
                tool: 'Snyk',
                filePath: v.from?.[0],
                description: v.description,
                cveId: v.identifiers?.CVE?.[0],
                cweId: v.identifiers?.CWE?.[0],
                recommendation: v.fixedIn ? `Upgrade to ${v.fixedIn}` : undefined,
                timestamp: new Date()
            }));

            return { tool: 'Snyk', timestamp: new Date(), findings, success: true };
        } catch (error) {
            Logger.error('Snyk scan failed', error);
            return {
                tool: 'Snyk',
                timestamp: new Date(),
                findings: [],
                success: false,
                error: String(error)
            };
        }
    }

    private mapSeverity(severity: string): Severity {
        const map: Record<string, Severity> = {
            // eslint-disable-next-line @typescript-eslint/naming-convention
            'CRITICAL': Severity.critical,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            'HIGH': Severity.high,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            'MEDIUM': Severity.medium,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            'LOW': Severity.low,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            'INFO': Severity.info,
            'critical': Severity.critical,
            'high': Severity.high,
            'medium': Severity.medium,
            'low': Severity.low,
            'info': Severity.info
        };
        return map[severity] || Severity.info;
    }

    getFindings(): SecurityFinding[] {
        return this.findings;
    }

    getFindingsBySeverity(severity: Severity): SecurityFinding[] {
        return this.findings.filter(f => f.severity === severity);
    }
}
