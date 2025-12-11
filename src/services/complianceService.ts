import * as vscode from 'vscode';
import { ComplianceControl, ComplianceFramework, ComplianceStatus, RiskScore } from '../types';
import { Logger } from '../utils/logger';

export class ComplianceService {
    private context: vscode.ExtensionContext;
    private controls: ComplianceControl[] = [];

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.initializeControls();
    }

    private initializeControls(): void {
        // Initialize CMMC 2.0 controls
        this.controls = [
            {
                id: 'AC.L1-3.1.1',
                framework: ComplianceFramework.cmmc2,
                title: 'Authorized Access Control',
                description: 'Limit system access to authorized users',
                status: ComplianceStatus.notAssessed
            },
            {
                id: 'AC.L1-3.1.2',
                framework: ComplianceFramework.cmmc2,
                title: 'Transaction & Function Control',
                description: 'Limit system access to authorized transactions and functions',
                status: ComplianceStatus.notAssessed
            },
            {
                id: 'IA.L1-3.5.1',
                framework: ComplianceFramework.cmmc2,
                title: 'Identification',
                description: 'Identify system users, processes acting on behalf of users',
                status: ComplianceStatus.notAssessed
            },
            {
                id: 'IA.L1-3.5.2',
                framework: ComplianceFramework.cmmc2,
                title: 'Authentication',
                description: 'Authenticate identities of users, processes, or devices',
                status: ComplianceStatus.notAssessed
            },
            {
                id: 'SC.L1-3.13.1',
                framework: ComplianceFramework.cmmc2,
                title: 'Boundary Protection',
                description: 'Monitor and control communications at system boundaries',
                status: ComplianceStatus.notAssessed
            },
            {
                id: 'SI.L1-3.14.1',
                framework: ComplianceFramework.cmmc2,
                title: 'Flaw Remediation',
                description: 'Identify and remediate system flaws in a timely manner',
                status: ComplianceStatus.notAssessed
            },
            {
                id: 'SI.L1-3.14.2',
                framework: ComplianceFramework.cmmc2,
                title: 'Malicious Code Protection',
                description: 'Provide protection from malicious code',
                status: ComplianceStatus.notAssessed
            }
        ];
    }

    async runPolicyCheck(): Promise<void> {
        Logger.info('Running policy compliance check...');

        await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: 'Running Compliance Check',
                cancellable: false
            },
            async (progress) => {
                progress.report({ message: 'Evaluating controls...' });

                // Simulate policy evaluation
                for (const control of this.controls) {
                    // In a real implementation, this would check actual evidence
                    control.status = this.evaluateControl();
                }

                vscode.window.showInformationMessage(
                    `Compliance check complete. ${this.getCompliancePercentage()}% compliant.`
                );
            }
        );
    }

    private evaluateControl(): ComplianceStatus {
        // Placeholder evaluation logic
        // In production, this would integrate with actual policy engines (OPA, Checkov, etc.)
        return ComplianceStatus.notAssessed;
    }

    showComplianceMatrix(): void {
        const panel = vscode.window.createWebviewPanel(
            'joeComplianceMatrix',
            'Compliance Matrix',
            vscode.ViewColumn.One,
            { enableScripts: true }
        );

        panel.webview.html = this.getComplianceMatrixHtml();
    }

    private getComplianceMatrixHtml(): string {
        const statusColors: Record<ComplianceStatus, string> = {
            [ComplianceStatus.compliant]: '#4caf50',
            [ComplianceStatus.partiallyCompliant]: '#ff9800',
            [ComplianceStatus.nonCompliant]: '#f44336',
            [ComplianceStatus.notAssessed]: '#9e9e9e'
        };

        const rows = this.controls.map(c => `
            <tr>
                <td>${c.id}</td>
                <td>${c.title}</td>
                <td style="color: ${statusColors[c.status]}">${c.status}</td>
            </tr>
        `).join('');

        return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Compliance Matrix</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            padding: 20px;
            background: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
        }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid var(--vscode-panel-border); padding: 10px; text-align: left; }
        th { background: var(--vscode-editor-selectionBackground); }
        .gauge {
            width: 200px;
            height: 100px;
            margin: 20px auto;
        }
        h1 { color: var(--vscode-editor-foreground); }
        .summary { margin: 20px 0; padding: 15px; background: var(--vscode-editor-selectionBackground); border-radius: 5px; }
    </style>
</head>
<body>
    <h1>CMMC 2.0 Compliance Matrix</h1>
    <div class="summary">
        <strong>Overall Compliance:</strong> ${this.getCompliancePercentage()}%<br>
        <strong>CMMC Level:</strong> ${this.calculateCmmcLevel()}
    </div>
    <table>
        <thead>
            <tr>
                <th>Control ID</th>
                <th>Title</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            ${rows}
        </tbody>
    </table>
</body>
</html>`;
    }

    async generateReport(): Promise<void> {
        Logger.info('Generating compliance report...');

        const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspaceFolder) {
            throw new Error('No workspace folder open');
        }

        // In production, this would use pdfmake to generate a proper PDF
        const reportContent = this.generateReportContent();

        const fs = await import('fs').then(m => m.promises);
        const path = await import('path');
        const reportPath = path.join(workspaceFolder, 'compliance-report.md');
        await fs.writeFile(reportPath, reportContent, 'utf-8');

        const doc = await vscode.workspace.openTextDocument(reportPath);
        await vscode.window.showTextDocument(doc);

        vscode.window.showInformationMessage(`Report generated: ${reportPath}`);
    }

    private generateReportContent(): string {
        const date = new Date().toISOString().split('T')[0];
        return `# Compliance Report
Generated: ${date}

## Summary
- **Framework:** CMMC 2.0
- **Overall Compliance:** ${this.getCompliancePercentage()}%
- **CMMC Level:** ${this.calculateCmmcLevel()}

## Control Status

${this.controls.map(c => `### ${c.id}: ${c.title}
- **Status:** ${c.status}
- **Description:** ${c.description}
`).join('\n')}

---
*Generated by J.O.E. DevSecOps Arsenal*
`;
    }

    getControls(): ComplianceControl[] {
        return this.controls;
    }

    getCompliancePercentage(): number {
        const compliant = this.controls.filter(
            c => c.status === ComplianceStatus.compliant
        ).length;
        return Math.round((compliant / this.controls.length) * 100);
    }

    calculateCmmcLevel(): number {
        const percentage = this.getCompliancePercentage();
        if (percentage >= 90) {return 3;}
        if (percentage >= 70) {return 2;}
        if (percentage >= 50) {return 1;}
        return 0;
    }

    getRiskScore(): RiskScore {
        return {
            overall: 100 - this.getCompliancePercentage(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            cmmcLevel: this.calculateCmmcLevel()
        };
    }
}
