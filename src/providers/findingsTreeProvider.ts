import * as vscode from 'vscode';
import { SecurityFinding, Severity } from '../types';
import { ScannerService } from '../services/scannerService';

export class FindingsTreeProvider implements vscode.TreeDataProvider<FindingTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<FindingTreeItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor(private scannerService: ScannerService) {}

    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: FindingTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: FindingTreeItem): Thenable<FindingTreeItem[]> {
        if (!element) {
            // Root level - show severity categories
            return Promise.resolve(this.getSeverityCategories());
        }

        if (element.contextValue === 'severity') {
            // Show findings for this severity
            const findings = this.scannerService.getFindingsBySeverity(element.severity!);
            return Promise.resolve(findings.map(f => new FindingTreeItem(f)));
        }

        return Promise.resolve([]);
    }

    private getSeverityCategories(): FindingTreeItem[] {
        const severities = [Severity.critical, Severity.high, Severity.medium, Severity.low];
        return severities.map(severity => {
            const count = this.scannerService.getFindingsBySeverity(severity).length;
            return new FindingTreeItem(undefined, severity, count);
        });
    }
}

class FindingTreeItem extends vscode.TreeItem {
    severity?: Severity;

    constructor(finding?: SecurityFinding, severity?: Severity, count?: number) {
        if (finding) {
            super(finding.title, vscode.TreeItemCollapsibleState.None);
            this.description = `${finding.tool} - ${finding.severity}`;
            this.tooltip = finding.description;
            this.contextValue = 'finding';
            this.iconPath = FindingTreeItem.getIcon(finding.severity);

            if (finding.filePath) {
                this.command = {
                    command: 'vscode.open',
                    title: 'Open File',
                    arguments: [
                        vscode.Uri.file(finding.filePath),
                        { selection: new vscode.Range(finding.line || 0, 0, finding.line || 0, 0) }
                    ]
                };
            }
        } else if (severity) {
            super(
                `${severity.toUpperCase()} (${count || 0})`,
                vscode.TreeItemCollapsibleState.Collapsed
            );
            this.severity = severity;
            this.contextValue = 'severity';
            this.iconPath = FindingTreeItem.getIcon(severity);
        } else {
            super('Unknown', vscode.TreeItemCollapsibleState.None);
        }
    }

    private static getIcon(severity: Severity): vscode.ThemeIcon {
        switch (severity) {
            case Severity.critical:
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case Severity.high:
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
            case Severity.medium:
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
            case Severity.low:
                return new vscode.ThemeIcon('circle-outline');
            default:
                return new vscode.ThemeIcon('question');
        }
    }
}
