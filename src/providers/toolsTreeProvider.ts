import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';
import { ToolInfo } from '../types';
import { Config } from '../utils/config';

const execAsync = promisify(exec);

export class ToolsTreeProvider implements vscode.TreeDataProvider<ToolTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<ToolTreeItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    private tools: ToolInfo[] = [
        { name: 'Semgrep', description: 'SAST Scanner', installed: false, enabled: Config.semgrepEnabled },
        { name: 'Trivy', description: 'Container Scanner', installed: false, enabled: Config.trivyEnabled },
        { name: 'Snyk', description: 'SCA Scanner', installed: false, enabled: Config.snykEnabled },
        { name: 'Syft', description: 'SBOM Generator', installed: false, enabled: true },
        { name: 'Grype', description: 'Vulnerability Scanner', installed: false, enabled: true },
        { name: 'OPA', description: 'Policy Engine', installed: false, enabled: true },
        { name: 'Checkov', description: 'IaC Scanner', installed: false, enabled: true }
    ];

    constructor() {
        this.checkToolsInstallation();
    }

    private async checkToolsInstallation(): Promise<void> {
        for (const tool of this.tools) {
            try {
                const cmd = tool.name.toLowerCase();
                await execAsync(`${cmd} --version`);
                tool.installed = true;
            } catch {
                tool.installed = false;
            }
        }
        this._onDidChangeTreeData.fire(undefined);
    }

    refresh(): void {
        this.checkToolsInstallation();
    }

    getTreeItem(element: ToolTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(): Thenable<ToolTreeItem[]> {
        return Promise.resolve(this.tools.map(t => new ToolTreeItem(t)));
    }
}

class ToolTreeItem extends vscode.TreeItem {
    constructor(tool: ToolInfo) {
        super(tool.name, vscode.TreeItemCollapsibleState.None);
        this.description = tool.description;

        const status = tool.installed ? (tool.enabled ? 'Enabled' : 'Disabled') : 'Not Installed';
        this.tooltip = `${tool.name}\n${tool.description}\n\nStatus: ${status}`;

        if (tool.installed) {
            this.iconPath = tool.enabled
                ? new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'))
                : new vscode.ThemeIcon('circle-slash');
        } else {
            this.iconPath = new vscode.ThemeIcon('cloud-download');
        }

        this.contextValue = tool.installed ? 'installedTool' : 'missingTool';
    }
}
