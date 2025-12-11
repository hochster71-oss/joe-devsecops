import * as vscode from 'vscode';
import { ComplianceControl, ComplianceStatus } from '../types';
import { ComplianceService } from '../services/complianceService';

export class ComplianceTreeProvider implements vscode.TreeDataProvider<ComplianceTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<ComplianceTreeItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor(private complianceService: ComplianceService) {}

    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: ComplianceTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: ComplianceTreeItem): Thenable<ComplianceTreeItem[]> {
        if (!element) {
            const controls = this.complianceService.getControls();
            return Promise.resolve(controls.map(c => new ComplianceTreeItem(c)));
        }
        return Promise.resolve([]);
    }
}

class ComplianceTreeItem extends vscode.TreeItem {
    constructor(control: ComplianceControl) {
        super(control.id, vscode.TreeItemCollapsibleState.None);
        this.description = control.title;
        this.tooltip = `${control.description}\n\nStatus: ${control.status}`;
        this.contextValue = 'control';
        this.iconPath = ComplianceTreeItem.getIcon(control.status);
    }

    private static getIcon(status: ComplianceStatus): vscode.ThemeIcon {
        switch (status) {
            case ComplianceStatus.compliant:
                return new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
            case ComplianceStatus.partiallyCompliant:
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
            case ComplianceStatus.nonCompliant:
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }
}
