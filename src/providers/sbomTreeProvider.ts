import * as vscode from 'vscode';
import { SbomComponent, ComponentType } from '../types';
import { SbomService } from '../services/sbomService';

export class SbomTreeProvider implements vscode.TreeDataProvider<SbomTreeItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<SbomTreeItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor(private sbomService: SbomService) {}

    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: SbomTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: SbomTreeItem): Thenable<SbomTreeItem[]> {
        if (!element) {
            const components = this.sbomService.getComponents();
            if (components.length === 0) {
                return Promise.resolve([
                    new SbomTreeItem('No SBOM generated', 'Run "J.O.E.: Generate SBOM" to analyze dependencies')
                ]);
            }
            return Promise.resolve(components.map(c => new SbomTreeItem(c)));
        }
        return Promise.resolve([]);
    }
}

class SbomTreeItem extends vscode.TreeItem {
    constructor(componentOrLabel: SbomComponent | string, description?: string) {
        if (typeof componentOrLabel === 'string') {
            super(componentOrLabel, vscode.TreeItemCollapsibleState.None);
            this.description = description;
            this.iconPath = new vscode.ThemeIcon('info');
        } else {
            const component = componentOrLabel;
            super(`${component.name}@${component.version}`, vscode.TreeItemCollapsibleState.None);
            this.description = component.type;
            this.tooltip = `PURL: ${component.purl || 'N/A'}\nLicenses: ${component.licenses?.join(', ') || 'Unknown'}`;
            this.contextValue = 'component';
            this.iconPath = SbomTreeItem.getIcon(component.type);
        }
    }

    private static getIcon(type: ComponentType): vscode.ThemeIcon {
        switch (type) {
            case ComponentType.library:
                return new vscode.ThemeIcon('library');
            case ComponentType.framework:
                return new vscode.ThemeIcon('extensions');
            case ComponentType.application:
                return new vscode.ThemeIcon('window');
            case ComponentType.container:
                return new vscode.ThemeIcon('package');
            default:
                return new vscode.ThemeIcon('file');
        }
    }
}
