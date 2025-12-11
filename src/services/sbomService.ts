import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import { SbomComponent, ComponentType } from '../types';
import { Config } from '../utils/config';
import { Logger } from '../utils/logger';

const execAsync = promisify(exec);

export interface CycloneDXLicense {
    license?: {
        id?: string;
    };
    expression?: string;
}

export class SbomService {
    private context: vscode.ExtensionContext;
    private components: SbomComponent[] = [];

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    async generateSBOM(): Promise<string> {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspaceFolder) {
            throw new Error('No workspace folder open');
        }

        const format = Config.sbomFormat;
        const outputFile = path.join(workspaceFolder, `sbom.${format === 'cyclonedx' ? 'json' : 'spdx.json'}`);

        Logger.info(`Generating SBOM in ${format} format...`);

        try {
            // Use Syft to generate SBOM
            const formatFlag = format === 'cyclonedx' ? 'cyclonedx-json' : 'spdx-json';
            await execAsync(
                `syft "${workspaceFolder}" -o ${formatFlag}=${outputFile}`,
                { maxBuffer: 10 * 1024 * 1024 }
            );

            // Parse and store components
            await this.parseSBOM(outputFile, format);

            // Upload to Dependency-Track if configured
            if (Config.dependencyTrackUrl && Config.dependencyTrackApiKey) {
                await this.uploadToDependencyTrack(outputFile);
            }

            Logger.info(`SBOM generated: ${outputFile}`);
            return outputFile;
        } catch (error) {
            Logger.error('SBOM generation failed', error);
            throw error;
        }
    }

    private async parseSBOM(filePath: string, format: string): Promise<void> {
        const fs = await import('fs').then(m => m.promises);
        const content = await fs.readFile(filePath, 'utf-8');
        const data = JSON.parse(content);

        this.components = [];

        if (format === 'cyclonedx') {
            for (const comp of data.components || []) {
                this.components.push({
                    name: comp.name,
                    version: comp.version,
                    type: this.mapComponentType(comp.type),
                    purl: comp.purl,
                    licenses: comp.licenses?.map((l: CycloneDXLicense) => l.license?.id || l.expression)
                });
            }
        } else {
            // SPDX format
            for (const pkg of data.packages || []) {
                this.components.push({
                    name: pkg.name,
                    version: pkg.versionInfo,
                    type: ComponentType.library,
                    licenses: pkg.licenseDeclared ? [pkg.licenseDeclared] : []
                });
            }
        }
    }

    private mapComponentType(type: string): ComponentType {
        // eslint-disable-next-line @typescript-eslint/naming-convention
        const map: Record<string, ComponentType> = {
            'library': ComponentType.library,
            'framework': ComponentType.framework,
            'application': ComponentType.application,
            'container': ComponentType.container,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            'operating-system': ComponentType.operatingSystem
        };
        return map[type] || ComponentType.library;
    }

    private async uploadToDependencyTrack(sbomPath: string): Promise<void> {
        Logger.info('Uploading SBOM to Dependency-Track...');

        try {
            const fs = await import('fs').then(m => m.promises);
            const sbomContent = await fs.readFile(sbomPath, 'utf-8');
            const base64Sbom = Buffer.from(sbomContent).toString('base64');

            const axios = (await import('axios')).default;
            await axios.put(
                `${Config.dependencyTrackUrl}/api/v1/bom`,
                {
                    projectName: vscode.workspace.name || 'unknown',
                    projectVersion: '1.0.0',
                    bom: base64Sbom
                },
                {
                    headers: {
                        // eslint-disable-next-line @typescript-eslint/naming-convention
                        'X-Api-Key': Config.dependencyTrackApiKey,
                        // eslint-disable-next-line @typescript-eslint/naming-convention
                        'Content-Type': 'application/json'
                    }
                }
            );

            Logger.info('SBOM uploaded to Dependency-Track');
        } catch (error) {
            Logger.error('Failed to upload SBOM to Dependency-Track', error);
        }
    }

    getComponents(): SbomComponent[] {
        return this.components;
    }

    showAttackSurfaceGraph(): void {
        const panel = vscode.window.createWebviewPanel(
            'joeAttackSurface',
            'Attack Surface Graph',
            vscode.ViewColumn.One,
            { enableScripts: true }
        );

        panel.webview.html = this.getAttackSurfaceHtml();
    }

    private getAttackSurfaceHtml(): string {
        const nodes = this.components.map((c, i) => ({
            id: i,
            name: `${c.name}@${c.version}`,
            hasVulns: (c.vulnerabilities?.length || 0) > 0
        }));

        return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Attack Surface Graph</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { margin: 0; background: var(--vscode-editor-background); }
        .node { cursor: pointer; }
        .node.vulnerable { fill: #f44336; }
        .node.safe { fill: #4caf50; }
        .link { stroke: #999; stroke-opacity: 0.6; }
        text { fill: var(--vscode-editor-foreground); font-size: 10px; }
    </style>
</head>
<body>
    <svg width="100%" height="600"></svg>
    <script>
        const nodes = ${JSON.stringify(nodes)};
        // D3.js visualization code would go here
        const svg = d3.select("svg");
        const width = window.innerWidth;
        const height = 600;

        svg.selectAll("circle")
            .data(nodes)
            .enter()
            .append("circle")
            .attr("r", 20)
            .attr("cx", (d, i) => 50 + (i % 10) * 80)
            .attr("cy", (d, i) => 50 + Math.floor(i / 10) * 80)
            .attr("class", d => d.hasVulns ? "node vulnerable" : "node safe")
            .append("title")
            .text(d => d.name);
    </script>
</body>
</html>`;
    }
}
