import * as vscode from 'vscode';

export class Config {
    private static readonly section = 'joe';

    static get<T>(key: string, defaultValue: T): T {
        return vscode.workspace.getConfiguration(this.section).get<T>(key, defaultValue);
    }

    static async set(key: string, value: unknown, global = false): Promise<void> {
        await vscode.workspace.getConfiguration(this.section).update(
            key,
            value,
            global ? vscode.ConfigurationTarget.Global : vscode.ConfigurationTarget.Workspace
        );
    }

    // Scanner settings
    static get enableAutoScan(): boolean {
        return this.get<boolean>('enableAutoScan', false);
    }

    static get semgrepEnabled(): boolean {
        return this.get<boolean>('scanners.semgrep.enabled', true);
    }

    static get trivyEnabled(): boolean {
        return this.get<boolean>('scanners.trivy.enabled', true);
    }

    static get snykEnabled(): boolean {
        return this.get<boolean>('scanners.snyk.enabled', false);
    }

    static get snykApiKey(): string {
        return this.get<string>('scanners.snyk.apiKey', '');
    }

    // SBOM settings
    static get sbomFormat(): 'cyclonedx' | 'spdx' {
        return this.get<'cyclonedx' | 'spdx'>('sbom.format', 'cyclonedx');
    }

    // Compliance settings
    static get complianceFramework(): string {
        return this.get<string>('compliance.framework', 'cmmc-2');
    }

    // Dependency-Track settings
    static get dependencyTrackUrl(): string {
        return this.get<string>('dependencyTrack.url', '');
    }

    static get dependencyTrackApiKey(): string {
        return this.get<string>('dependencyTrack.apiKey', '');
    }

    // PQC settings
    static get pqcEnabled(): boolean {
        return this.get<boolean>('pqc.enabled', false);
    }
}
