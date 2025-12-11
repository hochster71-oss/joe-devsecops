#!/usr/bin/env node

import { execAsync } from './utils/execAsync';
import * as fs from 'fs';
import * as path from 'path';

class JOECLI {
    async runScan(workspacePath: string = process.cwd()): Promise<void> {
        console.log('Starting security scan...');
        console.log(`Scanning workspace: ${workspacePath}`);

        try {
            // Run Semgrep if available
            console.log('Running Semgrep scan...');
            try {
                await execAsync(
                    `semgrep scan --json --config auto "${workspacePath}"`,
                    { maxBuffer: 10 * 1024 * 1024 }
                );
                console.log('Semgrep scan completed');
            } catch (error) {
                console.log('Semgrep not available or failed');
            }

            // Run Trivy if available
            console.log('Running Trivy scan...');
            try {
                await execAsync(
                    `trivy fs "${workspacePath}"`,
                    { maxBuffer: 10 * 1024 * 1024 }
                );
                console.log('Trivy scan completed');
            } catch (error) {
                console.log('Trivy not available or failed');
            }

            console.log('Scan completed!');
        } catch (error) {
            console.error('Scan failed:', error);
            process.exit(1);
        }
    }

    async generateSBOM(workspacePath: string = process.cwd()): Promise<void> {
        console.log('Generating SBOM...');
        console.log(`Generating SBOM for: ${workspacePath}`);

        try {
            // Use Syft if available
            console.log('Running Syft SBOM generation...');
            try {
                const outputPath = path.join(workspacePath, 'sbom.json');
                await execAsync(
                    `syft . -o json > "${outputPath}"`,
                    { cwd: workspacePath }
                );
                console.log(`SBOM generated: ${outputPath}`);
            } catch (error) {
                console.log('Syft not available, trying Trivy...');
                // Fallback to Trivy SBOM
                const outputPath = path.join(workspacePath, 'sbom-trivy.json');
                await execAsync(
                    `trivy sbom "${workspacePath}" -o "${outputPath}"`,
                    { cwd: workspacePath }
                );
                console.log(`SBOM generated: ${outputPath}`);
            }
        } catch (error) {
            console.error('SBOM generation failed:', error);
            process.exit(1);
        }
    }

    async runComplianceCheck(): Promise<void> {
        console.log('Running compliance check...');
        console.log('Running basic compliance checks...');

        // Basic checks
        const issues: string[] = [];

        // Check for package.json
        if (fs.existsSync('package.json')) {
            const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
            if (!pkg.license) {
                issues.push('No license specified in package.json');
            }
            if (!pkg.repository) {
                issues.push('No repository specified in package.json');
            }
        }

        // Check for security files
        const securityFiles = ['.gitignore', 'SECURITY.md', 'CODE_OF_CONDUCT.md'];
        securityFiles.forEach(file => {
            if (!fs.existsSync(file)) {
                issues.push(`Missing ${file}`);
            }
        });

        if (issues.length === 0) {
            console.log('✅ Basic compliance checks passed');
        } else {
            console.log('❌ Compliance issues found:');
            issues.forEach(issue => console.log(`  - ${issue}`));
        }
    }

    showHelp(): void {
        console.log(`
J.O.E. DevSecOps CLI - Joint-Ops-Engine

Usage: joe <command> [options]

Commands:
  scan [path]          Run security scan on workspace
  sbom [path]          Generate SBOM for workspace
  compliance          Run compliance policy check
  help                Show this help

Examples:
  joe scan .
  joe sbom /path/to/project
  joe compliance
`);
    }
}

async function main() {
    const args = process.argv.slice(2);
    const command = args[0];

    const cli = new JOECLI();

    switch (command) {
        case 'scan':
            await cli.runScan();
            break;
        case 'sbom':
            await cli.generateSBOM();
            break;
        case 'compliance':
            await cli.runComplianceCheck();
            break;
        case 'help':
        default:
            cli.showHelp();
            break;
    }
}

main().catch(console.error);