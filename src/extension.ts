import * as vscode from 'vscode';
import { FindingsTreeProvider } from './providers/findingsTreeProvider';
import { SbomTreeProvider } from './providers/sbomTreeProvider';
import { ComplianceTreeProvider } from './providers/complianceTreeProvider';
import { ToolsTreeProvider } from './providers/toolsTreeProvider';
import { StatusBarManager } from './services/statusBarManager';
import { ScannerService } from './services/scannerService';
import { SbomService } from './services/sbomService';
import { ComplianceService } from './services/complianceService';
import { DashboardPanel } from './views/dashboardPanel';
import { Logger } from './utils/logger';

let statusBarManager: StatusBarManager;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    Logger.info('J.O.E. DevSecOps Arsenal is activating...');

    // Initialize services
    const scannerService = new ScannerService(context);
    const sbomService = new SbomService(context);
    const complianceService = new ComplianceService(context);

    // Initialize tree providers
    const findingsProvider = new FindingsTreeProvider(scannerService);
    const sbomProvider = new SbomTreeProvider(sbomService);
    const complianceProvider = new ComplianceTreeProvider(complianceService);
    const toolsProvider = new ToolsTreeProvider();

    // Register tree views
    context.subscriptions.push(
        vscode.window.registerTreeDataProvider('joe.findingsView', findingsProvider),
        vscode.window.registerTreeDataProvider('joe.sbomView', sbomProvider),
        vscode.window.registerTreeDataProvider('joe.complianceView', complianceProvider),
        vscode.window.registerTreeDataProvider('joe.toolsView', toolsProvider)
    );

    // Initialize status bar
    statusBarManager = new StatusBarManager(context);
    statusBarManager.initialize();

    // Register commands
    registerCommands(context, scannerService, sbomService, complianceService, findingsProvider);

    Logger.info('J.O.E. DevSecOps Arsenal activated successfully');
    vscode.window.showInformationMessage('J.O.E. DevSecOps Arsenal is ready!');
}

function registerCommands(
    context: vscode.ExtensionContext,
    scannerService: ScannerService,
    sbomService: SbomService,
    complianceService: ComplianceService,
    findingsProvider: FindingsTreeProvider
): void {
    // Dashboard command
    context.subscriptions.push(
        vscode.commands.registerCommand('joe.openDashboard', () => {
            DashboardPanel.createOrShow(context.extensionUri);
        })
    );

    // Security scan command
    context.subscriptions.push(
        vscode.commands.registerCommand('joe.runSecurityScan', async () => {
            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'J.O.E. Security Scan',
                    cancellable: true
                },
                async (progress) => {
                    progress.report({ message: 'Running security scans...' });
                    try {
                        await scannerService.runAllScans();
                        findingsProvider.refresh();
                        statusBarManager.updateRiskBadge();
                        vscode.window.showInformationMessage('Security scan completed');
                    } catch (error) {
                        Logger.error('Security scan failed', error);
                        vscode.window.showErrorMessage(`Security scan failed: ${error}`);
                    }
                }
            );
        })
    );

    // SBOM generation command
    context.subscriptions.push(
        vscode.commands.registerCommand('joe.generateSBOM', async () => {
            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'Generating SBOM',
                    cancellable: false
                },
                async (progress) => {
                    progress.report({ message: 'Analyzing dependencies...' });
                    try {
                        const sbomPath = await sbomService.generateSBOM();
                        vscode.window.showInformationMessage(`SBOM generated: ${sbomPath}`);
                    } catch (error) {
                        Logger.error('SBOM generation failed', error);
                        vscode.window.showErrorMessage(`SBOM generation failed: ${error}`);
                    }
                }
            );
        })
    );

    // Compliance matrix command
    context.subscriptions.push(
        vscode.commands.registerCommand('joe.viewComplianceMatrix', () => {
            complianceService.showComplianceMatrix();
        })
    );

    // Policy check command
    context.subscriptions.push(
        vscode.commands.registerCommand('joe.runPolicyCheck', async () => {
            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'Running Policy Check',
                    cancellable: false
                },
                async (progress) => {
                    progress.report({ message: 'Evaluating policies...' });
                    try {
                        await complianceService.runPolicyCheck();
                        vscode.window.showInformationMessage('Policy check completed');
                    } catch (error) {
                        Logger.error('Policy check failed', error);
                        vscode.window.showErrorMessage(`Policy check failed: ${error}`);
                    }
                }
            );
        })
    );

    // Report generation command
    context.subscriptions.push(
        vscode.commands.registerCommand('joe.generateReport', async () => {
            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: 'Generating Compliance Report',
                    cancellable: false
                },
                async (progress) => {
                    progress.report({ message: 'Generating report...' });
                    try {
                        const reportPath = await complianceService.generateReport();
                        vscode.window.showInformationMessage(`Report generated: ${reportPath}`);
                    } catch (error) {
                        Logger.error('Report generation failed', error);
                        vscode.window.showErrorMessage(`Report generation failed: ${error}`);
                    }
                }
            );
        })
    );

    // Refresh findings command
    context.subscriptions.push(
        vscode.commands.registerCommand('joe.refreshFindings', () => {
            findingsProvider.refresh();
        })
    );

    // Attack surface graph command
    // context.subscriptions.push(
    //     vscode.commands.registerCommand('joe.showAttackSurface', () => {
    //         complianceService.showAttackSurface();
    //     })
    // );
}

export function deactivate(): void {
    Logger.info('J.O.E. DevSecOps Arsenal is deactivating...');
    // if (statusBarManager) {
    //     statusBarManager.dispose();
    // }
}