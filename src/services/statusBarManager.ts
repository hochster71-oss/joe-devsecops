import * as vscode from 'vscode';
import { RiskScore } from '../types';

export class StatusBarManager {
    private riskBadge: vscode.StatusBarItem;
    private cmmcGauge: vscode.StatusBarItem;
    private context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.riskBadge = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            100
        );
        this.cmmcGauge = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            99
        );
    }

    initialize(): void {
        // Risk badge
        this.riskBadge.text = '$(shield) J.O.E.';
        this.riskBadge.tooltip = 'Click to open J.O.E. Dashboard';
        this.riskBadge.command = 'joe.openDashboard';
        this.riskBadge.show();

        // CMMC gauge
        this.cmmcGauge.text = '$(verified) CMMC: --';
        this.cmmcGauge.tooltip = 'CMMC Compliance Level';
        this.cmmcGauge.command = 'joe.viewComplianceMatrix';
        this.cmmcGauge.show();

        this.context.subscriptions.push(this.riskBadge, this.cmmcGauge);
    }

    updateRiskBadge(score?: RiskScore): void {
        if (!score) {
            this.riskBadge.text = '$(shield) J.O.E.';
            this.riskBadge.backgroundColor = undefined;
            return;
        }

        const { critical, high, medium, low } = score;

        if (critical > 0) {
            this.riskBadge.text = `$(error) ${critical} CRIT`;
            this.riskBadge.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        } else if (high > 0) {
            this.riskBadge.text = `$(warning) ${high} HIGH`;
            this.riskBadge.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else if (medium > 0) {
            this.riskBadge.text = `$(info) ${medium} MED`;
            this.riskBadge.backgroundColor = undefined;
        } else {
            this.riskBadge.text = '$(pass) Secure';
            this.riskBadge.backgroundColor = undefined;
        }

        this.riskBadge.tooltip = `Critical: ${critical} | High: ${high} | Medium: ${medium} | Low: ${low}`;
    }

    updateCmmcGauge(level: number): void {
        const icons = ['$(circle-slash)', '$(circle-outline)', '$(circle-filled)', '$(verified)'];
        const icon = level >= 2 ? icons[3] : icons[Math.min(level, icons.length - 1)];
        this.cmmcGauge.text = `${icon} CMMC: L${level}`;
        this.cmmcGauge.tooltip = `CMMC 2.0 Compliance Level: ${level}/3`;
    }
}
