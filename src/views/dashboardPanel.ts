import * as vscode from 'vscode';

export class DashboardPanel {
    public static currentPanel: DashboardPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this._panel = panel;
        this._extensionUri = extensionUri;

        this._update();

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        this._panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'runScan':
                        vscode.commands.executeCommand('joe.runSecurityScan');
                        return;
                    case 'generateSbom':
                        vscode.commands.executeCommand('joe.generateSBOM');
                        return;
                    case 'viewCompliance':
                        vscode.commands.executeCommand('joe.viewComplianceMatrix');
                        return;
                }
            },
            null,
            this._disposables
        );
    }

    public static createOrShow(extensionUri: vscode.Uri): void {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (DashboardPanel.currentPanel) {
            DashboardPanel.currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'joeDashboard',
            'J.O.E. Dashboard',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                localResourceRoots: [extensionUri]
            }
        );

        DashboardPanel.currentPanel = new DashboardPanel(panel, extensionUri);
    }

    private _update(): void {
        this._panel.webview.html = this._getHtmlContent();
    }

    private _getHtmlContent(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>J.O.E. Dashboard</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            padding: 20px;
            background: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 {
            color: var(--vscode-textLink-foreground);
            margin-bottom: 5px;
        }
        .header p {
            color: var(--vscode-descriptionForeground);
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: var(--vscode-editor-selectionBackground);
            border-radius: 8px;
            padding: 20px;
            border: 1px solid var(--vscode-panel-border);
        }
        .card h3 {
            margin-top: 0;
            color: var(--vscode-textLink-foreground);
        }
        .stat {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat.critical { color: #f44336; }
        .stat.warning { color: #ff9800; }
        .stat.success { color: #4caf50; }
        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            justify-content: center;
        }
        button {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        button:hover {
            background: var(--vscode-button-hoverBackground);
        }
        .gauge-container {
            text-align: center;
            padding: 20px;
        }
        .gauge {
            width: 150px;
            height: 75px;
            background: conic-gradient(from 180deg, #4caf50 0deg, #ff9800 180deg, #f44336 270deg, transparent 270deg);
            border-radius: 150px 150px 0 0;
            position: relative;
            margin: 0 auto;
        }
        .gauge-inner {
            position: absolute;
            bottom: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 100px;
            height: 50px;
            background: var(--vscode-editor-background);
            border-radius: 100px 100px 0 0;
        }
        .gauge-value {
            position: absolute;
            bottom: 5px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 1.5em;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>J.O.E. DevSecOps Arsenal</h1>
        <p>Joint-Ops-Engine - Your All-in-One Security Command Center</p>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Security Findings</h3>
            <div class="stat critical">0</div>
            <p>Critical vulnerabilities</p>
        </div>
        <div class="card">
            <h3>SBOM Components</h3>
            <div class="stat">--</div>
            <p>Dependencies tracked</p>
        </div>
        <div class="card">
            <h3>Compliance Score</h3>
            <div class="stat success">--%</div>
            <p>CMMC 2.0</p>
        </div>
        <div class="card gauge-container">
            <h3>CMMC Level</h3>
            <div class="gauge">
                <div class="gauge-inner">
                    <div class="gauge-value">--</div>
                </div>
            </div>
        </div>
    </div>

    <div class="actions">
        <button onclick="runScan()">Run Security Scan</button>
        <button onclick="generateSbom()">Generate SBOM</button>
        <button onclick="viewCompliance()">View Compliance Matrix</button>
    </div>

    <script>
        const vscode = acquireVsCodeApi();

        function runScan() {
            vscode.postMessage({ command: 'runScan' });
        }

        function generateSbom() {
            vscode.postMessage({ command: 'generateSbom' });
        }

        function viewCompliance() {
            vscode.postMessage({ command: 'viewCompliance' });
        }
    </script>
</body>
</html>`;
    }

    public dispose(): void {
        DashboardPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
