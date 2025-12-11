import * as vscode from 'vscode';

export class Logger {
    private static outputChannel: vscode.OutputChannel | undefined;

    private static getChannel(): vscode.OutputChannel {
        if (!this.outputChannel) {
            this.outputChannel = vscode.window.createOutputChannel('J.O.E. DevSecOps');
        }
        return this.outputChannel;
    }

    private static formatMessage(level: string, message: string): string {
        const timestamp = new Date().toISOString();
        return `[${timestamp}] [${level}] ${message}`;
    }

    static info(message: string): void {
        this.getChannel().appendLine(this.formatMessage('INFO', message));
    }

    static warn(message: string): void {
        this.getChannel().appendLine(this.formatMessage('WARN', message));
    }

    static error(message: string, error?: unknown): void {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.getChannel().appendLine(this.formatMessage('ERROR', `${message}: ${errorMessage}`));
    }

    static debug(message: string): void {
        this.getChannel().appendLine(this.formatMessage('DEBUG', message));
    }

    static show(): void {
        this.getChannel().show();
    }
}
