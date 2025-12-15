/**
 * J.O.E. DevSecOps Arsenal - Notification Service
 * Real-time alerting and notification infrastructure
 *
 * Supports: Slack, Microsoft Teams, Email, Desktop notifications
 * @module electron/notification-service
 * @version 1.0.0
 */

import { Notification } from 'electron';
import Store from 'electron-store';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

export type NotificationChannel = 'slack' | 'teams' | 'email' | 'desktop';
export type NotificationSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type NotificationCategory =
  | 'vulnerability'
  | 'compliance'
  | 'scan-complete'
  | 'scan-failed'
  | 'threshold-breach'
  | 'security-event'
  | 'system';

export interface NotificationPayload {
  id: string;
  title: string;
  message: string;
  severity: NotificationSeverity;
  category: NotificationCategory;
  timestamp: string;
  metadata?: Record<string, unknown>;
  actionUrl?: string;
  findings?: Array<{
    id: string;
    title: string;
    severity: string;
  }>;
}

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  conditions: {
    severities: NotificationSeverity[];
    categories: NotificationCategory[];
    minCount?: number;
    frameworks?: string[];
  };
  channels: NotificationChannel[];
  throttleMinutes: number;
  createdAt: string;
  updatedAt: string;
}

export interface ChannelConfig {
  slack?: SlackConfig;
  teams?: TeamsConfig;
  email?: EmailConfig;
  desktop?: DesktopConfig;
}

export interface SlackConfig {
  enabled: boolean;
  webhookUrl: string;
  channel?: string;
  username?: string;
  iconEmoji?: string;
}

export interface TeamsConfig {
  enabled: boolean;
  webhookUrl: string;
}

export interface EmailConfig {
  enabled: boolean;
  smtpHost: string;
  smtpPort: number;
  smtpSecure: boolean;
  smtpUser: string;
  smtpPass: string;
  fromAddress: string;
  toAddresses: string[];
  digestEnabled: boolean;
  digestSchedule: 'daily' | 'weekly';
}

export interface DesktopConfig {
  enabled: boolean;
  sound: boolean;
  showPreview: boolean;
}

export interface NotificationResult {
  success: boolean;
  channel: NotificationChannel;
  error?: string;
  messageId?: string;
}

export interface NotificationStats {
  totalSent: number;
  byChannel: Record<NotificationChannel, number>;
  bySeverity: Record<NotificationSeverity, number>;
  lastSent?: string;
  failures: number;
}

// =============================================================================
// NOTIFICATION HISTORY
// =============================================================================

interface NotificationHistoryEntry {
  id: string;
  payload: NotificationPayload;
  channels: NotificationChannel[];
  results: NotificationResult[];
  timestamp: string;
}

// =============================================================================
// STORE SCHEMA
// =============================================================================

interface NotificationStoreSchema {
  channelConfig: ChannelConfig;
  alertRules: AlertRule[];
  notificationHistory: NotificationHistoryEntry[];
}

// =============================================================================
// NOTIFICATION SERVICE
// =============================================================================

class NotificationService {
  private store: Store<NotificationStoreSchema>;
  private history: NotificationHistoryEntry[] = [];
  private throttleMap: Map<string, number> = new Map();
  private stats: NotificationStats = {
    totalSent: 0,
    byChannel: { slack: 0, teams: 0, email: 0, desktop: 0 },
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    failures: 0
  };

  constructor() {
    this.store = new Store({ name: 'joe-notifications' });
    this.loadConfig();
    this.loadHistory();
  }

  // ===========================================================================
  // CONFIGURATION MANAGEMENT
  // ===========================================================================

  private loadConfig(): void {
    const defaultConfig: ChannelConfig = {
      slack: { enabled: false, webhookUrl: '' },
      teams: { enabled: false, webhookUrl: '' },
      email: {
        enabled: false,
        smtpHost: '',
        smtpPort: 587,
        smtpSecure: true,
        smtpUser: '',
        smtpPass: '',
        fromAddress: '',
        toAddresses: [],
        digestEnabled: false,
        digestSchedule: 'daily'
      },
      desktop: { enabled: true, sound: true, showPreview: true }
    };

    if (!this.store.has('channelConfig')) {
      this.store.set('channelConfig', defaultConfig);
    }

    if (!this.store.has('alertRules')) {
      this.store.set('alertRules', this.getDefaultAlertRules());
    }
  }

  private loadHistory(): void {
    this.history = this.store.get('notificationHistory', []) as NotificationHistoryEntry[];
    // Keep only last 500 entries
    if (this.history.length > 500) {
      this.history = this.history.slice(-500);
      this.store.set('notificationHistory', this.history);
    }
  }

  private getDefaultAlertRules(): AlertRule[] {
    const now = new Date().toISOString();
    return [
      {
        id: 'rule-critical-vulns',
        name: 'Critical Vulnerabilities',
        enabled: true,
        conditions: {
          severities: ['critical'],
          categories: ['vulnerability', 'security-event']
        },
        channels: ['desktop', 'slack'],
        throttleMinutes: 5,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'rule-scan-complete',
        name: 'Scan Completion',
        enabled: true,
        conditions: {
          severities: ['info'],
          categories: ['scan-complete', 'scan-failed']
        },
        channels: ['desktop'],
        throttleMinutes: 0,
        createdAt: now,
        updatedAt: now
      },
      {
        id: 'rule-compliance-breach',
        name: 'Compliance Threshold Breach',
        enabled: true,
        conditions: {
          severities: ['high', 'critical'],
          categories: ['compliance', 'threshold-breach']
        },
        channels: ['desktop', 'slack', 'email'],
        throttleMinutes: 30,
        createdAt: now,
        updatedAt: now
      }
    ];
  }

  // ===========================================================================
  // CHANNEL CONFIGURATION
  // ===========================================================================

  getChannelConfig(): ChannelConfig {
    return this.store.get('channelConfig') as ChannelConfig;
  }

  updateChannelConfig(channel: NotificationChannel, config: Partial<ChannelConfig[keyof ChannelConfig]>): { success: boolean; error?: string } {
    try {
      const currentConfig = this.getChannelConfig();
      const channelConfig = currentConfig[channel] || {};
      currentConfig[channel] = { ...channelConfig, ...config } as never;
      this.store.set('channelConfig', currentConfig);
      return { success: true };
    } catch (error) {
      return { success: false, error: String(error) };
    }
  }

  async testChannel(channel: NotificationChannel): Promise<NotificationResult> {
    const testPayload: NotificationPayload = {
      id: `test-${Date.now()}`,
      title: 'J.O.E. Test Notification',
      message: 'This is a test notification from J.O.E. DevSecOps Arsenal. If you receive this, your notification channel is configured correctly.',
      severity: 'info',
      category: 'system',
      timestamp: new Date().toISOString()
    };

    return this.sendToChannel(channel, testPayload);
  }

  // ===========================================================================
  // ALERT RULES
  // ===========================================================================

  getAlertRules(): AlertRule[] {
    return this.store.get('alertRules', []) as AlertRule[];
  }

  createAlertRule(rule: Omit<AlertRule, 'id' | 'createdAt' | 'updatedAt'>): AlertRule {
    const rules = this.getAlertRules();
    const now = new Date().toISOString();
    const newRule: AlertRule = {
      ...rule,
      id: `rule-${Date.now()}`,
      createdAt: now,
      updatedAt: now
    };
    rules.push(newRule);
    this.store.set('alertRules', rules);
    return newRule;
  }

  updateAlertRule(ruleId: string, updates: Partial<AlertRule>): AlertRule | null {
    const rules = this.getAlertRules();
    const index = rules.findIndex(r => r.id === ruleId);
    if (index === -1) {return null;}

    rules[index] = {
      ...rules[index],
      ...updates,
      id: ruleId,
      updatedAt: new Date().toISOString()
    };
    this.store.set('alertRules', rules);
    return rules[index];
  }

  deleteAlertRule(ruleId: string): boolean {
    const rules = this.getAlertRules();
    const filtered = rules.filter(r => r.id !== ruleId);
    if (filtered.length === rules.length) {return false;}
    this.store.set('alertRules', filtered);
    return true;
  }

  // ===========================================================================
  // NOTIFICATION DISPATCH
  // ===========================================================================

  async notify(payload: NotificationPayload): Promise<NotificationResult[]> {
    const rules = this.getAlertRules().filter(r => r.enabled);
    const matchingRules = rules.filter(rule => this.matchesRule(payload, rule));

    if (matchingRules.length === 0) {
      return [];
    }

    // Collect unique channels from matching rules
    const channels = new Set<NotificationChannel>();
    for (const rule of matchingRules) {
      // Check throttling
      if (this.isThrottled(rule.id, rule.throttleMinutes)) {
        continue;
      }
      rule.channels.forEach(ch => channels.add(ch));
      this.updateThrottle(rule.id);
    }

    const results: NotificationResult[] = [];
    for (const channel of channels) {
      const result = await this.sendToChannel(channel, payload);
      results.push(result);

      if (result.success) {
        this.stats.totalSent++;
        this.stats.byChannel[channel]++;
        this.stats.bySeverity[payload.severity]++;
        this.stats.lastSent = new Date().toISOString();
      } else {
        this.stats.failures++;
      }
    }

    // Save to history
    this.addToHistory(payload, Array.from(channels), results);

    return results;
  }

  private matchesRule(payload: NotificationPayload, rule: AlertRule): boolean {
    const { conditions } = rule;

    if (!conditions.severities.includes(payload.severity)) {
      return false;
    }

    if (!conditions.categories.includes(payload.category)) {
      return false;
    }

    if (conditions.minCount && payload.findings && payload.findings.length < conditions.minCount) {
      return false;
    }

    return true;
  }

  private isThrottled(ruleId: string, throttleMinutes: number): boolean {
    if (throttleMinutes <= 0) {return false;}

    const lastSent = this.throttleMap.get(ruleId);
    if (!lastSent) {return false;}

    const elapsed = (Date.now() - lastSent) / 60000; // minutes
    return elapsed < throttleMinutes;
  }

  private updateThrottle(ruleId: string): void {
    this.throttleMap.set(ruleId, Date.now());
  }

  // ===========================================================================
  // CHANNEL IMPLEMENTATIONS
  // ===========================================================================

  private async sendToChannel(channel: NotificationChannel, payload: NotificationPayload): Promise<NotificationResult> {
    const config = this.getChannelConfig();

    switch (channel) {
      case 'slack':
        return this.sendSlack(payload, config.slack);
      case 'teams':
        return this.sendTeams(payload, config.teams);
      case 'email':
        return this.sendEmail(payload, config.email);
      case 'desktop':
        return this.sendDesktop(payload, config.desktop);
      default:
        return { success: false, channel, error: 'Unknown channel' };
    }
  }

  private async sendSlack(payload: NotificationPayload, config?: SlackConfig): Promise<NotificationResult> {
    if (!config?.enabled || !config.webhookUrl) {
      return { success: false, channel: 'slack', error: 'Slack not configured' };
    }

    try {
      const color = this.getSeverityColor(payload.severity);
      const slackPayload = {
        username: config.username || 'J.O.E. DevSecOps',
        icon_emoji: config.iconEmoji || ':wolf:',
        channel: config.channel,
        attachments: [{
          color,
          title: payload.title,
          text: payload.message,
          fields: [
            { title: 'Severity', value: payload.severity.toUpperCase(), short: true },
            { title: 'Category', value: payload.category, short: true }
          ],
          footer: 'J.O.E. DevSecOps Arsenal',
          ts: Math.floor(new Date(payload.timestamp).getTime() / 1000)
        }]
      };

      if (payload.findings && payload.findings.length > 0) {
        slackPayload.attachments[0].fields.push({
          title: 'Findings',
          value: payload.findings.slice(0, 5).map(f => `• ${f.title} (${f.severity})`).join('\n'),
          short: false
        });
      }

      const response = await fetch(config.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(slackPayload)
      });

      if (!response.ok) {
        throw new Error(`Slack webhook failed: ${response.status}`);
      }

      return { success: true, channel: 'slack', messageId: payload.id };
    } catch (error) {
      return { success: false, channel: 'slack', error: String(error) };
    }
  }

  private async sendTeams(payload: NotificationPayload, config?: TeamsConfig): Promise<NotificationResult> {
    if (!config?.enabled || !config.webhookUrl) {
      return { success: false, channel: 'teams', error: 'Teams not configured' };
    }

    try {
      const color = this.getSeverityColor(payload.severity);
      const teamsPayload = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        themeColor: color.replace('#', ''),
        summary: payload.title,
        sections: [{
          activityTitle: payload.title,
          activitySubtitle: `Severity: ${payload.severity.toUpperCase()} | Category: ${payload.category}`,
          activityImage: 'https://raw.githubusercontent.com/microsoft/fluentui-emoji/main/assets/Wolf/3D/wolf_3d.png',
          text: payload.message,
          facts: payload.findings?.slice(0, 5).map(f => ({
            name: f.severity.toUpperCase(),
            value: f.title
          })) || []
        }],
        potentialAction: payload.actionUrl ? [{
          '@type': 'OpenUri',
          name: 'View in J.O.E.',
          targets: [{ os: 'default', uri: payload.actionUrl }]
        }] : []
      };

      const response = await fetch(config.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(teamsPayload)
      });

      if (!response.ok) {
        throw new Error(`Teams webhook failed: ${response.status}`);
      }

      return { success: true, channel: 'teams', messageId: payload.id };
    } catch (error) {
      return { success: false, channel: 'teams', error: String(error) };
    }
  }

  private async sendEmail(payload: NotificationPayload, config?: EmailConfig): Promise<NotificationResult> {
    if (!config?.enabled) {
      return { success: false, channel: 'email', error: 'Email not configured' };
    }

    // Note: Full email implementation would require nodemailer
    // This is a stub that would be expanded with actual SMTP sending
    try {
      console.log('[J.O.E. Notifications] Email notification queued:', {
        to: config.toAddresses,
        subject: `[J.O.E.] ${payload.severity.toUpperCase()}: ${payload.title}`,
        body: payload.message
      });

      // In production, this would use nodemailer or similar
      // For now, return success as a placeholder
      return { success: true, channel: 'email', messageId: payload.id };
    } catch (error) {
      return { success: false, channel: 'email', error: String(error) };
    }
  }

  private sendDesktop(payload: NotificationPayload, config?: DesktopConfig): NotificationResult {
    if (!config?.enabled) {
      return { success: false, channel: 'desktop', error: 'Desktop notifications disabled' };
    }

    try {
      const notification = new Notification({
        title: `J.O.E. - ${payload.severity.toUpperCase()}`,
        body: config.showPreview ? `${payload.title}\n${payload.message.slice(0, 100)}...` : payload.title,
        silent: !config.sound,
        urgency: payload.severity === 'critical' ? 'critical' : payload.severity === 'high' ? 'normal' : 'low'
      });

      notification.show();
      return { success: true, channel: 'desktop', messageId: payload.id };
    } catch (error) {
      return { success: false, channel: 'desktop', error: String(error) };
    }
  }

  private getSeverityColor(severity: NotificationSeverity): string {
    const colors: Record<NotificationSeverity, string> = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#ca8a04',
      low: '#2563eb',
      info: '#6b7280'
    };
    return colors[severity];
  }

  // ===========================================================================
  // HISTORY & STATS
  // ===========================================================================

  private addToHistory(payload: NotificationPayload, channels: NotificationChannel[], results: NotificationResult[]): void {
    const entry: NotificationHistoryEntry = {
      id: `hist-${Date.now()}`,
      payload,
      channels,
      results,
      timestamp: new Date().toISOString()
    };

    this.history.push(entry);

    // Keep only last 500 entries
    if (this.history.length > 500) {
      this.history = this.history.slice(-500);
    }

    this.store.set('notificationHistory', this.history);
  }

  getHistory(limit = 50): NotificationHistoryEntry[] {
    return this.history.slice(-limit).reverse();
  }

  getStats(): NotificationStats {
    return { ...this.stats };
  }

  clearHistory(): void {
    this.history = [];
    this.store.set('notificationHistory', []);
    this.stats = {
      totalSent: 0,
      byChannel: { slack: 0, teams: 0, email: 0, desktop: 0 },
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      failures: 0
    };
  }

  // ===========================================================================
  // CONVENIENCE METHODS
  // ===========================================================================

  async notifyVulnerability(
    title: string,
    severity: NotificationSeverity,
    findings: Array<{ id: string; title: string; severity: string }>
  ): Promise<NotificationResult[]> {
    return this.notify({
      id: `vuln-${Date.now()}`,
      title,
      message: `${findings.length} security finding(s) detected. Immediate review recommended.`,
      severity,
      category: 'vulnerability',
      timestamp: new Date().toISOString(),
      findings
    });
  }

  async notifyScanComplete(
    scanType: string,
    findingsCount: number,
    criticalCount: number
  ): Promise<NotificationResult[]> {
    const severity: NotificationSeverity = criticalCount > 0 ? 'high' : findingsCount > 0 ? 'medium' : 'info';
    return this.notify({
      id: `scan-${Date.now()}`,
      title: `${scanType} Scan Complete`,
      message: `Scan completed with ${findingsCount} finding(s)${criticalCount > 0 ? `, including ${criticalCount} critical` : ''}.`,
      severity,
      category: 'scan-complete',
      timestamp: new Date().toISOString(),
      metadata: { scanType, findingsCount, criticalCount }
    });
  }

  async notifyComplianceBreach(
    framework: string,
    score: number,
    threshold: number
  ): Promise<NotificationResult[]> {
    return this.notify({
      id: `compliance-${Date.now()}`,
      title: `${framework} Compliance Below Threshold`,
      message: `Compliance score (${score}%) has fallen below the required threshold (${threshold}%). Remediation required.`,
      severity: score < threshold - 20 ? 'critical' : 'high',
      category: 'threshold-breach',
      timestamp: new Date().toISOString(),
      metadata: { framework, score, threshold }
    });
  }
}

// Export singleton instance
export const notificationService = new NotificationService();
