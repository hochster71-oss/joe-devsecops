/**
 * J.O.E. DevSecOps Arsenal - SIEM Connector
 * Integration with Splunk, Elastic Security, Microsoft Sentinel, and QRadar
 *
 * @module electron/integrations/siem-connector
 * @version 1.0.0
 */

import Store from 'electron-store';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

export type SIEMPlatform = 'splunk' | 'elastic' | 'sentinel' | 'qradar';

export interface SIEMConfig {
  platform: SIEMPlatform;
  enabled: boolean;
  name: string;
  endpoint: string;
  credentials: {
    apiKey?: string;
    token?: string;
    username?: string;
    password?: string;
    workspaceId?: string;
    sharedKey?: string;
  };
  options: {
    index?: string;
    sourcetype?: string;
    logType?: string;
    verifySSL: boolean;
    batchSize: number;
    flushIntervalMs: number;
  };
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  eventType: 'vulnerability' | 'compliance' | 'scan' | 'alert' | 'incident';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  source: string;
  title: string;
  description: string;
  metadata: Record<string, unknown>;
  findings?: Array<{
    id: string;
    title: string;
    severity: string;
    cve?: string;
  }>;
  host?: string;
  user?: string;
  tags?: string[];
}

export interface SIEMResponse {
  success: boolean;
  platform: SIEMPlatform;
  eventId?: string;
  error?: string;
  statusCode?: number;
}

export interface SIEMStats {
  platform: SIEMPlatform;
  eventsSent: number;
  lastSent?: string;
  failures: number;
  avgLatencyMs: number;
}

// =============================================================================
// SIEM CONNECTOR SERVICE
// =============================================================================

class SIEMConnector {
  private store: Store;
  private eventBuffer: Map<SIEMPlatform, SecurityEvent[]> = new Map();
  private stats: Map<SIEMPlatform, SIEMStats> = new Map();
  private flushTimers: Map<SIEMPlatform, NodeJS.Timeout> = new Map();

  constructor() {
    this.store = new Store({ name: 'joe-siem-config' });
    this.initializeConfigs();
  }

  private initializeConfigs(): void {
    const defaultConfigs: SIEMConfig[] = [
      {
        platform: 'splunk',
        enabled: false,
        name: 'Splunk',
        endpoint: '',
        credentials: {},
        options: {
          index: 'main',
          sourcetype: 'joe:security',
          verifySSL: true,
          batchSize: 100,
          flushIntervalMs: 5000
        }
      },
      {
        platform: 'elastic',
        enabled: false,
        name: 'Elastic Security',
        endpoint: '',
        credentials: {},
        options: {
          index: 'joe-security-events',
          verifySSL: true,
          batchSize: 100,
          flushIntervalMs: 5000
        }
      },
      {
        platform: 'sentinel',
        enabled: false,
        name: 'Microsoft Sentinel',
        endpoint: '',
        credentials: {},
        options: {
          logType: 'JOESecurityEvents',
          verifySSL: true,
          batchSize: 100,
          flushIntervalMs: 5000
        }
      },
      {
        platform: 'qradar',
        enabled: false,
        name: 'IBM QRadar',
        endpoint: '',
        credentials: {},
        options: {
          verifySSL: true,
          batchSize: 100,
          flushIntervalMs: 5000
        }
      }
    ];

    if (!this.store.has('siemConfigs')) {
      this.store.set('siemConfigs', defaultConfigs);
    }

    // Initialize stats
    for (const platform of ['splunk', 'elastic', 'sentinel', 'qradar'] as SIEMPlatform[]) {
      this.stats.set(platform, {
        platform,
        eventsSent: 0,
        failures: 0,
        avgLatencyMs: 0
      });
      this.eventBuffer.set(platform, []);
    }
  }

  // ===========================================================================
  // CONFIGURATION
  // ===========================================================================

  getConfigs(): SIEMConfig[] {
    return this.store.get('siemConfigs', []) as SIEMConfig[];
  }

  getConfig(platform: SIEMPlatform): SIEMConfig | undefined {
    return this.getConfigs().find(c => c.platform === platform);
  }

  updateConfig(platform: SIEMPlatform, updates: Partial<SIEMConfig>): SIEMConfig | null {
    const configs = this.getConfigs();
    const index = configs.findIndex(c => c.platform === platform);

    if (index === -1) return null;

    configs[index] = { ...configs[index], ...updates, platform };
    this.store.set('siemConfigs', configs);

    // Restart flush timer if enabled
    if (configs[index].enabled) {
      this.startFlushTimer(platform);
    } else {
      this.stopFlushTimer(platform);
    }

    return configs[index];
  }

  async testConnection(platform: SIEMPlatform): Promise<SIEMResponse> {
    const config = this.getConfig(platform);
    if (!config) {
      return { success: false, platform, error: 'Configuration not found' };
    }

    const testEvent: SecurityEvent = {
      id: `test-${Date.now()}`,
      timestamp: new Date().toISOString(),
      eventType: 'alert',
      severity: 'info',
      source: 'J.O.E. DevSecOps',
      title: 'Connection Test',
      description: 'This is a test event to verify SIEM connectivity',
      metadata: { test: true }
    };

    return this.sendEvent(platform, testEvent);
  }

  // ===========================================================================
  // EVENT SENDING
  // ===========================================================================

  async sendEvent(platform: SIEMPlatform, event: SecurityEvent): Promise<SIEMResponse> {
    const config = this.getConfig(platform);
    if (!config || !config.enabled) {
      return { success: false, platform, error: 'Platform not configured or disabled' };
    }

    try {
      const startTime = Date.now();
      let response: SIEMResponse;

      switch (platform) {
        case 'splunk':
          response = await this.sendToSplunk(config, event);
          break;
        case 'elastic':
          response = await this.sendToElastic(config, event);
          break;
        case 'sentinel':
          response = await this.sendToSentinel(config, event);
          break;
        case 'qradar':
          response = await this.sendToQRadar(config, event);
          break;
        default:
          response = { success: false, platform, error: 'Unknown platform' };
      }

      // Update stats
      const stats = this.stats.get(platform)!;
      const latency = Date.now() - startTime;

      if (response.success) {
        stats.eventsSent++;
        stats.lastSent = new Date().toISOString();
        stats.avgLatencyMs = (stats.avgLatencyMs * (stats.eventsSent - 1) + latency) / stats.eventsSent;
      } else {
        stats.failures++;
      }

      return response;
    } catch (error) {
      const stats = this.stats.get(platform)!;
      stats.failures++;
      return { success: false, platform, error: String(error) };
    }
  }

  async queueEvent(event: SecurityEvent): Promise<void> {
    const configs = this.getConfigs().filter(c => c.enabled);

    for (const config of configs) {
      const buffer = this.eventBuffer.get(config.platform)!;
      buffer.push(event);

      if (buffer.length >= config.options.batchSize) {
        await this.flushBuffer(config.platform);
      }
    }
  }

  private async flushBuffer(platform: SIEMPlatform): Promise<void> {
    const buffer = this.eventBuffer.get(platform)!;
    if (buffer.length === 0) return;

    const events = [...buffer];
    this.eventBuffer.set(platform, []);

    for (const event of events) {
      await this.sendEvent(platform, event);
    }
  }

  private startFlushTimer(platform: SIEMPlatform): void {
    this.stopFlushTimer(platform);

    const config = this.getConfig(platform);
    if (!config) return;

    const timer = setInterval(() => {
      this.flushBuffer(platform);
    }, config.options.flushIntervalMs);

    this.flushTimers.set(platform, timer);
  }

  private stopFlushTimer(platform: SIEMPlatform): void {
    const timer = this.flushTimers.get(platform);
    if (timer) {
      clearInterval(timer);
      this.flushTimers.delete(platform);
    }
  }

  // ===========================================================================
  // PLATFORM-SPECIFIC IMPLEMENTATIONS
  // ===========================================================================

  private async sendToSplunk(config: SIEMConfig, event: SecurityEvent): Promise<SIEMResponse> {
    if (!config.endpoint || !config.credentials.token) {
      return { success: false, platform: 'splunk', error: 'Missing endpoint or HEC token' };
    }

    try {
      const payload = {
        time: new Date(event.timestamp).getTime() / 1000,
        host: event.host || 'joe-devsecops',
        source: event.source,
        sourcetype: config.options.sourcetype,
        index: config.options.index,
        event: {
          ...event,
          app: 'J.O.E. DevSecOps Arsenal'
        }
      };

      const response = await fetch(`${config.endpoint}/services/collector/event`, {
        method: 'POST',
        headers: {
          'Authorization': `Splunk ${config.credentials.token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`Splunk HEC returned ${response.status}`);
      }

      return { success: true, platform: 'splunk', eventId: event.id };
    } catch (error) {
      return { success: false, platform: 'splunk', error: String(error) };
    }
  }

  private async sendToElastic(config: SIEMConfig, event: SecurityEvent): Promise<SIEMResponse> {
    if (!config.endpoint) {
      return { success: false, platform: 'elastic', error: 'Missing endpoint' };
    }

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      };

      if (config.credentials.apiKey) {
        headers['Authorization'] = `ApiKey ${config.credentials.apiKey}`;
      } else if (config.credentials.username && config.credentials.password) {
        const auth = Buffer.from(`${config.credentials.username}:${config.credentials.password}`).toString('base64');
        headers['Authorization'] = `Basic ${auth}`;
      }

      const doc = {
        '@timestamp': event.timestamp,
        event: {
          kind: 'alert',
          category: ['intrusion_detection'],
          type: ['info'],
          severity: this.mapSeverityToNumber(event.severity),
          original: JSON.stringify(event)
        },
        joe: event,
        host: {
          name: event.host || 'joe-devsecops'
        },
        tags: event.tags || ['joe-security']
      };

      const response = await fetch(`${config.endpoint}/${config.options.index}/_doc`, {
        method: 'POST',
        headers,
        body: JSON.stringify(doc)
      });

      if (!response.ok) {
        throw new Error(`Elasticsearch returned ${response.status}`);
      }

      const result = await response.json() as { _id: string };
      return { success: true, platform: 'elastic', eventId: result._id };
    } catch (error) {
      return { success: false, platform: 'elastic', error: String(error) };
    }
  }

  private async sendToSentinel(config: SIEMConfig, event: SecurityEvent): Promise<SIEMResponse> {
    if (!config.credentials.workspaceId || !config.credentials.sharedKey) {
      return { success: false, platform: 'sentinel', error: 'Missing workspace ID or shared key' };
    }

    try {
      const body = JSON.stringify([{
        TimeGenerated: event.timestamp,
        EventType: event.eventType,
        Severity: event.severity,
        Source: event.source,
        Title: event.title,
        Description: event.description,
        Metadata: JSON.stringify(event.metadata),
        Findings: JSON.stringify(event.findings || []),
        Tags: (event.tags || []).join(',')
      }]);

      const date = new Date().toUTCString();
      const contentLength = Buffer.byteLength(body, 'utf8');
      const stringToHash = `POST\n${contentLength}\napplication/json\nx-ms-date:${date}\n/api/logs`;

      // Note: In production, use proper HMAC-SHA256 signing
      const crypto = await import('crypto');
      const signature = crypto
        .createHmac('sha256', Buffer.from(config.credentials.sharedKey, 'base64'))
        .update(stringToHash, 'utf8')
        .digest('base64');

      const authorization = `SharedKey ${config.credentials.workspaceId}:${signature}`;

      const response = await fetch(
        `https://${config.credentials.workspaceId}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Log-Type': config.options.logType || 'JOESecurityEvents',
            'x-ms-date': date,
            'Authorization': authorization
          },
          body
        }
      );

      if (!response.ok) {
        throw new Error(`Sentinel returned ${response.status}`);
      }

      return { success: true, platform: 'sentinel', eventId: event.id };
    } catch (error) {
      return { success: false, platform: 'sentinel', error: String(error) };
    }
  }

  private async sendToQRadar(config: SIEMConfig, event: SecurityEvent): Promise<SIEMResponse> {
    if (!config.endpoint || !config.credentials.token) {
      return { success: false, platform: 'qradar', error: 'Missing endpoint or API token' };
    }

    try {
      // QRadar uses syslog or API - this implements the API approach
      const payload = {
        log_source_identifier: 'JOE-DevSecOps',
        log_source_type_id: 4000, // Custom log source
        events: [{
          timestamp: event.timestamp,
          category: event.eventType,
          severity: this.mapSeverityToNumber(event.severity),
          description: `${event.title}: ${event.description}`,
          payload: JSON.stringify(event)
        }]
      };

      const response = await fetch(`${config.endpoint}/api/data_classification/dsm_event_mappings`, {
        method: 'POST',
        headers: {
          'SEC': config.credentials.token,
          'Content-Type': 'application/json',
          'Version': '14.0'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`QRadar returned ${response.status}`);
      }

      return { success: true, platform: 'qradar', eventId: event.id };
    } catch (error) {
      return { success: false, platform: 'qradar', error: String(error) };
    }
  }

  private mapSeverityToNumber(severity: string): number {
    const map: Record<string, number> = {
      critical: 10,
      high: 8,
      medium: 5,
      low: 3,
      info: 1
    };
    return map[severity] || 1;
  }

  // ===========================================================================
  // CONVENIENCE METHODS
  // ===========================================================================

  async sendVulnerabilityFinding(finding: {
    id: string;
    title: string;
    severity: string;
    description: string;
    cve?: string;
    file?: string;
    line?: number;
    tool: string;
  }): Promise<SIEMResponse[]> {
    const event: SecurityEvent = {
      id: `vuln-${finding.id}-${Date.now()}`,
      timestamp: new Date().toISOString(),
      eventType: 'vulnerability',
      severity: finding.severity as SecurityEvent['severity'],
      source: `J.O.E. ${finding.tool}`,
      title: finding.title,
      description: finding.description,
      metadata: {
        cve: finding.cve,
        file: finding.file,
        line: finding.line,
        tool: finding.tool
      },
      tags: ['vulnerability', finding.tool.toLowerCase()]
    };

    await this.queueEvent(event);

    const results: SIEMResponse[] = [];
    for (const config of this.getConfigs().filter(c => c.enabled)) {
      results.push(await this.sendEvent(config.platform, event));
    }
    return results;
  }

  async sendComplianceEvent(framework: string, score: number, status: string): Promise<SIEMResponse[]> {
    const event: SecurityEvent = {
      id: `compliance-${framework}-${Date.now()}`,
      timestamp: new Date().toISOString(),
      eventType: 'compliance',
      severity: score < 50 ? 'high' : score < 70 ? 'medium' : 'info',
      source: 'J.O.E. Compliance',
      title: `${framework} Compliance Assessment`,
      description: `Compliance score: ${score}% - Status: ${status}`,
      metadata: { framework, score, status },
      tags: ['compliance', framework.toLowerCase()]
    };

    await this.queueEvent(event);

    const results: SIEMResponse[] = [];
    for (const config of this.getConfigs().filter(c => c.enabled)) {
      results.push(await this.sendEvent(config.platform, event));
    }
    return results;
  }

  async sendScanComplete(scanType: string, findings: number, critical: number): Promise<SIEMResponse[]> {
    const event: SecurityEvent = {
      id: `scan-${scanType}-${Date.now()}`,
      timestamp: new Date().toISOString(),
      eventType: 'scan',
      severity: critical > 0 ? 'high' : findings > 0 ? 'medium' : 'info',
      source: 'J.O.E. Scanner',
      title: `${scanType} Scan Complete`,
      description: `Found ${findings} issue(s), ${critical} critical`,
      metadata: { scanType, totalFindings: findings, criticalFindings: critical },
      tags: ['scan', scanType.toLowerCase()]
    };

    await this.queueEvent(event);

    const results: SIEMResponse[] = [];
    for (const config of this.getConfigs().filter(c => c.enabled)) {
      results.push(await this.sendEvent(config.platform, event));
    }
    return results;
  }

  // ===========================================================================
  // STATS
  // ===========================================================================

  getStats(platform?: SIEMPlatform): SIEMStats | SIEMStats[] {
    if (platform) {
      return this.stats.get(platform)!;
    }
    return Array.from(this.stats.values());
  }

  resetStats(platform?: SIEMPlatform): void {
    if (platform) {
      this.stats.set(platform, {
        platform,
        eventsSent: 0,
        failures: 0,
        avgLatencyMs: 0
      });
    } else {
      for (const p of this.stats.keys()) {
        this.stats.set(p, {
          platform: p,
          eventsSent: 0,
          failures: 0,
          avgLatencyMs: 0
        });
      }
    }
  }
}

// Export singleton instance
export const siemConnector = new SIEMConnector();
