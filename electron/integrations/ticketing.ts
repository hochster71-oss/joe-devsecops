/**
 * J.O.E. DevSecOps Arsenal - Ticketing System Integration
 * Integration with Jira, ServiceNow, Azure Boards, GitHub Issues, and Linear
 *
 * @module electron/integrations/ticketing
 * @version 1.0.0
 */

import Store from 'electron-store';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

export type TicketingPlatform = 'jira' | 'servicenow' | 'azure-boards' | 'github' | 'linear';

export interface TicketingConfig {
  platform: TicketingPlatform;
  enabled: boolean;
  name: string;
  baseUrl: string;
  credentials: {
    apiToken?: string;
    username?: string;
    password?: string;
    email?: string;
    pat?: string; // Personal Access Token
    apiKey?: string;
  };
  defaultProject?: string;
  defaultIssueType?: string;
  defaultPriority?: string;
  customFields?: Record<string, string>;
  labelMapping?: Record<string, string>;
}

export interface SecurityFinding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  tool: string;
  file?: string;
  line?: number;
  cve?: string;
  remediation?: string;
  framework?: string;
  controlId?: string;
}

export interface TicketPayload {
  title: string;
  description: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  labels?: string[];
  assignee?: string;
  dueDate?: string;
  customFields?: Record<string, unknown>;
  findings?: SecurityFinding[];
}

export interface TicketResult {
  success: boolean;
  platform: TicketingPlatform;
  ticketId?: string;
  ticketKey?: string;
  ticketUrl?: string;
  error?: string;
}

export interface TicketStatus {
  id: string;
  key: string;
  status: string;
  assignee?: string;
  lastUpdated: string;
  platform: TicketingPlatform;
}

// =============================================================================
// TICKETING SERVICE
// =============================================================================

class TicketingService {
  private store: Store;

  constructor() {
    this.store = new Store({ name: 'joe-ticketing-config' });
    this.initializeConfigs();
  }

  private initializeConfigs(): void {
    const defaultConfigs: TicketingConfig[] = [
      {
        platform: 'jira',
        enabled: false,
        name: 'Jira',
        baseUrl: '',
        credentials: {},
        defaultIssueType: 'Bug',
        defaultPriority: 'Medium'
      },
      {
        platform: 'servicenow',
        enabled: false,
        name: 'ServiceNow',
        baseUrl: '',
        credentials: {},
        defaultIssueType: 'incident'
      },
      {
        platform: 'azure-boards',
        enabled: false,
        name: 'Azure Boards',
        baseUrl: '',
        credentials: {},
        defaultIssueType: 'Bug'
      },
      {
        platform: 'github',
        enabled: false,
        name: 'GitHub Issues',
        baseUrl: 'https://api.github.com',
        credentials: {}
      },
      {
        platform: 'linear',
        enabled: false,
        name: 'Linear',
        baseUrl: 'https://api.linear.app',
        credentials: {}
      }
    ];

    if (!this.store.has('ticketingConfigs')) {
      this.store.set('ticketingConfigs', defaultConfigs);
    }
  }

  // ===========================================================================
  // CONFIGURATION
  // ===========================================================================

  getConfigs(): TicketingConfig[] {
    return this.store.get('ticketingConfigs', []) as TicketingConfig[];
  }

  getConfig(platform: TicketingPlatform): TicketingConfig | undefined {
    return this.getConfigs().find(c => c.platform === platform);
  }

  updateConfig(platform: TicketingPlatform, updates: Partial<TicketingConfig>): TicketingConfig | null {
    const configs = this.getConfigs();
    const index = configs.findIndex(c => c.platform === platform);

    if (index === -1) return null;

    configs[index] = { ...configs[index], ...updates, platform };
    this.store.set('ticketingConfigs', configs);
    return configs[index];
  }

  async testConnection(platform: TicketingPlatform): Promise<TicketResult> {
    const config = this.getConfig(platform);
    if (!config) {
      return { success: false, platform, error: 'Configuration not found' };
    }

    try {
      switch (platform) {
        case 'jira':
          return await this.testJiraConnection(config);
        case 'servicenow':
          return await this.testServiceNowConnection(config);
        case 'azure-boards':
          return await this.testAzureBoardsConnection(config);
        case 'github':
          return await this.testGitHubConnection(config);
        case 'linear':
          return await this.testLinearConnection(config);
        default:
          return { success: false, platform, error: 'Unknown platform' };
      }
    } catch (error) {
      return { success: false, platform, error: String(error) };
    }
  }

  // ===========================================================================
  // TICKET CREATION
  // ===========================================================================

  async createTicket(platform: TicketingPlatform, payload: TicketPayload): Promise<TicketResult> {
    const config = this.getConfig(platform);
    if (!config || !config.enabled) {
      return { success: false, platform, error: 'Platform not configured or disabled' };
    }

    try {
      switch (platform) {
        case 'jira':
          return await this.createJiraTicket(config, payload);
        case 'servicenow':
          return await this.createServiceNowTicket(config, payload);
        case 'azure-boards':
          return await this.createAzureBoardsTicket(config, payload);
        case 'github':
          return await this.createGitHubIssue(config, payload);
        case 'linear':
          return await this.createLinearIssue(config, payload);
        default:
          return { success: false, platform, error: 'Unknown platform' };
      }
    } catch (error) {
      return { success: false, platform, error: String(error) };
    }
  }

  async createTicketFromFinding(finding: SecurityFinding): Promise<TicketResult[]> {
    const results: TicketResult[] = [];
    const enabledConfigs = this.getConfigs().filter(c => c.enabled);

    const payload: TicketPayload = {
      title: `[Security] ${finding.severity.toUpperCase()}: ${finding.title}`,
      description: this.formatFindingDescription(finding),
      priority: this.mapSeverityToPriority(finding.severity),
      labels: [
        'security',
        finding.severity,
        finding.tool.toLowerCase(),
        ...(finding.cve ? ['cve'] : []),
        ...(finding.framework ? [finding.framework.toLowerCase()] : [])
      ],
      findings: [finding]
    };

    for (const config of enabledConfigs) {
      const result = await this.createTicket(config.platform, payload);
      results.push(result);
    }

    return results;
  }

  async createBulkTickets(findings: SecurityFinding[], groupBy: 'severity' | 'tool' | 'file' = 'severity'): Promise<TicketResult[]> {
    const results: TicketResult[] = [];
    const enabledConfigs = this.getConfigs().filter(c => c.enabled);

    // Group findings
    const grouped = new Map<string, SecurityFinding[]>();
    for (const finding of findings) {
      const key = groupBy === 'severity' ? finding.severity :
                  groupBy === 'tool' ? finding.tool :
                  finding.file || 'unknown';

      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key)!.push(finding);
    }

    for (const [key, groupFindings] of grouped) {
      const payload: TicketPayload = {
        title: `[Security] ${groupFindings.length} ${key} findings`,
        description: this.formatGroupedDescription(groupBy, key, groupFindings),
        priority: this.mapSeverityToPriority(this.getHighestSeverity(groupFindings)),
        labels: ['security', 'bulk', key.toLowerCase()],
        findings: groupFindings
      };

      for (const config of enabledConfigs) {
        const result = await this.createTicket(config.platform, payload);
        results.push(result);
      }
    }

    return results;
  }

  // ===========================================================================
  // PLATFORM IMPLEMENTATIONS - JIRA
  // ===========================================================================

  private async testJiraConnection(config: TicketingConfig): Promise<TicketResult> {
    const auth = Buffer.from(`${config.credentials.email}:${config.credentials.apiToken}`).toString('base64');

    const response = await fetch(`${config.baseUrl}/rest/api/3/myself`, {
      headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
    });

    if (!response.ok) {
      throw new Error(`Jira returned ${response.status}`);
    }

    return { success: true, platform: 'jira' };
  }

  private async createJiraTicket(config: TicketingConfig, payload: TicketPayload): Promise<TicketResult> {
    const auth = Buffer.from(`${config.credentials.email}:${config.credentials.apiToken}`).toString('base64');

    const priorityMap: Record<string, string> = {
      critical: 'Highest',
      high: 'High',
      medium: 'Medium',
      low: 'Low'
    };

    const body = {
      fields: {
        project: { key: config.defaultProject },
        summary: payload.title,
        description: {
          type: 'doc',
          version: 1,
          content: [{
            type: 'paragraph',
            content: [{ type: 'text', text: payload.description }]
          }]
        },
        issuetype: { name: config.defaultIssueType || 'Bug' },
        priority: { name: priorityMap[payload.priority] || config.defaultPriority },
        labels: payload.labels,
        ...(payload.assignee && { assignee: { accountId: payload.assignee } }),
        ...(payload.dueDate && { duedate: payload.dueDate }),
        ...config.customFields
      }
    };

    const response = await fetch(`${config.baseUrl}/rest/api/3/issue`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Jira returned ${response.status}: ${error}`);
    }

    const result = await response.json() as { id: string; key: string; self: string };
    return {
      success: true,
      platform: 'jira',
      ticketId: result.id,
      ticketKey: result.key,
      ticketUrl: `${config.baseUrl}/browse/${result.key}`
    };
  }

  // ===========================================================================
  // PLATFORM IMPLEMENTATIONS - SERVICENOW
  // ===========================================================================

  private async testServiceNowConnection(config: TicketingConfig): Promise<TicketResult> {
    const auth = Buffer.from(`${config.credentials.username}:${config.credentials.password}`).toString('base64');

    const response = await fetch(`${config.baseUrl}/api/now/table/sys_user?sysparm_limit=1`, {
      headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
    });

    if (!response.ok) {
      throw new Error(`ServiceNow returned ${response.status}`);
    }

    return { success: true, platform: 'servicenow' };
  }

  private async createServiceNowTicket(config: TicketingConfig, payload: TicketPayload): Promise<TicketResult> {
    const auth = Buffer.from(`${config.credentials.username}:${config.credentials.password}`).toString('base64');

    const priorityMap: Record<string, number> = {
      critical: 1,
      high: 2,
      medium: 3,
      low: 4
    };

    const body = {
      short_description: payload.title,
      description: payload.description,
      priority: priorityMap[payload.priority],
      category: 'Security',
      subcategory: 'Vulnerability',
      ...(payload.assignee && { assigned_to: payload.assignee }),
      ...(payload.dueDate && { due_date: payload.dueDate })
    };

    const response = await fetch(`${config.baseUrl}/api/now/table/${config.defaultIssueType || 'incident'}`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      throw new Error(`ServiceNow returned ${response.status}`);
    }

    const result = await response.json() as { result: { sys_id: string; number: string } };
    return {
      success: true,
      platform: 'servicenow',
      ticketId: result.result.sys_id,
      ticketKey: result.result.number,
      ticketUrl: `${config.baseUrl}/nav_to.do?uri=incident.do?sys_id=${result.result.sys_id}`
    };
  }

  // ===========================================================================
  // PLATFORM IMPLEMENTATIONS - AZURE BOARDS
  // ===========================================================================

  private async testAzureBoardsConnection(config: TicketingConfig): Promise<TicketResult> {
    const response = await fetch(`${config.baseUrl}/_apis/projects?api-version=7.0`, {
      headers: {
        'Authorization': `Basic ${Buffer.from(`:${config.credentials.pat}`).toString('base64')}`,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Azure Boards returned ${response.status}`);
    }

    return { success: true, platform: 'azure-boards' };
  }

  private async createAzureBoardsTicket(config: TicketingConfig, payload: TicketPayload): Promise<TicketResult> {
    const priorityMap: Record<string, number> = {
      critical: 1,
      high: 2,
      medium: 3,
      low: 4
    };

    const body = [
      { op: 'add', path: '/fields/System.Title', value: payload.title },
      { op: 'add', path: '/fields/System.Description', value: payload.description },
      { op: 'add', path: '/fields/Microsoft.VSTS.Common.Priority', value: priorityMap[payload.priority] },
      { op: 'add', path: '/fields/System.Tags', value: (payload.labels || []).join('; ') }
    ];

    if (payload.assignee) {
      body.push({ op: 'add', path: '/fields/System.AssignedTo', value: payload.assignee });
    }

    const response = await fetch(
      `${config.baseUrl}/${config.defaultProject}/_apis/wit/workitems/$${config.defaultIssueType || 'Bug'}?api-version=7.0`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${Buffer.from(`:${config.credentials.pat}`).toString('base64')}`,
          'Content-Type': 'application/json-patch+json'
        },
        body: JSON.stringify(body)
      }
    );

    if (!response.ok) {
      throw new Error(`Azure Boards returned ${response.status}`);
    }

    const result = await response.json() as { id: number; _links: { html: { href: string } } };
    return {
      success: true,
      platform: 'azure-boards',
      ticketId: String(result.id),
      ticketKey: String(result.id),
      ticketUrl: result._links.html.href
    };
  }

  // ===========================================================================
  // PLATFORM IMPLEMENTATIONS - GITHUB
  // ===========================================================================

  private async testGitHubConnection(config: TicketingConfig): Promise<TicketResult> {
    const response = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${config.credentials.apiToken}`,
        'Accept': 'application/vnd.github+json'
      }
    });

    if (!response.ok) {
      throw new Error(`GitHub returned ${response.status}`);
    }

    return { success: true, platform: 'github' };
  }

  private async createGitHubIssue(config: TicketingConfig, payload: TicketPayload): Promise<TicketResult> {
    const body = {
      title: payload.title,
      body: payload.description,
      labels: payload.labels,
      ...(payload.assignee && { assignees: [payload.assignee] })
    };

    const response = await fetch(
      `https://api.github.com/repos/${config.defaultProject}/issues`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${config.credentials.apiToken}`,
          'Accept': 'application/vnd.github+json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      }
    );

    if (!response.ok) {
      throw new Error(`GitHub returned ${response.status}`);
    }

    const result = await response.json() as { id: number; number: number; html_url: string };
    return {
      success: true,
      platform: 'github',
      ticketId: String(result.id),
      ticketKey: `#${result.number}`,
      ticketUrl: result.html_url
    };
  }

  // ===========================================================================
  // PLATFORM IMPLEMENTATIONS - LINEAR
  // ===========================================================================

  private async testLinearConnection(config: TicketingConfig): Promise<TicketResult> {
    const response = await fetch('https://api.linear.app/graphql', {
      method: 'POST',
      headers: {
        'Authorization': config.credentials.apiKey || '',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ query: '{ viewer { id name } }' })
    });

    if (!response.ok) {
      throw new Error(`Linear returned ${response.status}`);
    }

    return { success: true, platform: 'linear' };
  }

  private async createLinearIssue(config: TicketingConfig, payload: TicketPayload): Promise<TicketResult> {
    const priorityMap: Record<string, number> = {
      critical: 1,
      high: 2,
      medium: 3,
      low: 4
    };

    const mutation = `
      mutation CreateIssue($input: IssueCreateInput!) {
        issueCreate(input: $input) {
          success
          issue {
            id
            identifier
            url
          }
        }
      }
    `;

    const response = await fetch('https://api.linear.app/graphql', {
      method: 'POST',
      headers: {
        'Authorization': config.credentials.apiKey || '',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        query: mutation,
        variables: {
          input: {
            teamId: config.defaultProject,
            title: payload.title,
            description: payload.description,
            priority: priorityMap[payload.priority],
            labelIds: payload.labels
          }
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Linear returned ${response.status}`);
    }

    const result = await response.json() as {
      data: { issueCreate: { success: boolean; issue: { id: string; identifier: string; url: string } } }
    };

    if (!result.data.issueCreate.success) {
      throw new Error('Linear issue creation failed');
    }

    return {
      success: true,
      platform: 'linear',
      ticketId: result.data.issueCreate.issue.id,
      ticketKey: result.data.issueCreate.issue.identifier,
      ticketUrl: result.data.issueCreate.issue.url
    };
  }

  // ===========================================================================
  // HELPER METHODS
  // ===========================================================================

  private formatFindingDescription(finding: SecurityFinding): string {
    return `
## Security Finding

**Severity:** ${finding.severity.toUpperCase()}
**Tool:** ${finding.tool}
${finding.cve ? `**CVE:** ${finding.cve}` : ''}
${finding.file ? `**File:** ${finding.file}${finding.line ? `:${finding.line}` : ''}` : ''}
${finding.framework ? `**Framework:** ${finding.framework} ${finding.controlId || ''}` : ''}

### Description
${finding.description}

${finding.remediation ? `### Remediation\n${finding.remediation}` : ''}

---
*Created by J.O.E. DevSecOps Arsenal*
    `.trim();
  }

  private formatGroupedDescription(groupBy: string, key: string, findings: SecurityFinding[]): string {
    const summaryLines = findings.map(f =>
      `- [${f.severity.toUpperCase()}] ${f.title}${f.file ? ` (${f.file})` : ''}`
    ).join('\n');

    return `
## Security Findings - Grouped by ${groupBy}: ${key}

**Total Findings:** ${findings.length}
**Critical:** ${findings.filter(f => f.severity === 'critical').length}
**High:** ${findings.filter(f => f.severity === 'high').length}
**Medium:** ${findings.filter(f => f.severity === 'medium').length}
**Low:** ${findings.filter(f => f.severity === 'low').length}

### Findings
${summaryLines}

---
*Created by J.O.E. DevSecOps Arsenal*
    `.trim();
  }

  private mapSeverityToPriority(severity: string): TicketPayload['priority'] {
    const map: Record<string, TicketPayload['priority']> = {
      critical: 'critical',
      high: 'high',
      medium: 'medium',
      low: 'low',
      info: 'low'
    };
    return map[severity] || 'medium';
  }

  private getHighestSeverity(findings: SecurityFinding[]): SecurityFinding['severity'] {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    for (const sev of order) {
      if (findings.some(f => f.severity === sev)) {
        return sev as SecurityFinding['severity'];
      }
    }
    return 'info';
  }
}

// Export singleton instance
export const ticketingService = new TicketingService();
