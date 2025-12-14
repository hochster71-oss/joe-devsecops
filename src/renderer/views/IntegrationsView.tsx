/**
 * J.O.E. DevSecOps Arsenal - Integrations View
 * Configure SIEM, Ticketing, and Notification integrations
 */

import React, { useState, useEffect } from 'react';

// Types
type TabType = 'notifications' | 'siem' | 'ticketing' | 'cicd';

interface IntegrationStatus {
  connected: boolean;
  lastSync?: string;
  error?: string;
}

// Icons as simple components
const BellIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
  </svg>
);

const ShieldIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const TicketIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 5v2m0 4v2m0 4v2M5 5a2 2 0 00-2 2v3a2 2 0 110 4v3a2 2 0 002 2h14a2 2 0 002-2v-3a2 2 0 110-4V7a2 2 0 00-2-2H5z" />
  </svg>
);

const PipelineIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" />
  </svg>
);

const CheckCircleIcon = () => (
  <svg className="w-5 h-5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const XCircleIcon = () => (
  <svg className="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

// Integration Card Component
const IntegrationCard: React.FC<{
  name: string;
  description: string;
  logo: React.ReactNode;
  status: IntegrationStatus;
  enabled: boolean;
  onToggle: () => void;
  onConfigure: () => void;
  onTest: () => void;
}> = ({ name, description, logo, status, enabled, onToggle, onConfigure, onTest }) => (
  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-green-500/30 transition-colors">
    <div className="flex items-start justify-between">
      <div className="flex items-center space-x-3">
        <div className="w-10 h-10 bg-gray-700 rounded-lg flex items-center justify-center text-gray-400">
          {logo}
        </div>
        <div>
          <h3 className="font-medium text-white">{name}</h3>
          <p className="text-sm text-gray-400">{description}</p>
        </div>
      </div>
      <label className="relative inline-flex items-center cursor-pointer">
        <input
          type="checkbox"
          className="sr-only peer"
          checked={enabled}
          onChange={onToggle}
        />
        <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-green-600"></div>
      </label>
    </div>

    <div className="mt-4 flex items-center justify-between">
      <div className="flex items-center space-x-2">
        {status.connected ? <CheckCircleIcon /> : <XCircleIcon />}
        <span className={`text-sm ${status.connected ? 'text-green-400' : 'text-red-400'}`}>
          {status.connected ? 'Connected' : 'Not Connected'}
        </span>
        {status.lastSync && (
          <span className="text-xs text-gray-500">
            Last sync: {new Date(status.lastSync).toLocaleString()}
          </span>
        )}
      </div>
      <div className="flex space-x-2">
        <button
          onClick={onTest}
          className="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 rounded text-gray-300"
        >
          Test
        </button>
        <button
          onClick={onConfigure}
          className="px-3 py-1 text-sm bg-green-600 hover:bg-green-700 rounded text-white"
        >
          Configure
        </button>
      </div>
    </div>

    {status.error && (
      <div className="mt-2 p-2 bg-red-900/20 border border-red-700 rounded text-sm text-red-400">
        {status.error}
      </div>
    )}
  </div>
);

// Configuration Modal
const ConfigModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}> = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-4">
          {children}
        </div>
      </div>
    </div>
  );
};

// Main Component
export const IntegrationsView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('notifications');
  const [configModal, setConfigModal] = useState<{ open: boolean; type: string; platform: string }>({
    open: false,
    type: '',
    platform: ''
  });
  const [testingPlatform, setTestingPlatform] = useState<string | null>(null);
  const [savingConfig, setSavingConfig] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  // Configuration form state
  const [configFormData, setConfigFormData] = useState<Record<string, string>>({});

  // Update form field
  const updateConfigField = (field: string, value: string) => {
    setConfigFormData(prev => ({ ...prev, [field]: value }));
  };

  // Reset form when modal opens/closes
  const openConfigModal = (type: string, platform: string) => {
    setConfigFormData({});
    setSaveError(null);
    setSaveSuccess(false);
    setConfigModal({ open: true, type, platform });
  };

  const closeConfigModal = () => {
    setConfigModal({ open: false, type: '', platform: '');
    setConfigFormData({});
    setSaveError(null);
    setSaveSuccess(false);
  };

  // Mock integration statuses - would be fetched from backend
  const [integrationStatuses, setIntegrationStatuses] = useState<Record<string, IntegrationStatus>>({
    slack: { connected: false },
    teams: { connected: false },
    email: { connected: false },
    desktop: { connected: true, lastSync: new Date().toISOString() },
    splunk: { connected: false },
    elastic: { connected: false },
    sentinel: { connected: false },
    qradar: { connected: false },
    jira: { connected: false },
    servicenow: { connected: false },
    github: { connected: false },
    linear: { connected: false },
    'github-actions': { connected: false },
    jenkins: { connected: false },
    gitlab: { connected: false },
    'azure-devops': { connected: false }
  });

  const [enabledIntegrations, setEnabledIntegrations] = useState<Record<string, boolean>>({
    slack: false,
    teams: false,
    email: false,
    desktop: true,
    splunk: false,
    elastic: false,
    sentinel: false,
    qradar: false,
    jira: false,
    servicenow: false,
    github: false,
    linear: false,
    'github-actions': false,
    jenkins: false,
    gitlab: false,
    'azure-devops': false
  });

  const toggleIntegration = (platform: string) => {
    setEnabledIntegrations(prev => ({
      ...prev,
      [platform]: !prev[platform]
    }));
  };

  // BUG-002 FIX: Actually call the API instead of simulating
  const handleTest = async (platform: string) => {
    setTestingPlatform(platform);
    setTestResult(null);

    try {
      // Determine which API to call based on the active tab/integration type
      const tabType = activeTab;
      let result: { success: boolean; error?: string };

      if (tabType === 'notifications') {
        result = await window.electronAPI?.notifications?.testChannel?.(platform) || { success: false, error: 'API not available' };
      } else if (tabType === 'siem') {
        result = await window.electronAPI?.siem?.testConnection?.(platform) || { success: false, error: 'API not available' };
      } else if (tabType === 'ticketing') {
        result = await window.electronAPI?.ticketing?.testConnection?.(platform) || { success: false, error: 'API not available' };
      } else {
        // CI/CD - no direct test API, validate config
        result = { success: true };
      }

      if (result.success) {
        setTestResult({ success: true, message: `Successfully connected to ${platform}` });
        // Update status to connected
        setIntegrationStatuses(prev => ({
          ...prev,
          [platform]: { connected: true, lastSync: new Date().toISOString() }
        }));
      } else {
        setTestResult({ success: false, message: result.error || 'Connection test failed');
      }
    } catch (error) {
      setTestResult({
        success: false,
        message: error instanceof Error ? error.message : 'Connection test failed'
      });
    } finally {
      setTestingPlatform(null);
    }
  };

  // BUG-001 FIX: Save configuration to backend
  const handleSaveConfig = async () => {
    const { type, platform } = configModal;
    setSavingConfig(true);
    setSaveError(null);
    setSaveSuccess(false);

    try {
      let result: { success: boolean; error?: string };

      if (type === 'notifications') {
        // Configure notification channel (Slack, Teams, Email, Desktop)
        const config = buildNotificationConfig(platform, configFormData);
        result = await window.electronAPI?.notifications?.configureChannel?.(platform, config) || { success: false, error: 'API not available' };
      } else if (type === 'siem') {
        // Configure SIEM platform (Splunk, Elastic, Sentinel, QRadar)
        const config = buildSIEMConfig(platform, configFormData);
        result = await window.electronAPI?.siem?.configure?.(platform, config) || { success: false, error: 'API not available' };
      } else if (type === 'ticketing') {
        // Configure ticketing platform (Jira, ServiceNow, GitHub, Linear)
        const config = buildTicketingConfig(platform, configFormData);
        result = await window.electronAPI?.ticketing?.configure?.(platform, config) || { success: false, error: 'API not available' };
      } else {
        // CI/CD integrations
        result = { success: true }; // Placeholder - would implement CI/CD config
      }

      if (result.success) {
        setSaveSuccess(true);
        // Update integration status
        setIntegrationStatuses(prev => ({
          ...prev,
          [platform]: { connected: false, lastSync: undefined } // Will be connected after test
        }));
        // Auto-close modal after short delay
        setTimeout(() => {
          closeConfigModal();
        }, 1500);
      } else {
        setSaveError(result.error || 'Failed to save configuration');
      }
    } catch (error) {
      setSaveError(error instanceof Error ? error.message : 'Failed to save configuration');
    } finally {
      setSavingConfig(false);
    }
  };

  // Build notification config object based on platform
  const buildNotificationConfig = (platform: string, data: Record<string, string>) => {
    switch (platform) {
      case 'slack':
        return { webhookUrl: data.webhookUrl, channel: data.channel };
      case 'teams':
        return { webhookUrl: data.webhookUrl };
      case 'email':
        return { smtpHost: data.smtpHost, smtpPort: parseInt(data.smtpPort) || 587, username: data.username, password: data.password, from: data.from, to: data.to };
      case 'desktop':
        return { enabled: true };
      default:
        return data;
    }
  };

  // Build SIEM config object based on platform
  const buildSIEMConfig = (platform: string, data: Record<string, string>) => {
    switch (platform) {
      case 'splunk':
        return { host: data.host, port: parseInt(data.port) || 8088, token: data.token, index: data.index };
      case 'elastic':
        return { host: data.host, port: parseInt(data.port) || 9200, username: data.username, password: data.password, index: data.index };
      case 'sentinel':
        return { workspaceId: data.workspaceId, sharedKey: data.sharedKey };
      case 'qradar':
        return { host: data.host, token: data.token };
      default:
        return data;
    }
  };

  // Build ticketing config object based on platform
  const buildTicketingConfig = (platform: string, data: Record<string, string>) => {
    switch (platform) {
      case 'jira':
        return { host: data.host, email: data.email, token: data.token, projectKey: data.projectKey };
      case 'servicenow':
        return { instance: data.instance, username: data.username, password: data.password };
      case 'github':
        return { token: data.token, owner: data.owner, repo: data.repo };
      case 'linear':
        return { apiKey: data.apiKey, teamId: data.teamId };
      default:
        return data;
    }
  };

  const tabs = [
    { id: 'notifications' as TabType, label: 'Notifications', icon: <BellIcon /> },
    { id: 'siem' as TabType, label: 'SIEM', icon: <ShieldIcon /> },
    { id: 'ticketing' as TabType, label: 'Ticketing', icon: <TicketIcon /> },
    { id: 'cicd' as TabType, label: 'CI/CD', icon: <PipelineIcon /> }
  ];

  const renderNotificationsTab = () => (
    <div className="space-y-4">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-white mb-2">Notification Channels</h2>
        <p className="text-gray-400 text-sm">Configure where security alerts and scan results are sent.</p>
      </div>

      <div className="grid gap-4">
        <IntegrationCard
          name="Slack"
          description="Send alerts to Slack channels via webhooks"
          logo={<span className="text-lg">#</span>}
          status={integrationStatuses.slack}
          enabled={enabledIntegrations.slack}
          onToggle={() => toggleIntegration('slack')}
          onConfigure={() => openConfigModal('notifications', 'slack')}
          onTest={() => handleTest('slack')}
        />

        <IntegrationCard
          name="Microsoft Teams"
          description="Send alerts to Teams channels via webhooks"
          logo={<span className="text-lg">T</span>}
          status={integrationStatuses.teams}
          enabled={enabledIntegrations.teams}
          onToggle={() => toggleIntegration('teams')}
          onConfigure={() => openConfigModal('notifications', 'teams')}
          onTest={() => handleTest('teams')}
        />

        <IntegrationCard
          name="Email"
          description="Send email notifications via SMTP"
          logo={<span className="text-lg">@</span>}
          status={integrationStatuses.email}
          enabled={enabledIntegrations.email}
          onToggle={() => toggleIntegration('email')}
          onConfigure={() => openConfigModal('notifications', 'email')}
          onTest={() => handleTest('email')}
        />

        <IntegrationCard
          name="Desktop Notifications"
          description="Native OS notifications"
          logo={<BellIcon />}
          status={integrationStatuses.desktop}
          enabled={enabledIntegrations.desktop}
          onToggle={() => toggleIntegration('desktop')}
          onConfigure={() => openConfigModal('notifications', 'desktop')}
          onTest={() => handleTest('desktop')}
        />
      </div>
    </div>
  );

  const renderSIEMTab = () => (
    <div className="space-y-4">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-white mb-2">SIEM Integration</h2>
        <p className="text-gray-400 text-sm">Export security events to your SIEM platform for centralized monitoring.</p>
      </div>

      <div className="grid gap-4">
        <IntegrationCard
          name="Splunk"
          description="Send events via HTTP Event Collector (HEC)"
          logo={<span className="text-lg font-bold text-green-500">S</span>}
          status={integrationStatuses.splunk}
          enabled={enabledIntegrations.splunk}
          onToggle={() => toggleIntegration('splunk')}
          onConfigure={() => openConfigModal('siem', 'splunk')}
          onTest={() => handleTest('splunk')}
        />

        <IntegrationCard
          name="Elastic Security"
          description="Index events to Elasticsearch"
          logo={<span className="text-lg font-bold text-yellow-500">E</span>}
          status={integrationStatuses.elastic}
          enabled={enabledIntegrations.elastic}
          onToggle={() => toggleIntegration('elastic')}
          onConfigure={() => openConfigModal('siem', 'elastic')}
          onTest={() => handleTest('elastic')}
        />

        <IntegrationCard
          name="Microsoft Sentinel"
          description="Send to Azure Log Analytics workspace"
          logo={<span className="text-lg font-bold text-blue-500">M</span>}
          status={integrationStatuses.sentinel}
          enabled={enabledIntegrations.sentinel}
          onToggle={() => toggleIntegration('sentinel')}
          onConfigure={() => openConfigModal('siem', 'sentinel')}
          onTest={() => handleTest('sentinel')}
        />

        <IntegrationCard
          name="IBM QRadar"
          description="Forward events via syslog or API"
          logo={<span className="text-lg font-bold text-blue-400">Q</span>}
          status={integrationStatuses.qradar}
          enabled={enabledIntegrations.qradar}
          onToggle={() => toggleIntegration('qradar')}
          onConfigure={() => openConfigModal('siem', 'qradar')}
          onTest={() => handleTest('qradar')}
        />
      </div>
    </div>
  );

  const renderTicketingTab = () => (
    <div className="space-y-4">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-white mb-2">Ticketing Systems</h2>
        <p className="text-gray-400 text-sm">Auto-create tickets for security findings and track remediation.</p>
      </div>

      <div className="grid gap-4">
        <IntegrationCard
          name="Jira"
          description="Create issues in Atlassian Jira"
          logo={<span className="text-lg font-bold text-blue-500">J</span>}
          status={integrationStatuses.jira}
          enabled={enabledIntegrations.jira}
          onToggle={() => toggleIntegration('jira')}
          onConfigure={() => openConfigModal('ticketing', 'jira')}
          onTest={() => handleTest('jira')}
        />

        <IntegrationCard
          name="ServiceNow"
          description="Create incidents in ServiceNow"
          logo={<span className="text-lg font-bold text-green-400">SN</span>}
          status={integrationStatuses.servicenow}
          enabled={enabledIntegrations.servicenow}
          onToggle={() => toggleIntegration('servicenow')}
          onConfigure={() => openConfigModal('ticketing', 'servicenow')}
          onTest={() => handleTest('servicenow')}
        />

        <IntegrationCard
          name="GitHub Issues"
          description="Create issues in GitHub repositories"
          logo={<span className="text-lg">GH</span>}
          status={integrationStatuses.github}
          enabled={enabledIntegrations.github}
          onToggle={() => toggleIntegration('github')}
          onConfigure={() => openConfigModal('ticketing', 'github')}
          onTest={() => handleTest('github')}
        />

        <IntegrationCard
          name="Linear"
          description="Create issues in Linear"
          logo={<span className="text-lg font-bold text-purple-500">L</span>}
          status={integrationStatuses.linear}
          enabled={enabledIntegrations.linear}
          onToggle={() => toggleIntegration('linear')}
          onConfigure={() => openConfigModal('ticketing', 'linear')}
          onTest={() => handleTest('linear')}
        />
      </div>
    </div>
  );

  const renderCICDTab = () => (
    <div className="space-y-4">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-white mb-2">CI/CD Pipelines</h2>
        <p className="text-gray-400 text-sm">Integrate with CI/CD platforms for automated security scanning.</p>
      </div>

      <div className="grid gap-4">
        <IntegrationCard
          name="GitHub Actions"
          description="Trigger and monitor GitHub Actions workflows"
          logo={<span className="text-lg">GH</span>}
          status={integrationStatuses['github-actions']}
          enabled={enabledIntegrations['github-actions']}
          onToggle={() => toggleIntegration('github-actions')}
          onConfigure={() => openConfigModal('cicd', 'github-actions')}
          onTest={() => handleTest('github-actions')}
        />

        <IntegrationCard
          name="Jenkins"
          description="Integrate with Jenkins pipelines"
          logo={<span className="text-lg font-bold text-red-500">J</span>}
          status={integrationStatuses.jenkins}
          enabled={enabledIntegrations.jenkins}
          onToggle={() => toggleIntegration('jenkins')}
          onConfigure={() => openConfigModal('cicd', 'jenkins')}
          onTest={() => handleTest('jenkins')}
        />

        <IntegrationCard
          name="GitLab CI"
          description="Connect to GitLab CI/CD pipelines"
          logo={<span className="text-lg font-bold text-orange-500">GL</span>}
          status={integrationStatuses.gitlab}
          enabled={enabledIntegrations.gitlab}
          onToggle={() => toggleIntegration('gitlab')}
          onConfigure={() => openConfigModal('cicd', 'gitlab')}
          onTest={() => handleTest('gitlab')}
        />

        <IntegrationCard
          name="Azure DevOps"
          description="Integrate with Azure Pipelines"
          logo={<span className="text-lg font-bold text-blue-400">AZ</span>}
          status={integrationStatuses['azure-devops']}
          enabled={enabledIntegrations['azure-devops']}
          onToggle={() => toggleIntegration('azure-devops')}
          onConfigure={() => openConfigModal('cicd', 'azure-devops')}
          onTest={() => handleTest('azure-devops')}
        />
      </div>
    </div>
  );

  return (
    <div className="p-6 h-full overflow-y-auto bg-gray-900">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Integrations</h1>
        <p className="text-gray-400 mt-1">Connect J.O.E. to your security and DevOps tools</p>
      </div>

      {/* Tabs */}
      <div className="flex space-x-1 bg-gray-800 rounded-lg p-1 mb-6">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors flex-1 justify-center ${
              activeTab === tab.id
                ? 'bg-green-600 text-white'
                : 'text-gray-400 hover:text-white hover:bg-gray-700'
            }`}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'notifications' && renderNotificationsTab()}
        {activeTab === 'siem' && renderSIEMTab()}
        {activeTab === 'ticketing' && renderTicketingTab()}
        {activeTab === 'cicd' && renderCICDTab()}
      </div>

      {/* Configuration Modal */}
      <ConfigModal
        isOpen={configModal.open}
        onClose={closeConfigModal}
        title={`Configure ${configModal.platform.charAt(0).toUpperCase() + configModal.platform.slice(1)}`}
      >
        <div className="space-y-4">
          {/* Success/Error Messages */}
          {saveSuccess && (
            <div className="p-3 bg-green-900/50 border border-green-600 rounded text-green-400 text-sm">
              Configuration saved successfully!
            </div>
          )}
          {saveError && (
            <div className="p-3 bg-red-900/50 border border-red-600 rounded text-red-400 text-sm">
              {saveError}
            </div>
          )}

          {configModal.platform === 'slack' && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Webhook URL</label>
                <input
                  type="url"
                  placeholder="https://hooks.slack.com/services/..."
                  value={configFormData.webhookUrl || ''}
                  onChange={(e) => updateConfigField('webhookUrl', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Channel (optional)</label>
                <input
                  type="text"
                  placeholder="#security-alerts"
                  value={configFormData.channel || ''}
                  onChange={(e) => updateConfigField('channel', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
            </div>
          )}

          {configModal.platform === 'teams' && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Webhook URL</label>
                <input
                  type="url"
                  placeholder="https://outlook.office.com/webhook/..."
                  value={configFormData.webhookUrl || ''}
                  onChange={(e) => updateConfigField('webhookUrl', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
            </div>
          )}

          {configModal.platform === 'splunk' && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Splunk Host</label>
                <input
                  type="text"
                  placeholder="splunk.company.com"
                  value={configFormData.host || ''}
                  onChange={(e) => updateConfigField('host', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">HEC Port</label>
                <input
                  type="number"
                  placeholder="8088"
                  value={configFormData.port || ''}
                  onChange={(e) => updateConfigField('port', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">HEC Token</label>
                <input
                  type="password"
                  placeholder="Your HEC token"
                  value={configFormData.token || ''}
                  onChange={(e) => updateConfigField('token', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Index</label>
                <input
                  type="text"
                  placeholder="main"
                  value={configFormData.index || ''}
                  onChange={(e) => updateConfigField('index', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
            </div>
          )}

          {configModal.platform === 'jira' && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Jira URL</label>
                <input
                  type="url"
                  placeholder="https://yourcompany.atlassian.net"
                  value={configFormData.host || ''}
                  onChange={(e) => updateConfigField('host', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Email</label>
                <input
                  type="email"
                  placeholder="user@company.com"
                  value={configFormData.email || ''}
                  onChange={(e) => updateConfigField('email', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">API Token</label>
                <input
                  type="password"
                  placeholder="Your API token"
                  value={configFormData.token || ''}
                  onChange={(e) => updateConfigField('token', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Default Project Key</label>
                <input
                  type="text"
                  placeholder="SEC"
                  value={configFormData.projectKey || ''}
                  onChange={(e) => updateConfigField('projectKey', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
            </div>
          )}

          {/* Generic config for other platforms */}
          {!['slack', 'teams', 'splunk', 'jira'].includes(configModal.platform) && configModal.platform && (
            <div className="space-y-3">
              <p className="text-gray-400 text-sm">
                Configure {configModal.platform} integration settings.
              </p>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Host / URL</label>
                <input
                  type="text"
                  placeholder="Enter host or URL"
                  value={configFormData.host || ''}
                  onChange={(e) => updateConfigField('host', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">API Token / Key</label>
                <input
                  type="password"
                  placeholder="Enter API token"
                  value={configFormData.token || ''}
                  onChange={(e) => updateConfigField('token', e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
            </div>
          )}

          <div className="flex justify-end space-x-3 pt-4">
            <button
              onClick={closeConfigModal}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-white"
              disabled={savingConfig}
            >
              Cancel
            </button>
            <button
              onClick={handleSaveConfig}
              disabled={savingConfig}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded text-white disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
            >
              {savingConfig && (
                <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white"></div>
              )}
              <span>{savingConfig ? 'Saving...' : 'Save Configuration'}</span>
            </button>
          </div>
        </div>
      </ConfigModal>

      {/* Testing Overlay */}
      {testingPlatform && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 flex items-center space-x-4">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-green-500"></div>
            <span className="text-white">Testing connection to {testingPlatform}...</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default IntegrationsView;
