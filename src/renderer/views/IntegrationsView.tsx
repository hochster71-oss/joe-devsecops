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

  // Mock integration statuses - would be fetched from backend
  const [integrationStatuses] = useState<Record<string, IntegrationStatus>>({
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

  const handleTest = async (platform: string) => {
    setTestingPlatform(platform);
    // Simulate test - would call backend
    await new Promise(resolve => setTimeout(resolve, 2000));
    setTestingPlatform(null);
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
          onConfigure={() => setConfigModal({ open: true, type: 'notifications', platform: 'slack' })}
          onTest={() => handleTest('slack')}
        />

        <IntegrationCard
          name="Microsoft Teams"
          description="Send alerts to Teams channels via webhooks"
          logo={<span className="text-lg">T</span>}
          status={integrationStatuses.teams}
          enabled={enabledIntegrations.teams}
          onToggle={() => toggleIntegration('teams')}
          onConfigure={() => setConfigModal({ open: true, type: 'notifications', platform: 'teams' })}
          onTest={() => handleTest('teams')}
        />

        <IntegrationCard
          name="Email"
          description="Send email notifications via SMTP"
          logo={<span className="text-lg">@</span>}
          status={integrationStatuses.email}
          enabled={enabledIntegrations.email}
          onToggle={() => toggleIntegration('email')}
          onConfigure={() => setConfigModal({ open: true, type: 'notifications', platform: 'email' })}
          onTest={() => handleTest('email')}
        />

        <IntegrationCard
          name="Desktop Notifications"
          description="Native OS notifications"
          logo={<BellIcon />}
          status={integrationStatuses.desktop}
          enabled={enabledIntegrations.desktop}
          onToggle={() => toggleIntegration('desktop')}
          onConfigure={() => setConfigModal({ open: true, type: 'notifications', platform: 'desktop' })}
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
          onConfigure={() => setConfigModal({ open: true, type: 'siem', platform: 'splunk' })}
          onTest={() => handleTest('splunk')}
        />

        <IntegrationCard
          name="Elastic Security"
          description="Index events to Elasticsearch"
          logo={<span className="text-lg font-bold text-yellow-500">E</span>}
          status={integrationStatuses.elastic}
          enabled={enabledIntegrations.elastic}
          onToggle={() => toggleIntegration('elastic')}
          onConfigure={() => setConfigModal({ open: true, type: 'siem', platform: 'elastic' })}
          onTest={() => handleTest('elastic')}
        />

        <IntegrationCard
          name="Microsoft Sentinel"
          description="Send to Azure Log Analytics workspace"
          logo={<span className="text-lg font-bold text-blue-500">M</span>}
          status={integrationStatuses.sentinel}
          enabled={enabledIntegrations.sentinel}
          onToggle={() => toggleIntegration('sentinel')}
          onConfigure={() => setConfigModal({ open: true, type: 'siem', platform: 'sentinel' })}
          onTest={() => handleTest('sentinel')}
        />

        <IntegrationCard
          name="IBM QRadar"
          description="Forward events via syslog or API"
          logo={<span className="text-lg font-bold text-blue-400">Q</span>}
          status={integrationStatuses.qradar}
          enabled={enabledIntegrations.qradar}
          onToggle={() => toggleIntegration('qradar')}
          onConfigure={() => setConfigModal({ open: true, type: 'siem', platform: 'qradar' })}
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
          onConfigure={() => setConfigModal({ open: true, type: 'ticketing', platform: 'jira' })}
          onTest={() => handleTest('jira')}
        />

        <IntegrationCard
          name="ServiceNow"
          description="Create incidents in ServiceNow"
          logo={<span className="text-lg font-bold text-green-400">SN</span>}
          status={integrationStatuses.servicenow}
          enabled={enabledIntegrations.servicenow}
          onToggle={() => toggleIntegration('servicenow')}
          onConfigure={() => setConfigModal({ open: true, type: 'ticketing', platform: 'servicenow' })}
          onTest={() => handleTest('servicenow')}
        />

        <IntegrationCard
          name="GitHub Issues"
          description="Create issues in GitHub repositories"
          logo={<span className="text-lg">GH</span>}
          status={integrationStatuses.github}
          enabled={enabledIntegrations.github}
          onToggle={() => toggleIntegration('github')}
          onConfigure={() => setConfigModal({ open: true, type: 'ticketing', platform: 'github' })}
          onTest={() => handleTest('github')}
        />

        <IntegrationCard
          name="Linear"
          description="Create issues in Linear"
          logo={<span className="text-lg font-bold text-purple-500">L</span>}
          status={integrationStatuses.linear}
          enabled={enabledIntegrations.linear}
          onToggle={() => toggleIntegration('linear')}
          onConfigure={() => setConfigModal({ open: true, type: 'ticketing', platform: 'linear' })}
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
          onConfigure={() => setConfigModal({ open: true, type: 'cicd', platform: 'github-actions' })}
          onTest={() => handleTest('github-actions')}
        />

        <IntegrationCard
          name="Jenkins"
          description="Integrate with Jenkins pipelines"
          logo={<span className="text-lg font-bold text-red-500">J</span>}
          status={integrationStatuses.jenkins}
          enabled={enabledIntegrations.jenkins}
          onToggle={() => toggleIntegration('jenkins')}
          onConfigure={() => setConfigModal({ open: true, type: 'cicd', platform: 'jenkins' })}
          onTest={() => handleTest('jenkins')}
        />

        <IntegrationCard
          name="GitLab CI"
          description="Connect to GitLab CI/CD pipelines"
          logo={<span className="text-lg font-bold text-orange-500">GL</span>}
          status={integrationStatuses.gitlab}
          enabled={enabledIntegrations.gitlab}
          onToggle={() => toggleIntegration('gitlab')}
          onConfigure={() => setConfigModal({ open: true, type: 'cicd', platform: 'gitlab' })}
          onTest={() => handleTest('gitlab')}
        />

        <IntegrationCard
          name="Azure DevOps"
          description="Integrate with Azure Pipelines"
          logo={<span className="text-lg font-bold text-blue-400">AZ</span>}
          status={integrationStatuses['azure-devops']}
          enabled={enabledIntegrations['azure-devops']}
          onToggle={() => toggleIntegration('azure-devops')}
          onConfigure={() => setConfigModal({ open: true, type: 'cicd', platform: 'azure-devops' })}
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
        onClose={() => setConfigModal({ open: false, type: '', platform: '' })}
        title={`Configure ${configModal.platform.charAt(0).toUpperCase() + configModal.platform.slice(1)}`}
      >
        <div className="space-y-4">
          <p className="text-gray-400 text-sm">
            Configuration for {configModal.platform} would go here. This is a placeholder.
          </p>

          {configModal.platform === 'slack' && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Webhook URL</label>
                <input
                  type="url"
                  placeholder="https://hooks.slack.com/services/..."
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Channel (optional)</label>
                <input
                  type="text"
                  placeholder="#security-alerts"
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
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Email</label>
                <input
                  type="email"
                  placeholder="user@company.com"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">API Token</label>
                <input
                  type="password"
                  placeholder="Your API token"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Default Project Key</label>
                <input
                  type="text"
                  placeholder="SEC"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white placeholder-gray-500 focus:outline-none focus:border-green-500"
                />
              </div>
            </div>
          )}

          <div className="flex justify-end space-x-3 pt-4">
            <button
              onClick={() => setConfigModal({ open: false, type: '', platform: '' })}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-white"
            >
              Cancel
            </button>
            <button
              className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded text-white"
            >
              Save Configuration
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
