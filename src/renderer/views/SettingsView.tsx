import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Settings,
  Shield,
  Package,
  ClipboardCheck,
  Bot,
  Bell,
  Palette,
  Save
} from 'lucide-react';

export default function SettingsView() {
  const [settings, setSettings] = useState({
    // Scanners
    enableSemgrep: true,
    enableTrivy: true,
    enableSnyk: false,
    snykApiKey: '',

    // SBOM
    sbomFormat: 'cyclonedx',
    autoGenerateSbom: false,

    // Compliance
    complianceFramework: 'cmmc-2',
    enableAutoCheck: true,

    // AI
    ollamaModel: 'llama3.2',
    enableAiSuggestions: true,

    // Notifications
    enableNotifications: true,
    notifyOnCritical: true,

    // Appearance
    theme: 'dark'
  });

  const handleSave = () => {
    console.log('Saving settings:', settings);
    // Save to localStorage or electron store
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-2xl font-bold text-white">Settings</h1>
          <p className="text-gray-400 mt-1">Configure J.O.E. DevSecOps Arsenal</p>
        </div>
        <button onClick={handleSave} className="btn-primary flex items-center gap-2">
          <Save size={16} />
          Save Changes
        </button>
      </div>

      {/* Scanner Settings */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Shield className="text-joe-blue" size={24} />
          <h2 className="font-heading font-semibold text-white text-lg">Security Scanners</h2>
        </div>

        <div className="space-y-4">
          <label className="flex items-center justify-between">
            <span className="text-gray-300">Enable Semgrep (SAST)</span>
            <input
              type="checkbox"
              checked={settings.enableSemgrep}
              onChange={(e) => setSettings({ ...settings, enableSemgrep: e.target.checked })}
              className="w-5 h-5 rounded text-joe-blue"
            />
          </label>

          <label className="flex items-center justify-between">
            <span className="text-gray-300">Enable Trivy (Container Scanner)</span>
            <input
              type="checkbox"
              checked={settings.enableTrivy}
              onChange={(e) => setSettings({ ...settings, enableTrivy: e.target.checked })}
              className="w-5 h-5 rounded text-joe-blue"
            />
          </label>

          <label className="flex items-center justify-between">
            <span className="text-gray-300">Enable Snyk (SCA)</span>
            <input
              type="checkbox"
              checked={settings.enableSnyk}
              onChange={(e) => setSettings({ ...settings, enableSnyk: e.target.checked })}
              className="w-5 h-5 rounded text-joe-blue"
            />
          </label>

          {settings.enableSnyk && (
            <div>
              <label className="block text-sm text-gray-400 mb-2">Snyk API Key</label>
              <input
                type="password"
                value={settings.snykApiKey}
                onChange={(e) => setSettings({ ...settings, snykApiKey: e.target.value })}
                className="input-field"
                placeholder="Enter your Snyk API key"
              />
            </div>
          )}
        </div>
      </motion.div>

      {/* SBOM Settings */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Package className="text-joe-blue" size={24} />
          <h2 className="font-heading font-semibold text-white text-lg">SBOM Settings</h2>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2">SBOM Format</label>
            <select
              value={settings.sbomFormat}
              onChange={(e) => setSettings({ ...settings, sbomFormat: e.target.value })}
              className="input-field"
            >
              <option value="cyclonedx">CycloneDX</option>
              <option value="spdx">SPDX</option>
            </select>
          </div>

          <label className="flex items-center justify-between">
            <span className="text-gray-300">Auto-generate SBOM on build</span>
            <input
              type="checkbox"
              checked={settings.autoGenerateSbom}
              onChange={(e) => setSettings({ ...settings, autoGenerateSbom: e.target.checked })}
              className="w-5 h-5 rounded text-joe-blue"
            />
          </label>
        </div>
      </motion.div>

      {/* Compliance Settings */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <ClipboardCheck className="text-joe-blue" size={24} />
          <h2 className="font-heading font-semibold text-white text-lg">Compliance</h2>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2">Compliance Framework</label>
            <select
              value={settings.complianceFramework}
              onChange={(e) => setSettings({ ...settings, complianceFramework: e.target.value })}
              className="input-field"
            >
              <option value="cmmc-2">CMMC 2.0</option>
              <option value="nist-800-53">NIST 800-53</option>
              <option value="iso-27001">ISO 27001</option>
              <option value="soc2">SOC 2</option>
            </select>
          </div>

          <label className="flex items-center justify-between">
            <span className="text-gray-300">Enable auto compliance check</span>
            <input
              type="checkbox"
              checked={settings.enableAutoCheck}
              onChange={(e) => setSettings({ ...settings, enableAutoCheck: e.target.checked })}
              className="w-5 h-5 rounded text-joe-blue"
            />
          </label>
        </div>
      </motion.div>

      {/* AI Settings */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Bot className="text-joe-blue" size={24} />
          <h2 className="font-heading font-semibold text-white text-lg">AI Assistant (Ollama)</h2>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2">Ollama Model</label>
            <select
              value={settings.ollamaModel}
              onChange={(e) => setSettings({ ...settings, ollamaModel: e.target.value })}
              className="input-field"
            >
              <option value="llama3.2">Llama 3.2</option>
              <option value="codellama">Code Llama</option>
              <option value="mistral">Mistral</option>
              <option value="mixtral">Mixtral</option>
            </select>
          </div>

          <label className="flex items-center justify-between">
            <span className="text-gray-300">Enable AI suggestions</span>
            <input
              type="checkbox"
              checked={settings.enableAiSuggestions}
              onChange={(e) => setSettings({ ...settings, enableAiSuggestions: e.target.checked })}
              className="w-5 h-5 rounded text-joe-blue"
            />
          </label>
        </div>
      </motion.div>

      {/* Notification Settings */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Bell className="text-joe-blue" size={24} />
          <h2 className="font-heading font-semibold text-white text-lg">Notifications</h2>
        </div>

        <div className="space-y-4">
          <label className="flex items-center justify-between">
            <span className="text-gray-300">Enable notifications</span>
            <input
              type="checkbox"
              checked={settings.enableNotifications}
              onChange={(e) => setSettings({ ...settings, enableNotifications: e.target.checked })}
              className="w-5 h-5 rounded text-joe-blue"
            />
          </label>

          <label className="flex items-center justify-between">
            <span className="text-gray-300">Alert on critical findings</span>
            <input
              type="checkbox"
              checked={settings.notifyOnCritical}
              onChange={(e) => setSettings({ ...settings, notifyOnCritical: e.target.checked })}
              className="w-5 h-5 rounded text-joe-blue"
            />
          </label>
        </div>
      </motion.div>
    </div>
  );
}
