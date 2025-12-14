import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Package,
  ClipboardCheck,
  Bot,
  Bell,
  Save,
  Smartphone,
  ShieldCheck,
  Loader2,
  CheckCircle,
  XCircle
} from 'lucide-react';
import { useAuthStore } from '../store/authStore';

export default function SettingsView() {
  const { setup2FA, confirm2FASetup, disable2FA, get2FAStatus, twoFactorEnabled, isLoading: _isLoading } = useAuthStore();

  // 2FA state
  const [is2FAEnabled, setIs2FAEnabled] = useState(false);
  const [show2FASetup, setShow2FASetup] = useState(false);
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [totpSecret, setTotpSecret] = useState<string | null>(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [setupMessage, setSetupMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [setupLoading, setSetupLoading] = useState(false);

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

  // Load 2FA status on mount
  useEffect(() => {
    const load2FAStatus = async () => {
      const status = await get2FAStatus();
      setIs2FAEnabled(status.enabled);
    };
    load2FAStatus();
  }, [get2FAStatus, twoFactorEnabled]);

  const handleStart2FASetup = async () => {
    setSetupLoading(true);
    setSetupMessage(null);

    const result = await setup2FA();

    if (result.success && result.qrCode) {
      setQrCode(result.qrCode);
      setTotpSecret(result.secret || null);
      setShow2FASetup(true);
    } else {
      setSetupMessage({ type: 'error', text: result.message || 'Failed to start 2FA setup' });
    }
    setSetupLoading(false);
  };

  const handleConfirm2FA = async () => {
    if (verificationCode.length !== 6) {
      setSetupMessage({ type: 'error', text: 'Please enter a 6-digit code' });
      return;
    }

    setSetupLoading(true);
    const result = await confirm2FASetup(verificationCode);

    if (result.success) {
      setSetupMessage({ type: 'success', text: result.message || '2FA enabled successfully!' });
      setIs2FAEnabled(true);
      setShow2FASetup(false);
      setQrCode(null);
      setTotpSecret(null);
      setVerificationCode('');
    } else {
      setSetupMessage({ type: 'error', text: result.message || 'Invalid code' });
    }
    setSetupLoading(false);
  };

  const handleDisable2FA = async () => {
    setSetupLoading(true);
    const success = await disable2FA();

    if (success) {
      setIs2FAEnabled(false);
      setSetupMessage({ type: 'success', text: '2FA has been disabled' });
    } else {
      setSetupMessage({ type: 'error', text: 'Failed to disable 2FA' });
    }
    setSetupLoading(false);
  };

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

      {/* Two-Factor Authentication */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-card p-6"
      >
        <div className="flex items-center gap-3 mb-4">
          <Smartphone className="text-joe-blue" size={24} />
          <h2 className="font-heading font-semibold text-white text-lg">Two-Factor Authentication</h2>
        </div>

        {/* Status Message */}
        {setupMessage && (
          <div className={`mb-4 p-3 rounded-lg flex items-center gap-2 ${
            setupMessage.type === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
          }`}>
            {setupMessage.type === 'success' ? <CheckCircle size={18} /> : <XCircle size={18} />}
            {setupMessage.text}
          </div>
        )}

        {/* 2FA Status */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <ShieldCheck className={is2FAEnabled ? 'text-green-400' : 'text-gray-500'} size={20} />
            <div>
              <p className="text-gray-300">
                {is2FAEnabled ? '2FA is enabled' : '2FA is not enabled'}
              </p>
              <p className="text-sm text-gray-500">
                {is2FAEnabled
                  ? 'Your account is protected with Google Authenticator'
                  : 'Add an extra layer of security to your account'}
              </p>
            </div>
          </div>

          {!show2FASetup && (
            <button
              onClick={is2FAEnabled ? handleDisable2FA : handleStart2FASetup}
              disabled={setupLoading}
              className={`px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 ${
                is2FAEnabled
                  ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
                  : 'bg-joe-blue/20 text-joe-blue hover:bg-joe-blue/30'
              }`}
            >
              {setupLoading && <Loader2 className="animate-spin" size={16} />}
              {is2FAEnabled ? 'Disable 2FA' : 'Enable 2FA'}
            </button>
          )}
        </div>

        {/* 2FA Setup Flow */}
        {show2FASetup && qrCode && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="border-t border-wolf-gray/30 pt-4"
          >
            <div className="text-center mb-4">
              <h3 className="text-white font-medium mb-2">Scan QR Code with Google Authenticator</h3>
              <p className="text-sm text-gray-400 mb-4">
                Open Google Authenticator on your phone and scan this QR code to add J.O.E.
              </p>

              {/* QR Code */}
              <div className="inline-block bg-white p-4 rounded-lg mb-4">
                <img src={qrCode} alt="2FA QR Code" className="w-48 h-48" />
              </div>

              {/* Manual Entry Secret */}
              {totpSecret && (
                <div className="mb-4">
                  <p className="text-xs text-gray-500 mb-1">Or enter this code manually:</p>
                  <code className="bg-wolf-gray/50 px-3 py-1 rounded text-joe-blue font-mono text-sm">
                    {totpSecret}
                  </code>
                </div>
              )}

              {/* Verification Code Input */}
              <div className="max-w-xs mx-auto">
                <label className="block text-sm text-gray-400 mb-2 text-left">
                  Enter the 6-digit code from your authenticator app
                </label>
                <input
                  type="text"
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="input-field text-center text-2xl tracking-widest font-mono"
                  placeholder="000000"
                  maxLength={6}
                />
              </div>

              {/* Action Buttons */}
              <div className="flex justify-center gap-3 mt-4">
                <button
                  onClick={() => {
                    setShow2FASetup(false);
                    setQrCode(null);
                    setTotpSecret(null);
                    setVerificationCode('');
                  }}
                  className="px-4 py-2 bg-wolf-gray/50 text-gray-300 rounded-lg hover:bg-wolf-gray/70 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleConfirm2FA}
                  disabled={verificationCode.length !== 6 || setupLoading}
                  className="px-4 py-2 bg-joe-blue text-white rounded-lg hover:bg-joe-blue/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {setupLoading && <Loader2 className="animate-spin" size={16} />}
                  Verify & Enable
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </motion.div>

      {/* Scanner Settings */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
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
