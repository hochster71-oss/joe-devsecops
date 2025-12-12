/**
 * J.O.E. Supply Chain Security View
 *
 * SBOM Generation & Analysis | Secret Detection | Dependency Scanning
 * Comprehensive supply chain risk management dashboard
 */

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Package,
  Shield,
  AlertTriangle,
  FileSearch,
  Download,
  RefreshCw,
  ChevronRight,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  CheckCircle,
  XCircle,
  Clock,
  Folder,
  FileCode,
  Key,
  Database,
  GitBranch,
  Scale,
  AlertCircle,
  Search,
  Filter,
  BarChart3,
  PieChart,
  TrendingUp,
  Zap,
  Vault,
  Plus,
  Trash2,
  Copy,
  FileDown,
  KeyRound,
  ShieldCheck
} from 'lucide-react';

// ========================================
// INTERFACES
// ========================================

interface SBOMComponent {
  name: string;
  version: string;
  type: string;
  purl?: string;
  licenses: string[];
  vulnerabilities?: { id: string; severity: string }[];
  riskScore?: number;
}

interface SBOM {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { name: string; version: string }[];
    component?: { name: string; version: string; type: string };
  };
  components: SBOMComponent[];
}

interface SBOMAnalysis {
  totalComponents: number;
  directDependencies: number;
  transitiveDependencies: number;
  licenseBreakdown: Record<string, number>;
  vulnerabilitySummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  riskScore: number;
  outdatedComponents: SBOMComponent[];
  licensingRisks: SBOMComponent[];
  recommendations: string[];
}

interface SecretFinding {
  id: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  file: string;
  line: number;
  maskedMatch: string;
  description: string;
  recommendation: string;
  entropy?: number;
}

interface ScanResult {
  scannedFiles: number;
  skippedFiles: number;
  findings: SecretFinding[];
  scanDuration: number;
  summary: { critical: number; high: number; medium: number; low: number; total: number };
}

interface VaultEntry {
  id: string;
  name: string;
  type: string;
  metadata: {
    createdAt: string;
    updatedAt: string;
    sourceFile?: string;
    sourceLine?: number;
    description?: string;
    tags?: string[];
  };
}

interface VaultStats {
  totalEntries: number;
  byType: Record<string, number>;
  lastUpdated: string;
  vaultSize: number;
  isLocked: boolean;
}

// ========================================
// SUPPLY CHAIN VIEW COMPONENT
// ========================================

export default function SupplyChainView() {
  const [activeTab, setActiveTab] = useState<'sbom' | 'secrets' | 'vault'>('sbom');

  // SBOM State
  const [sbom, setSbom] = useState<SBOM | null>(null);
  const [sbomAnalysis, setSbomAnalysis] = useState<SBOMAnalysis | null>(null);
  const [sbomLoading, setSbomLoading] = useState(false);
  const [sbomError, setSbomError] = useState<string | null>(null);
  const [projectPath, setProjectPath] = useState<string>('');

  // Secret Scanner State
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [secretsLoading, setSecretsLoading] = useState(false);
  const [secretsError, setSecretsError] = useState<string | null>(null);
  const [scanPath, setScanPath] = useState<string>('');
  const [showSecrets, setShowSecrets] = useState(false);
  const [secretFilter, setSecretFilter] = useState<string>('all');

  // Vault State
  const [vaultExists, setVaultExists] = useState(false);
  const [vaultUnlocked, setVaultUnlocked] = useState(false);
  const [vaultEntries, setVaultEntries] = useState<VaultEntry[]>([]);
  const [vaultStats, setVaultStats] = useState<VaultStats | null>(null);
  const [vaultLoading, setVaultLoading] = useState(false);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [masterPassword, setMasterPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<SecretFinding | null>(null);
  const [moveToVaultName, setMoveToVaultName] = useState('');

  // ========================================
  // SBOM HANDLERS
  // ========================================

  const handleSelectProject = async () => {
    try {
      const path = await window.electronAPI?.sbom?.selectProject();
      if (path) {
        setProjectPath(path);
      }
    } catch (err) {
      setSbomError('Failed to select project');
    }
  };

  const handleGenerateSBOM = async () => {
    if (!projectPath) {
      setSbomError('Please select a project directory first');
      return;
    }

    setSbomLoading(true);
    setSbomError(null);
    setSbom(null);
    setSbomAnalysis(null);

    try {
      const generatedSbom = await window.electronAPI?.sbom?.generate(projectPath);
      if (generatedSbom) {
        setSbom(generatedSbom);
        // Auto-analyze
        const analysis = await window.electronAPI?.sbom?.analyze(generatedSbom);
        setSbomAnalysis(analysis);
      }
    } catch (err) {
      setSbomError(err instanceof Error ? err.message : 'SBOM generation failed');
    } finally {
      setSbomLoading(false);
    }
  };

  // ========================================
  // SECRET SCANNER HANDLERS
  // ========================================

  const handleSelectScanDirectory = async () => {
    try {
      const path = await window.electronAPI?.secretScanner?.selectDirectory();
      if (path) {
        setScanPath(path);
      }
    } catch (err) {
      setSecretsError('Failed to select directory');
    }
  };

  const handleScanSecrets = async () => {
    if (!scanPath) {
      setSecretsError('Please select a directory to scan');
      return;
    }

    setSecretsLoading(true);
    setSecretsError(null);
    setScanResult(null);

    try {
      const result = await window.electronAPI?.secretScanner?.scanDirectory(scanPath);
      setScanResult(result);
    } catch (err) {
      setSecretsError(err instanceof Error ? err.message : 'Secret scan failed');
    } finally {
      setSecretsLoading(false);
    }
  };

  // ========================================
  // VAULT HANDLERS
  // ========================================

  const checkVaultStatus = async () => {
    try {
      const exists = await window.electronAPI?.vault?.exists();
      setVaultExists(exists);
      if (exists) {
        const unlocked = await window.electronAPI?.vault?.isUnlocked();
        setVaultUnlocked(unlocked);
        if (unlocked) {
          await loadVaultEntries();
        }
      }
      const stats = await window.electronAPI?.vault?.getStats();
      setVaultStats(stats);
    } catch (err) {
      console.error('Vault status check failed:', err);
    }
  };

  const loadVaultEntries = async () => {
    try {
      const entries = await window.electronAPI?.vault?.listEntries();
      setVaultEntries(entries || []);
      const stats = await window.electronAPI?.vault?.getStats();
      setVaultStats(stats);
    } catch (err) {
      setVaultError('Failed to load vault entries');
    }
  };

  const handleInitializeVault = async () => {
    if (!masterPassword || masterPassword.length < 15) {
      setVaultError('Master password must be at least 15 characters with mixed case, numbers, and symbols');
      return;
    }

    setVaultLoading(true);
    setVaultError(null);

    try {
      await window.electronAPI?.vault?.initialize(masterPassword);
      setVaultExists(true);
      setVaultUnlocked(true);
      setMasterPassword('');
      await loadVaultEntries();
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : 'Vault initialization failed');
    } finally {
      setVaultLoading(false);
    }
  };

  const handleUnlockVault = async () => {
    if (!masterPassword) {
      setVaultError('Please enter your master password');
      return;
    }

    setVaultLoading(true);
    setVaultError(null);

    try {
      await window.electronAPI?.vault?.unlock(masterPassword);
      setVaultUnlocked(true);
      setMasterPassword('');
      await loadVaultEntries();
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : 'Invalid master password');
    } finally {
      setVaultLoading(false);
    }
  };

  const handleLockVault = async () => {
    try {
      await window.electronAPI?.vault?.lock();
      setVaultUnlocked(false);
      setVaultEntries([]);
      setMasterPassword('');
    } catch (err) {
      setVaultError('Failed to lock vault');
    }
  };

  const handleMoveToVault = async (finding: SecretFinding, secretValue: string) => {
    if (!vaultUnlocked) {
      setVaultError('Vault must be unlocked to add secrets');
      return;
    }

    setVaultLoading(true);
    try {
      await window.electronAPI?.vault?.addSecret(
        moveToVaultName || `${finding.type}-${finding.id}`,
        secretValue,
        finding.type,
        {
          sourceFile: finding.file,
          sourceLine: finding.line,
          description: finding.description
        }
      );
      await loadVaultEntries();
      setSelectedFinding(null);
      setMoveToVaultName('');
      setVaultError(null);
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : 'Failed to add secret to vault');
    } finally {
      setVaultLoading(false);
    }
  };

  const handleDeleteFromVault = async (id: string) => {
    try {
      await window.electronAPI?.vault?.deleteSecret(id);
      await loadVaultEntries();
    } catch (err) {
      setVaultError('Failed to delete secret');
    }
  };

  const handleExportVault = async () => {
    try {
      await window.electronAPI?.vault?.export();
    } catch (err) {
      setVaultError('Failed to export vault');
    }
  };

  // Check vault status when vault tab is activated
  const handleTabChange = async (tab: 'sbom' | 'secrets' | 'vault') => {
    setActiveTab(tab);
    if (tab === 'vault') {
      await checkVaultStatus();
    }
  };

  // ========================================
  // HELPERS
  // ========================================

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-alert-critical bg-alert-critical/10 border-alert-critical/30';
      case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
      case 'MEDIUM': return 'text-alert-warning bg-alert-warning/10 border-alert-warning/30';
      case 'LOW': return 'text-dws-green bg-dws-green/10 border-dws-green/30';
      default: return 'text-gray-400 bg-gray-400/10 border-gray-400/30';
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-dws-green';
    if (score >= 60) return 'text-alert-warning';
    if (score >= 40) return 'text-orange-500';
    return 'text-alert-critical';
  };

  const filteredFindings = scanResult?.findings.filter(f => {
    if (secretFilter === 'all') return true;
    return f.severity === secretFilter;
  }) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-joe-blue/20 to-purple-500/20 border border-joe-blue/30">
            <Package className="text-joe-blue" size={28} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-white">
              Supply Chain Security
            </h1>
            <p className="text-gray-400 mt-1">SBOM Analysis | Secret Detection | Dependency Risk</p>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-dws-border pb-2">
        <button
          onClick={() => handleTabChange('sbom')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'sbom'
              ? 'bg-joe-blue/10 text-joe-blue border-b-2 border-joe-blue'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Package size={18} />
          SBOM Generator
        </button>
        <button
          onClick={() => handleTabChange('secrets')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'secrets'
              ? 'bg-joe-blue/10 text-joe-blue border-b-2 border-joe-blue'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Key size={18} />
          Secret Scanner
        </button>
        <button
          onClick={() => handleTabChange('vault')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'vault'
              ? 'bg-dws-green/10 text-dws-green border-b-2 border-dws-green'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <ShieldCheck size={18} />
          Secure Vault
          {vaultStats && !vaultStats.isLocked && (
            <span className="ml-1 px-1.5 py-0.5 text-xs bg-dws-green/20 text-dws-green rounded">
              {vaultStats.totalEntries}
            </span>
          )}
        </button>
      </div>

      <AnimatePresence mode="wait">
        {/* SBOM Tab */}
        {activeTab === 'sbom' && (
          <motion.div
            key="sbom"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* SBOM Controls */}
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <FileSearch className="text-joe-blue" size={20} />
                Generate Software Bill of Materials
              </h2>

              <div className="flex gap-4">
                <div className="flex-1">
                  <label className="text-sm text-gray-400 mb-2 block">Project Directory</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={projectPath}
                      onChange={(e) => setProjectPath(e.target.value)}
                      placeholder="Select or enter project path..."
                      className="input-field flex-1"
                    />
                    <button
                      onClick={handleSelectProject}
                      className="btn-secondary flex items-center gap-2"
                    >
                      <Folder size={16} />
                      Browse
                    </button>
                  </div>
                </div>
                <div className="flex items-end">
                  <button
                    onClick={handleGenerateSBOM}
                    disabled={sbomLoading || !projectPath}
                    className="btn-primary flex items-center gap-2"
                  >
                    {sbomLoading ? (
                      <RefreshCw size={16} className="animate-spin" />
                    ) : (
                      <Zap size={16} />
                    )}
                    Generate SBOM
                  </button>
                </div>
              </div>

              {sbomError && (
                <div className="mt-4 p-3 bg-alert-critical/10 border border-alert-critical/30 rounded-lg text-alert-critical text-sm">
                  {sbomError}
                </div>
              )}
            </div>

            {/* SBOM Analysis Results */}
            {sbomAnalysis && (
              <>
                {/* Summary Cards */}
                <div className="grid grid-cols-4 gap-4">
                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="glass-card p-4"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-joe-blue/10">
                        <Package className="text-joe-blue" size={20} />
                      </div>
                      <div>
                        <p className="text-gray-400 text-sm">Total Components</p>
                        <p className="text-2xl font-bold text-white">{sbomAnalysis.totalComponents}</p>
                      </div>
                    </div>
                  </motion.div>

                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.1 }}
                    className="glass-card p-4"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-purple-500/10">
                        <Shield className={getRiskColor(sbomAnalysis.riskScore)} size={20} />
                      </div>
                      <div>
                        <p className="text-gray-400 text-sm">Risk Score</p>
                        <p className={`text-2xl font-bold ${getRiskColor(sbomAnalysis.riskScore)}`}>
                          {sbomAnalysis.riskScore}/100
                        </p>
                      </div>
                    </div>
                  </motion.div>

                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.2 }}
                    className="glass-card p-4"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-alert-critical/10">
                        <AlertTriangle className="text-alert-critical" size={20} />
                      </div>
                      <div>
                        <p className="text-gray-400 text-sm">Vulnerabilities</p>
                        <p className="text-2xl font-bold text-white">
                          {sbomAnalysis.vulnerabilitySummary.total}
                        </p>
                      </div>
                    </div>
                  </motion.div>

                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.3 }}
                    className="glass-card p-4"
                  >
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-alert-warning/10">
                        <Scale className="text-alert-warning" size={20} />
                      </div>
                      <div>
                        <p className="text-gray-400 text-sm">License Risks</p>
                        <p className="text-2xl font-bold text-white">
                          {sbomAnalysis.licensingRisks.length}
                        </p>
                      </div>
                    </div>
                  </motion.div>
                </div>

                {/* Vulnerability Breakdown */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="glass-card p-6">
                    <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                      <AlertCircle size={18} className="text-alert-critical" />
                      Vulnerability Breakdown
                    </h3>
                    <div className="space-y-3">
                      {['critical', 'high', 'medium', 'low'].map((severity) => {
                        const count = sbomAnalysis.vulnerabilitySummary[severity as keyof typeof sbomAnalysis.vulnerabilitySummary];
                        const total = sbomAnalysis.vulnerabilitySummary.total || 1;
                        const percent = (count / total) * 100;
                        return (
                          <div key={severity} className="flex items-center gap-3">
                            <span className={`w-20 text-sm capitalize ${getSeverityColor(severity.toUpperCase()).split(' ')[0]}`}>
                              {severity}
                            </span>
                            <div className="flex-1 h-2 bg-dws-dark rounded-full overflow-hidden">
                              <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${percent}%` }}
                                className={`h-full ${severity === 'critical' ? 'bg-alert-critical' : severity === 'high' ? 'bg-orange-500' : severity === 'medium' ? 'bg-alert-warning' : 'bg-dws-green'}`}
                              />
                            </div>
                            <span className="text-white font-medium w-8 text-right">{count}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="glass-card p-6">
                    <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                      <Scale size={18} className="text-joe-blue" />
                      License Distribution
                    </h3>
                    <div className="space-y-2 max-h-40 overflow-y-auto">
                      {Object.entries(sbomAnalysis.licenseBreakdown)
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 8)
                        .map(([license, count]) => (
                          <div key={license} className="flex items-center justify-between text-sm">
                            <span className="text-gray-400">{license}</span>
                            <span className="text-white font-medium">{count}</span>
                          </div>
                        ))}
                    </div>
                  </div>
                </div>

                {/* Recommendations */}
                {sbomAnalysis.recommendations.length > 0 && (
                  <div className="glass-card p-6">
                    <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                      <CheckCircle size={18} className="text-dws-green" />
                      Recommendations
                    </h3>
                    <ul className="space-y-2">
                      {sbomAnalysis.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start gap-2 text-gray-300 text-sm">
                          <ChevronRight size={16} className="text-joe-blue mt-0.5 flex-shrink-0" />
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Components List */}
                {sbom && (
                  <div className="glass-card p-6">
                    <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                      <Database size={18} className="text-joe-blue" />
                      Components ({sbom.components.length})
                    </h3>
                    <div className="max-h-80 overflow-y-auto space-y-2">
                      {sbom.components.slice(0, 50).map((comp, i) => (
                        <div
                          key={`${comp.name}-${i}`}
                          className="flex items-center justify-between p-3 bg-dws-dark rounded-lg"
                        >
                          <div className="flex items-center gap-3">
                            <FileCode size={16} className="text-gray-500" />
                            <div>
                              <span className="text-white font-medium">{comp.name}</span>
                              <span className="text-gray-500 ml-2">@{comp.version}</span>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {comp.licenses.map((lic, j) => (
                              <span key={j} className="text-xs px-2 py-1 bg-joe-blue/10 text-joe-blue rounded">
                                {lic}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                      {sbom.components.length > 50 && (
                        <p className="text-gray-500 text-sm text-center py-2">
                          ... and {sbom.components.length - 50} more components
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </>
            )}
          </motion.div>
        )}

        {/* Secrets Tab */}
        {activeTab === 'secrets' && (
          <motion.div
            key="secrets"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Scanner Controls */}
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Key className="text-alert-warning" size={20} />
                Scan for Hardcoded Secrets
              </h2>

              <div className="flex gap-4">
                <div className="flex-1">
                  <label className="text-sm text-gray-400 mb-2 block">Directory to Scan</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={scanPath}
                      onChange={(e) => setScanPath(e.target.value)}
                      placeholder="Select or enter directory path..."
                      className="input-field flex-1"
                    />
                    <button
                      onClick={handleSelectScanDirectory}
                      className="btn-secondary flex items-center gap-2"
                    >
                      <Folder size={16} />
                      Browse
                    </button>
                  </div>
                </div>
                <div className="flex items-end">
                  <button
                    onClick={handleScanSecrets}
                    disabled={secretsLoading || !scanPath}
                    className="btn-primary flex items-center gap-2"
                  >
                    {secretsLoading ? (
                      <RefreshCw size={16} className="animate-spin" />
                    ) : (
                      <Search size={16} />
                    )}
                    Scan Secrets
                  </button>
                </div>
              </div>

              {secretsError && (
                <div className="mt-4 p-3 bg-alert-critical/10 border border-alert-critical/30 rounded-lg text-alert-critical text-sm">
                  {secretsError}
                </div>
              )}
            </div>

            {/* Scan Results */}
            {scanResult && (
              <>
                {/* Summary Cards */}
                <div className="grid grid-cols-5 gap-4">
                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="glass-card p-4"
                  >
                    <div className="text-center">
                      <FileSearch className="text-joe-blue mx-auto mb-2" size={24} />
                      <p className="text-2xl font-bold text-white">{scanResult.scannedFiles}</p>
                      <p className="text-gray-400 text-sm">Files Scanned</p>
                    </div>
                  </motion.div>

                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.1 }}
                    className="glass-card p-4"
                  >
                    <div className="text-center">
                      <AlertTriangle className="text-alert-critical mx-auto mb-2" size={24} />
                      <p className="text-2xl font-bold text-alert-critical">{scanResult.summary.critical}</p>
                      <p className="text-gray-400 text-sm">Critical</p>
                    </div>
                  </motion.div>

                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.2 }}
                    className="glass-card p-4"
                  >
                    <div className="text-center">
                      <AlertCircle className="text-orange-500 mx-auto mb-2" size={24} />
                      <p className="text-2xl font-bold text-orange-500">{scanResult.summary.high}</p>
                      <p className="text-gray-400 text-sm">High</p>
                    </div>
                  </motion.div>

                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.3 }}
                    className="glass-card p-4"
                  >
                    <div className="text-center">
                      <Shield className="text-alert-warning mx-auto mb-2" size={24} />
                      <p className="text-2xl font-bold text-alert-warning">{scanResult.summary.medium}</p>
                      <p className="text-gray-400 text-sm">Medium</p>
                    </div>
                  </motion.div>

                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: 0.4 }}
                    className="glass-card p-4"
                  >
                    <div className="text-center">
                      <Clock className="text-gray-400 mx-auto mb-2" size={24} />
                      <p className="text-2xl font-bold text-white">{(scanResult.scanDuration / 1000).toFixed(1)}s</p>
                      <p className="text-gray-400 text-sm">Duration</p>
                    </div>
                  </motion.div>
                </div>

                {/* Findings List */}
                <div className="glass-card p-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-white font-medium flex items-center gap-2">
                      <Lock size={18} className="text-alert-critical" />
                      Secret Findings ({scanResult.summary.total})
                    </h3>
                    <div className="flex items-center gap-4">
                      <button
                        onClick={() => setShowSecrets(!showSecrets)}
                        className="text-sm text-gray-400 hover:text-white flex items-center gap-1"
                      >
                        {showSecrets ? <EyeOff size={14} /> : <Eye size={14} />}
                        {showSecrets ? 'Hide' : 'Show'} Values
                      </button>
                      <select
                        value={secretFilter}
                        onChange={(e) => setSecretFilter(e.target.value)}
                        className="input-field text-sm py-1"
                      >
                        <option value="all">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                      </select>
                    </div>
                  </div>

                  {filteredFindings.length === 0 ? (
                    <div className="text-center py-8">
                      <CheckCircle className="text-dws-green mx-auto mb-3" size={48} />
                      <p className="text-white font-medium">No secrets found!</p>
                      <p className="text-gray-400 text-sm mt-1">Your code appears clean of hardcoded secrets</p>
                    </div>
                  ) : (
                    <div className="space-y-3 max-h-96 overflow-y-auto">
                      {filteredFindings.map((finding) => (
                        <motion.div
                          key={finding.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          className={`p-4 rounded-lg border ${getSeverityColor(finding.severity)}`}
                        >
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-2">
                                <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                                  {finding.severity}
                                </span>
                                <span className="text-white font-medium">{finding.type.replace(/_/g, ' ')}</span>
                              </div>
                              <p className="text-gray-400 text-sm mb-1">{finding.description}</p>
                              <p className="text-gray-500 text-xs font-mono">
                                {finding.file}:{finding.line}
                              </p>
                              {showSecrets && (
                                <div className="mt-2 p-2 bg-dws-dark rounded text-xs font-mono text-gray-300 overflow-x-auto">
                                  {finding.maskedMatch}
                                </div>
                              )}
                            </div>
                          </div>
                          <div className="mt-3 pt-3 border-t border-white/10">
                            <p className="text-sm text-joe-blue flex items-center gap-1">
                              <ChevronRight size={14} />
                              {finding.recommendation}
                            </p>
                          </div>
                        </motion.div>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}

            {/* Info Panel */}
            {!scanResult && (
              <div className="glass-card p-6">
                <h3 className="text-white font-medium mb-4">Detectable Secret Types</h3>
                <div className="grid grid-cols-4 gap-3">
                  {[
                    'AWS Keys', 'Azure Secrets', 'GCP Keys', 'GitHub Tokens',
                    'GitLab Tokens', 'Slack Tokens', 'JWT Secrets', 'Private Keys',
                    'API Keys', 'Database URLs', 'Passwords', 'Bearer Tokens',
                    'Stripe Keys', 'NPM Tokens', 'Docker Auth', 'K8s Secrets'
                  ].map((type) => (
                    <div key={type} className="flex items-center gap-2 text-gray-400 text-sm">
                      <Key size={12} className="text-joe-blue" />
                      {type}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}

        {/* Secure Vault Tab */}
        {activeTab === 'vault' && (
          <motion.div
            key="vault"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Vault Status Header */}
            <div className="glass-card p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                  <ShieldCheck className="text-dws-green" size={20} />
                  AES-256-GCM Encrypted Vault
                </h2>
                {vaultUnlocked && (
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleExportVault}
                      className="btn-secondary flex items-center gap-2 text-sm"
                    >
                      <FileDown size={14} />
                      Export Backup
                    </button>
                    <button
                      onClick={handleLockVault}
                      className="btn-secondary flex items-center gap-2 text-sm text-alert-warning"
                    >
                      <Lock size={14} />
                      Lock Vault
                    </button>
                  </div>
                )}
              </div>

              {/* Vault Info */}
              <div className="grid grid-cols-4 gap-4 mb-6">
                <div className="p-3 bg-dws-dark rounded-lg">
                  <p className="text-gray-400 text-xs">Encryption</p>
                  <p className="text-dws-green font-medium">AES-256-GCM</p>
                </div>
                <div className="p-3 bg-dws-dark rounded-lg">
                  <p className="text-gray-400 text-xs">Key Derivation</p>
                  <p className="text-joe-blue font-medium">PBKDF2-SHA512</p>
                </div>
                <div className="p-3 bg-dws-dark rounded-lg">
                  <p className="text-gray-400 text-xs">Iterations</p>
                  <p className="text-white font-medium">100,000</p>
                </div>
                <div className="p-3 bg-dws-dark rounded-lg">
                  <p className="text-gray-400 text-xs">Status</p>
                  <p className={`font-medium flex items-center gap-1 ${vaultUnlocked ? 'text-dws-green' : 'text-alert-warning'}`}>
                    {vaultUnlocked ? <Unlock size={14} /> : <Lock size={14} />}
                    {vaultUnlocked ? 'Unlocked' : 'Locked'}
                  </p>
                </div>
              </div>

              {/* Initialize or Unlock */}
              {!vaultUnlocked && (
                <div className="space-y-4">
                  <div>
                    <label className="text-sm text-gray-400 mb-2 block">
                      {vaultExists ? 'Master Password' : 'Create Master Password (DoD: 15+ chars, mixed case, numbers, symbols)'}
                    </label>
                    <div className="flex gap-2">
                      <div className="relative flex-1">
                        <input
                          type={showPassword ? 'text' : 'password'}
                          value={masterPassword}
                          onChange={(e) => setMasterPassword(e.target.value)}
                          placeholder={vaultExists ? 'Enter master password...' : 'Create a strong master password...'}
                          className="input-field w-full pr-10"
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                        >
                          {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                      </div>
                      <button
                        onClick={vaultExists ? handleUnlockVault : handleInitializeVault}
                        disabled={vaultLoading || !masterPassword}
                        className="btn-primary flex items-center gap-2"
                      >
                        {vaultLoading ? (
                          <RefreshCw size={16} className="animate-spin" />
                        ) : (
                          <KeyRound size={16} />
                        )}
                        {vaultExists ? 'Unlock Vault' : 'Initialize Vault'}
                      </button>
                    </div>
                  </div>

                  {!vaultExists && (
                    <div className="p-4 bg-alert-warning/10 border border-alert-warning/30 rounded-lg">
                      <p className="text-alert-warning text-sm flex items-center gap-2">
                        <AlertTriangle size={16} />
                        <strong>Important:</strong> This password cannot be recovered. Store it securely!
                      </p>
                    </div>
                  )}
                </div>
              )}

              {vaultError && (
                <div className="mt-4 p-3 bg-alert-critical/10 border border-alert-critical/30 rounded-lg text-alert-critical text-sm">
                  {vaultError}
                </div>
              )}
            </div>

            {/* Vault Contents */}
            {vaultUnlocked && (
              <>
                {/* Stats */}
                {vaultStats && (
                  <div className="grid grid-cols-4 gap-4">
                    <motion.div
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      className="glass-card p-4"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-dws-green/10">
                          <Database className="text-dws-green" size={20} />
                        </div>
                        <div>
                          <p className="text-gray-400 text-sm">Total Secrets</p>
                          <p className="text-2xl font-bold text-white">{vaultStats.totalEntries}</p>
                        </div>
                      </div>
                    </motion.div>

                    <motion.div
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: 0.1 }}
                      className="glass-card p-4"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-joe-blue/10">
                          <Key className="text-joe-blue" size={20} />
                        </div>
                        <div>
                          <p className="text-gray-400 text-sm">API Keys</p>
                          <p className="text-2xl font-bold text-white">{vaultStats.byType?.API_KEY || 0}</p>
                        </div>
                      </div>
                    </motion.div>

                    <motion.div
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: 0.2 }}
                      className="glass-card p-4"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-purple-500/10">
                          <Lock className="text-purple-500" size={20} />
                        </div>
                        <div>
                          <p className="text-gray-400 text-sm">Passwords</p>
                          <p className="text-2xl font-bold text-white">{vaultStats.byType?.PASSWORD || 0}</p>
                        </div>
                      </div>
                    </motion.div>

                    <motion.div
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: 0.3 }}
                      className="glass-card p-4"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-alert-warning/10">
                          <FileCode className="text-alert-warning" size={20} />
                        </div>
                        <div>
                          <p className="text-gray-400 text-sm">Vault Size</p>
                          <p className="text-2xl font-bold text-white">
                            {(vaultStats.vaultSize / 1024).toFixed(1)} KB
                          </p>
                        </div>
                      </div>
                    </motion.div>
                  </div>
                )}

                {/* Entries List */}
                <div className="glass-card p-6">
                  <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                    <Database size={18} className="text-dws-green" />
                    Stored Secrets ({vaultEntries.length})
                  </h3>

                  {vaultEntries.length === 0 ? (
                    <div className="text-center py-8">
                      <ShieldCheck className="text-dws-green/30 mx-auto mb-3" size={48} />
                      <p className="text-gray-400">No secrets stored yet</p>
                      <p className="text-gray-500 text-sm mt-1">
                        Scan for secrets and move them to the vault for secure storage
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {vaultEntries.map((entry, i) => (
                        <motion.div
                          key={entry.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.05 }}
                          className="flex items-center justify-between p-3 bg-dws-dark rounded-lg"
                        >
                          <div className="flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-dws-green/10">
                              <Key className="text-dws-green" size={16} />
                            </div>
                            <div>
                              <p className="text-white font-medium">{entry.name}</p>
                              <div className="flex items-center gap-2 text-xs text-gray-500">
                                <span className="px-1.5 py-0.5 bg-joe-blue/10 text-joe-blue rounded">
                                  {entry.type}
                                </span>
                                {entry.metadata.sourceFile && (
                                  <span>from {entry.metadata.sourceFile}</span>
                                )}
                                <span>
                                  Added {new Date(entry.metadata.createdAt).toLocaleDateString()}
                                </span>
                              </div>
                            </div>
                          </div>
                          <button
                            type="button"
                            onClick={() => handleDeleteFromVault(entry.id)}
                            className="p-2 text-gray-400 hover:text-alert-critical transition-colors"
                            title="Delete from vault"
                          >
                            <Trash2 size={16} />
                          </button>
                        </motion.div>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}

            {/* Security Info */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                <Shield size={18} className="text-joe-blue" />
                Vault Security Features
              </h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="flex items-start gap-3">
                  <CheckCircle className="text-dws-green mt-0.5" size={16} />
                  <div>
                    <p className="text-white text-sm font-medium">AES-256-GCM Encryption</p>
                    <p className="text-gray-500 text-xs">Military-grade authenticated encryption</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="text-dws-green mt-0.5" size={16} />
                  <div>
                    <p className="text-white text-sm font-medium">PBKDF2 Key Derivation</p>
                    <p className="text-gray-500 text-xs">100,000 iterations with SHA-512</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="text-dws-green mt-0.5" size={16} />
                  <div>
                    <p className="text-white text-sm font-medium">DoD STIG Compliant</p>
                    <p className="text-gray-500 text-xs">Meets federal security requirements</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="text-dws-green mt-0.5" size={16} />
                  <div>
                    <p className="text-white text-sm font-medium">Tamper Detection</p>
                    <p className="text-gray-500 text-xs">Authentication tags verify integrity</p>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
