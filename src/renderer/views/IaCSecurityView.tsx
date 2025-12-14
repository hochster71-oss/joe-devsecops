/**
 * J.O.E. Infrastructure as Code (IaC) Security View
 *
 * Terraform | CloudFormation | Kubernetes | Dockerfile | Ansible | Helm
 * Comprehensive IaC security scanning and compliance checking
 */

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Cloud,
  Shield,
  AlertTriangle,
  FileSearch,
  RefreshCw,
  ChevronRight,
  CheckCircle,
  XCircle,
  Clock,
  Folder,
  FileCode,
  Code,
  Server,
  Container,
  Database,
  Lock,
  AlertCircle,
  Search,
  Filter,
  BarChart3,
  Zap,
  Box,
  Layers,
  Terminal,
  FileJson,
  Settings,
  Download,
  Play,
  GitBranch,
  Eye,
  Copy,
  ExternalLink
} from 'lucide-react';
import { useIaCStore } from '../store/iacStore';

// ========================================
// INTERFACES
// ========================================

type IaCType = 'terraform' | 'cloudformation' | 'kubernetes' | 'dockerfile' | 'ansible' | 'helm';
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface IaCFinding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  resource?: string;
  file: string;
  line: number;
  remediation: string;
  references?: string[];
  cwe?: string;
  compliance?: string[];
}

interface IaCScanResult {
  scanId: string;
  timestamp: string;
  duration: number;
  iacType: IaCType;
  filesScanned: number;
  findings: IaCFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  passedChecks: number;
  failedChecks: number;
}

// ========================================
// IAC SECURITY VIEW COMPONENT
// ========================================

export default function IaCSecurityView() {
  const {
    scanResults,
    currentScan,
    isScanning,
    error,
    selectedSeverities,
    selectedTypes,
    searchQuery,
    setSeverityFilter,
    setTypeFilter,
    setSearchQuery,
    getFilteredFindings,
    clearResults
  } = useIaCStore();

  const [scanPath, setScanPath] = useState<string>('');
  const [selectedFinding, setSelectedFinding] = useState<IaCFinding | null>(null);
  const [activeTab, setActiveTab] = useState<'scan' | 'results' | 'rules'>('scan');

  // IaC type icons
  const getIaCIcon = (type: IaCType) => {
    switch (type) {
      case 'terraform': return <Layers className="text-purple-500" size={18} />;
      case 'cloudformation': return <Cloud className="text-orange-500" size={18} />;
      case 'kubernetes': return <Box className="text-blue-500" size={18} />;
      case 'dockerfile': return <Container className="text-cyan-500" size={18} />;
      case 'ansible': return <Terminal className="text-red-500" size={18} />;
      case 'helm': return <FileJson className="text-green-500" size={18} />;
      default: return <FileCode className="text-gray-500" size={18} />;
    }
  };

  const getIaCLabel = (type: IaCType) => {
    switch (type) {
      case 'terraform': return 'Terraform';
      case 'cloudformation': return 'CloudFormation';
      case 'kubernetes': return 'Kubernetes';
      case 'dockerfile': return 'Dockerfile';
      case 'ansible': return 'Ansible';
      case 'helm': return 'Helm';
      default: return type;
    }
  };

  // Severity styling
  const getSeverityColor = (severity: Severity) => {
    switch (severity) {
      case 'critical': return 'text-alert-critical bg-alert-critical/10 border-alert-critical/30';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
      case 'medium': return 'text-alert-warning bg-alert-warning/10 border-alert-warning/30';
      case 'low': return 'text-joe-blue bg-joe-blue/10 border-joe-blue/30';
      case 'info': return 'text-gray-400 bg-gray-400/10 border-gray-400/30';
      default: return 'text-gray-400 bg-gray-400/10 border-gray-400/30';
    }
  };

  const getSeverityBadgeColor = (severity: Severity) => {
    switch (severity) {
      case 'critical': return 'bg-alert-critical text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-alert-warning text-black';
      case 'low': return 'bg-joe-blue text-white';
      case 'info': return 'bg-gray-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  // ========================================
  // HANDLERS
  // ========================================

  const handleSelectDirectory = async () => {
    try {
      const path = await window.electronAPI?.iac?.selectDirectory();
      if (path) {
        setScanPath(path);
      }
    } catch (err) {
      console.error('Failed to select directory:', err);
    }
  };

  const handleScan = async () => {
    if (!scanPath) return;

    try {
      await window.electronAPI?.iac?.scanDirectory(scanPath);
      setActiveTab('results');
    } catch (err) {
      console.error('IaC scan failed:', err);
    }
  };

  const handleScanFile = async (filePath: string) => {
    try {
      await window.electronAPI?.iac?.scanFile(filePath);
      setActiveTab('results');
    } catch (err) {
      console.error('IaC file scan failed:', err);
    }
  };

  const handleCopyRemediation = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  // Get filtered findings from store
  const filteredFindings = getFilteredFindings();

  // Calculate summary from current scan
  const currentSummary = currentScan?.summary || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0
  };

  // Available IaC types
  const iacTypes: IaCType[] = ['terraform', 'cloudformation', 'kubernetes', 'dockerfile', 'ansible', 'helm'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-purple-500/20 to-cyan-500/20 border border-purple-500/30">
            <Cloud className="text-purple-500" size={28} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-white">
              IaC Security Scanner
            </h1>
            <p className="text-gray-400 mt-1">Terraform | CloudFormation | Kubernetes | Docker | Ansible</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {scanResults.length > 0 && (
            <button
              onClick={clearResults}
              className="btn-secondary flex items-center gap-2 text-sm"
            >
              <RefreshCw size={14} />
              Clear Results
            </button>
          )}
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-dws-border pb-2">
        <button
          onClick={() => setActiveTab('scan')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'scan'
              ? 'bg-purple-500/10 text-purple-500 border-b-2 border-purple-500'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <FileSearch size={18} />
          Scan
        </button>
        <button
          onClick={() => setActiveTab('results')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'results'
              ? 'bg-purple-500/10 text-purple-500 border-b-2 border-purple-500'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <AlertTriangle size={18} />
          Findings
          {currentSummary.total > 0 && (
            <span className="ml-1 px-1.5 py-0.5 text-xs bg-alert-critical/20 text-alert-critical rounded">
              {currentSummary.total}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'rules'
              ? 'bg-purple-500/10 text-purple-500 border-b-2 border-purple-500'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Shield size={18} />
          Rules & Checks
        </button>
      </div>

      <AnimatePresence mode="wait">
        {/* Scan Tab */}
        {activeTab === 'scan' && (
          <motion.div
            key="scan"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Scan Controls */}
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Zap className="text-purple-500" size={20} />
                Scan Infrastructure as Code
              </h2>

              <div className="flex gap-4">
                <div className="flex-1">
                  <label className="text-sm text-gray-400 mb-2 block">Directory or File Path</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={scanPath}
                      onChange={(e) => setScanPath(e.target.value)}
                      placeholder="Select or enter path to IaC files..."
                      className="input-field flex-1"
                    />
                    <button
                      onClick={handleSelectDirectory}
                      className="btn-secondary flex items-center gap-2"
                    >
                      <Folder size={16} />
                      Browse
                    </button>
                  </div>
                </div>
                <div className="flex items-end">
                  <button
                    onClick={handleScan}
                    disabled={isScanning || !scanPath}
                    className="btn-primary flex items-center gap-2"
                  >
                    {isScanning ? (
                      <RefreshCw size={16} className="animate-spin" />
                    ) : (
                      <Play size={16} />
                    )}
                    {isScanning ? 'Scanning...' : 'Start Scan'}
                  </button>
                </div>
              </div>

              {error && (
                <div className="mt-4 p-3 bg-alert-critical/10 border border-alert-critical/30 rounded-lg text-alert-critical text-sm">
                  {error}
                </div>
              )}
            </div>

            {/* Supported IaC Types */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4">Supported IaC Platforms</h3>
              <div className="grid grid-cols-3 gap-4">
                {[
                  {
                    type: 'terraform' as IaCType,
                    name: 'Terraform',
                    description: 'HashiCorp Configuration Language',
                    files: '*.tf, *.tfvars',
                    checks: 45,
                    color: 'purple'
                  },
                  {
                    type: 'cloudformation' as IaCType,
                    name: 'CloudFormation',
                    description: 'AWS Infrastructure Templates',
                    files: '*.yaml, *.json',
                    checks: 35,
                    color: 'orange'
                  },
                  {
                    type: 'kubernetes' as IaCType,
                    name: 'Kubernetes',
                    description: 'Container Orchestration Manifests',
                    files: '*.yaml, *.yml',
                    checks: 50,
                    color: 'blue'
                  },
                  {
                    type: 'dockerfile' as IaCType,
                    name: 'Dockerfile',
                    description: 'Container Image Definitions',
                    files: 'Dockerfile*',
                    checks: 25,
                    color: 'cyan'
                  },
                  {
                    type: 'ansible' as IaCType,
                    name: 'Ansible',
                    description: 'Configuration Management Playbooks',
                    files: '*.yml, *.yaml',
                    checks: 20,
                    color: 'red'
                  },
                  {
                    type: 'helm' as IaCType,
                    name: 'Helm Charts',
                    description: 'Kubernetes Package Templates',
                    files: 'Chart.yaml, values.yaml',
                    checks: 30,
                    color: 'green'
                  }
                ].map((platform) => (
                  <motion.div
                    key={platform.type}
                    whileHover={{ scale: 1.02 }}
                    className="p-4 bg-dws-dark rounded-lg border border-dws-border hover:border-purple-500/30 transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-3 mb-2">
                      {getIaCIcon(platform.type)}
                      <span className="text-white font-medium">{platform.name}</span>
                    </div>
                    <p className="text-gray-500 text-sm mb-2">{platform.description}</p>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-gray-500">{platform.files}</span>
                      <span className="text-purple-500">{platform.checks} checks</span>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Security Categories */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4">Security Check Categories</h3>
              <div className="grid grid-cols-4 gap-3">
                {[
                  { icon: Lock, name: 'Encryption', desc: 'At-rest & in-transit encryption' },
                  { icon: Shield, name: 'Access Control', desc: 'IAM & RBAC misconfigurations' },
                  { icon: Server, name: 'Network Security', desc: 'Security groups & firewalls' },
                  { icon: Database, name: 'Data Protection', desc: 'Storage & backup security' },
                  { icon: AlertTriangle, name: 'Secrets Management', desc: 'Hardcoded credentials' },
                  { icon: Container, name: 'Container Security', desc: 'Image & runtime security' },
                  { icon: Settings, name: 'Configuration', desc: 'Insecure defaults' },
                  { icon: GitBranch, name: 'Compliance', desc: 'CIS, SOC2, HIPAA mappings' }
                ].map((cat) => (
                  <div key={cat.name} className="flex items-start gap-2 p-3 bg-dws-dark/50 rounded-lg">
                    <cat.icon className="text-purple-500 mt-0.5" size={16} />
                    <div>
                      <p className="text-white text-sm font-medium">{cat.name}</p>
                      <p className="text-gray-500 text-xs">{cat.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {/* Results Tab */}
        {activeTab === 'results' && (
          <motion.div
            key="results"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Summary Cards */}
            {currentScan && (
              <div className="grid grid-cols-6 gap-4">
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="glass-card p-4"
                >
                  <div className="text-center">
                    <FileSearch className="text-purple-500 mx-auto mb-2" size={24} />
                    <p className="text-2xl font-bold text-white">{currentScan.filesScanned}</p>
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
                    <p className="text-2xl font-bold text-alert-critical">{currentSummary.critical}</p>
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
                    <p className="text-2xl font-bold text-orange-500">{currentSummary.high}</p>
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
                    <p className="text-2xl font-bold text-alert-warning">{currentSummary.medium}</p>
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
                    <CheckCircle className="text-dws-green mx-auto mb-2" size={24} />
                    <p className="text-2xl font-bold text-dws-green">{currentScan.passedChecks}</p>
                    <p className="text-gray-400 text-sm">Passed</p>
                  </div>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.5 }}
                  className="glass-card p-4"
                >
                  <div className="text-center">
                    <Clock className="text-gray-400 mx-auto mb-2" size={24} />
                    <p className="text-2xl font-bold text-white">{(currentScan.duration / 1000).toFixed(1)}s</p>
                    <p className="text-gray-400 text-sm">Duration</p>
                  </div>
                </motion.div>
              </div>
            )}

            {/* Filters */}
            <div className="glass-card p-4">
              <div className="flex items-center gap-4">
                <div className="flex-1">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search findings..."
                      className="input-field w-full pl-10"
                    />
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Filter size={16} className="text-gray-500" />
                  <span className="text-gray-400 text-sm">Severity:</span>
                  {(['critical', 'high', 'medium', 'low'] as Severity[]).map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setSeverityFilter(sev, !selectedSeverities.includes(sev))}
                      className={`px-2 py-1 text-xs rounded capitalize transition-colors ${
                        selectedSeverities.includes(sev)
                          ? getSeverityBadgeColor(sev)
                          : 'bg-dws-dark text-gray-400 hover:text-white'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-gray-400 text-sm">Type:</span>
                  {iacTypes.slice(0, 4).map((type) => (
                    <button
                      key={type}
                      onClick={() => setTypeFilter(type, !selectedTypes.includes(type))}
                      className={`px-2 py-1 text-xs rounded transition-colors flex items-center gap-1 ${
                        selectedTypes.includes(type)
                          ? 'bg-purple-500/20 text-purple-500'
                          : 'bg-dws-dark text-gray-400 hover:text-white'
                      }`}
                    >
                      {getIaCIcon(type)}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Findings List */}
            <div className="glass-card p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-white font-medium flex items-center gap-2">
                  <AlertTriangle size={18} className="text-alert-critical" />
                  Security Findings ({filteredFindings.length})
                </h3>
              </div>

              {filteredFindings.length === 0 ? (
                <div className="text-center py-12">
                  {currentScan ? (
                    <>
                      <CheckCircle className="text-dws-green mx-auto mb-3" size={48} />
                      <p className="text-white font-medium">No security issues found!</p>
                      <p className="text-gray-400 text-sm mt-1">Your infrastructure code passed all security checks</p>
                    </>
                  ) : (
                    <>
                      <FileSearch className="text-gray-500 mx-auto mb-3" size={48} />
                      <p className="text-gray-400">No scan results yet</p>
                      <p className="text-gray-500 text-sm mt-1">Run a scan to see findings</p>
                    </>
                  )}
                </div>
              ) : (
                <div className="space-y-3 max-h-[500px] overflow-y-auto">
                  {filteredFindings.map((finding, index) => (
                    <motion.div
                      key={finding.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.02 }}
                      className={`p-4 rounded-lg border cursor-pointer transition-colors hover:border-purple-500/50 ${getSeverityColor(finding.severity)}`}
                      onClick={() => setSelectedFinding(finding)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityBadgeColor(finding.severity)}`}>
                              {finding.severity.toUpperCase()}
                            </span>
                            <span className="text-xs text-gray-500 font-mono">{finding.ruleId}</span>
                            {finding.compliance && finding.compliance.length > 0 && (
                              <span className="text-xs text-joe-blue">
                                {finding.compliance.slice(0, 2).join(', ')}
                              </span>
                            )}
                          </div>
                          <p className="text-white font-medium mb-1">{finding.title}</p>
                          <p className="text-gray-400 text-sm line-clamp-2">{finding.description}</p>
                          <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
                            <span className="flex items-center gap-1">
                              <FileCode size={12} />
                              {finding.file}:{finding.line}
                            </span>
                            {finding.resource && (
                              <span className="flex items-center gap-1">
                                <Box size={12} />
                                {finding.resource}
                              </span>
                            )}
                          </div>
                        </div>
                        <ChevronRight className="text-gray-500" size={20} />
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </div>

            {/* Finding Detail Modal */}
            <AnimatePresence>
              {selectedFinding && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4"
                  onClick={() => setSelectedFinding(null)}
                >
                  <motion.div
                    initial={{ scale: 0.9, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0.9, opacity: 0 }}
                    className="glass-card p-6 max-w-2xl w-full max-h-[80vh] overflow-y-auto"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <span className={`px-3 py-1 rounded text-sm font-medium ${getSeverityBadgeColor(selectedFinding.severity)}`}>
                          {selectedFinding.severity.toUpperCase()}
                        </span>
                        <span className="text-gray-400 font-mono text-sm">{selectedFinding.ruleId}</span>
                      </div>
                      <button
                        onClick={() => setSelectedFinding(null)}
                        className="text-gray-400 hover:text-white"
                      >
                        <XCircle size={24} />
                      </button>
                    </div>

                    <h3 className="text-xl font-bold text-white mb-3">{selectedFinding.title}</h3>
                    <p className="text-gray-300 mb-4">{selectedFinding.description}</p>

                    <div className="space-y-4">
                      <div className="p-3 bg-dws-dark rounded-lg">
                        <p className="text-gray-400 text-sm mb-1">Location</p>
                        <p className="text-white font-mono text-sm">
                          {selectedFinding.file}:{selectedFinding.line}
                        </p>
                        {selectedFinding.resource && (
                          <p className="text-joe-blue text-sm mt-1">Resource: {selectedFinding.resource}</p>
                        )}
                      </div>

                      <div className="p-3 bg-dws-dark rounded-lg">
                        <p className="text-gray-400 text-sm mb-1">Category</p>
                        <p className="text-white">{selectedFinding.category}</p>
                      </div>

                      <div className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <p className="text-dws-green font-medium flex items-center gap-2">
                            <CheckCircle size={16} />
                            Remediation
                          </p>
                          <button
                            onClick={() => handleCopyRemediation(selectedFinding.remediation)}
                            className="text-dws-green hover:text-white transition-colors"
                          >
                            <Copy size={14} />
                          </button>
                        </div>
                        <p className="text-gray-300 text-sm">{selectedFinding.remediation}</p>
                      </div>

                      {selectedFinding.compliance && selectedFinding.compliance.length > 0 && (
                        <div className="p-3 bg-dws-dark rounded-lg">
                          <p className="text-gray-400 text-sm mb-2">Compliance Frameworks</p>
                          <div className="flex flex-wrap gap-2">
                            {selectedFinding.compliance.map((comp) => (
                              <span key={comp} className="px-2 py-1 bg-joe-blue/10 text-joe-blue text-xs rounded">
                                {comp}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {selectedFinding.cwe && (
                        <div className="p-3 bg-dws-dark rounded-lg">
                          <p className="text-gray-400 text-sm mb-1">CWE Reference</p>
                          <p className="text-white">{selectedFinding.cwe}</p>
                        </div>
                      )}

                      {selectedFinding.references && selectedFinding.references.length > 0 && (
                        <div className="p-3 bg-dws-dark rounded-lg">
                          <p className="text-gray-400 text-sm mb-2">References</p>
                          <div className="space-y-1">
                            {selectedFinding.references.map((ref, i) => (
                              <a
                                key={i}
                                href={ref}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-joe-blue text-sm hover:underline flex items-center gap-1"
                              >
                                <ExternalLink size={12} />
                                {ref}
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </motion.div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        )}

        {/* Rules Tab */}
        {activeTab === 'rules' && (
          <motion.div
            key="rules"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Built-in Rules */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                <Shield className="text-purple-500" size={20} />
                Built-in Security Rules
              </h3>

              <div className="space-y-4">
                {/* Terraform Rules */}
                <div className="border border-dws-border rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Layers className="text-purple-500" size={18} />
                    <span className="text-white font-medium">Terraform Rules</span>
                    <span className="text-gray-500 text-sm">(45 checks)</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    {[
                      'TF001: Unencrypted S3 bucket',
                      'TF002: Public S3 bucket',
                      'TF003: Unencrypted RDS instance',
                      'TF004: Overly permissive security group',
                      'TF005: Missing CloudTrail logging'
                    ].map((rule) => (
                      <div key={rule} className="flex items-center gap-2 text-gray-400">
                        <CheckCircle size={12} className="text-dws-green" />
                        {rule}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Kubernetes Rules */}
                <div className="border border-dws-border rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Box className="text-blue-500" size={18} />
                    <span className="text-white font-medium">Kubernetes Rules</span>
                    <span className="text-gray-500 text-sm">(50 checks)</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    {[
                      'K8S001: Container running as root',
                      'K8S002: Privileged container',
                      'K8S003: Host network/PID namespace',
                      'K8S004: No resource limits',
                      'K8S005: Writable root filesystem',
                      'K8S006: Capability escalation allowed'
                    ].map((rule) => (
                      <div key={rule} className="flex items-center gap-2 text-gray-400">
                        <CheckCircle size={12} className="text-dws-green" />
                        {rule}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Dockerfile Rules */}
                <div className="border border-dws-border rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Container className="text-cyan-500" size={18} />
                    <span className="text-white font-medium">Dockerfile Rules</span>
                    <span className="text-gray-500 text-sm">(25 checks)</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    {[
                      'DF001: Running as root user',
                      'DF002: Using latest tag',
                      'DF003: Hardcoded secrets in ENV',
                      'DF004: Missing HEALTHCHECK',
                      'DF005: Using ADD instead of COPY'
                    ].map((rule) => (
                      <div key={rule} className="flex items-center gap-2 text-gray-400">
                        <CheckCircle size={12} className="text-dws-green" />
                        {rule}
                      </div>
                    ))}
                  </div>
                </div>

                {/* CloudFormation Rules */}
                <div className="border border-dws-border rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Cloud className="text-orange-500" size={18} />
                    <span className="text-white font-medium">CloudFormation Rules</span>
                    <span className="text-gray-500 text-sm">(35 checks)</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    {[
                      'CFN001: IAM policy with * resource',
                      'CFN002: Unencrypted EBS volume',
                      'CFN003: Public subnet with auto-assign IP'
                    ].map((rule) => (
                      <div key={rule} className="flex items-center gap-2 text-gray-400">
                        <CheckCircle size={12} className="text-dws-green" />
                        {rule}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Ansible Rules */}
                <div className="border border-dws-border rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Terminal className="text-red-500" size={18} />
                    <span className="text-white font-medium">Ansible Rules</span>
                    <span className="text-gray-500 text-sm">(20 checks)</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    {[
                      'ANS001: Hardcoded password in playbook',
                      'ANS002: Using shell instead of command',
                      'ANS003: SSH without host key checking'
                    ].map((rule) => (
                      <div key={rule} className="flex items-center gap-2 text-gray-400">
                        <CheckCircle size={12} className="text-dws-green" />
                        {rule}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* External Tool Integration */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                <Settings className="text-joe-blue" size={20} />
                External Tool Integration
              </h3>
              <p className="text-gray-400 text-sm mb-4">
                J.O.E. can integrate with these external IaC security tools when installed:
              </p>
              <div className="grid grid-cols-4 gap-4">
                {[
                  { name: 'tfsec', desc: 'Terraform security scanner', url: 'https://tfsec.dev' },
                  { name: 'checkov', desc: 'Multi-platform IaC scanner', url: 'https://checkov.io' },
                  { name: 'kubesec', desc: 'Kubernetes security risk analysis', url: 'https://kubesec.io' },
                  { name: 'hadolint', desc: 'Dockerfile best practices', url: 'https://hadolint.github.io' }
                ].map((tool) => (
                  <div key={tool.name} className="p-3 bg-dws-dark rounded-lg border border-dws-border">
                    <p className="text-white font-medium mb-1">{tool.name}</p>
                    <p className="text-gray-500 text-xs mb-2">{tool.desc}</p>
                    <a
                      href={tool.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-joe-blue text-xs hover:underline flex items-center gap-1"
                    >
                      <ExternalLink size={10} />
                      Documentation
                    </a>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
