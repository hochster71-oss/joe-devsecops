/**
 * J.O.E. API Security Scanner View
 *
 * OpenAPI/Swagger Analysis | OWASP API Top 10 | Authentication Testing
 * Comprehensive API security assessment dashboard
 */

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Globe,
  Shield,
  AlertTriangle,
  FileSearch,
  RefreshCw,
  ChevronRight,
  CheckCircle,
  XCircle,
  Clock,
  Lock,
  Unlock,
  AlertCircle,
  Search,
  Filter,
  Zap,
  Server,
  Database,
  Eye,
  Copy,
  ExternalLink,
  Play,
  Upload,
  Activity,
  Users,
  Settings,
  BarChart3,
  ShieldAlert,
  ShieldCheck
} from 'lucide-react';
import { useAPISecurityStore } from '../store/apiSecurityStore';

// ========================================
// INTERFACES
// ========================================

type OWASPCategory =
  | 'API1:2023' | 'API2:2023' | 'API3:2023' | 'API4:2023' | 'API5:2023'
  | 'API6:2023' | 'API7:2023' | 'API8:2023' | 'API9:2023' | 'API10:2023';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface APIFinding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: OWASPCategory;
  endpoint?: string;
  method?: string;
  parameter?: string;
  location: string;
  remediation: string;
  owaspApiReference: string;
  cwe?: string;
  references?: string[];
}

interface APIEndpoint {
  path: string;
  method: string;
  summary?: string;
  security?: string[];
  parameters?: { name: string; in: string; required: boolean }[];
  responses?: Record<string, { description: string }>;
}

interface APIScanResult {
  scanId?: string;
  timestamp?: string;
  scanTime?: string;
  duration?: number;
  specFile: string;
  apiName?: string;
  apiTitle?: string;
  apiVersion: string;
  openApiVersion?: string;
  baseUrl?: string;
  endpointsAnalyzed?: number;
  endpoints?: APIEndpoint[];
  findings: APIFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  securityScore?: number;
  securitySchemes?: string[];
  coverage?: {
    authenticated: number;
    unauthenticated: number;
    total: number;
  };
  owaspCoverage?: Record<OWASPCategory, { findings: number; status: 'pass' | 'warn' | 'fail' }>;
}

// OWASP API Top 10 2023 definitions
const OWASP_API_TOP_10: Record<OWASPCategory, { name: string; description: string }> = {
  'API1:2023': {
    name: 'Broken Object Level Authorization',
    description: 'APIs expose endpoints that handle object identifiers, creating a wide attack surface.'
  },
  'API2:2023': {
    name: 'Broken Authentication',
    description: 'Authentication mechanisms are complex, making them susceptible to flaws.'
  },
  'API3:2023': {
    name: 'Broken Object Property Level Authorization',
    description: 'APIs expose object properties that should not be accessible or modifiable.'
  },
  'API4:2023': {
    name: 'Unrestricted Resource Consumption',
    description: 'APIs do not restrict the size or number of resources that can be requested.'
  },
  'API5:2023': {
    name: 'Broken Function Level Authorization',
    description: 'Complex access control policies lead to authorization flaws.'
  },
  'API6:2023': {
    name: 'Unrestricted Access to Sensitive Business Flows',
    description: 'APIs expose business flows without considering harm from excessive use.'
  },
  'API7:2023': {
    name: 'Server Side Request Forgery',
    description: 'APIs fetch remote resources without validating user-supplied URIs.'
  },
  'API8:2023': {
    name: 'Security Misconfiguration',
    description: 'Security hardening is often missing or improperly configured.'
  },
  'API9:2023': {
    name: 'Improper Inventory Management',
    description: 'APIs may expose deprecated endpoints or undocumented endpoints.'
  },
  'API10:2023': {
    name: 'Unsafe Consumption of APIs',
    description: 'Third-party APIs consumed without proper validation.'
  }
};

// ========================================
// API SECURITY VIEW COMPONENT
// ========================================

export default function APISecurityView() {
  const {
    scanResults,
    currentResult,
    isScanning,
    error,
    severityFilter,
    categoryFilter,
    searchQuery,
    setSeverityFilter,
    setCategoryFilter: _setCategoryFilter,
    setSearchQuery,
    getFilteredFindings,
    clearResults,
    getSecurityScore
  } = useAPISecurityStore();

  // Alias for UI compatibility - cast to local interface for extended properties
  const currentScan = currentResult as APIScanResult | null;
  const selectedSeverities = severityFilter;
  const _selectedCategories = categoryFilter;

  const [specPath, setSpecPath] = useState<string>('');
  const [selectedFinding, setSelectedFinding] = useState<APIFinding | null>(null);
  const [activeTab, setActiveTab] = useState<'scan' | 'findings' | 'endpoints' | 'owasp'>('scan');
  const [_selectedEndpoint, _setSelectedEndpoint] = useState<APIEndpoint | null>(null);

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

  const getMethodColor = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET': return 'text-dws-green bg-dws-green/10';
      case 'POST': return 'text-joe-blue bg-joe-blue/10';
      case 'PUT': return 'text-alert-warning bg-alert-warning/10';
      case 'PATCH': return 'text-purple-500 bg-purple-500/10';
      case 'DELETE': return 'text-alert-critical bg-alert-critical/10';
      default: return 'text-gray-400 bg-gray-400/10';
    }
  };

  const getOWASPStatusColor = (status: 'pass' | 'warn' | 'fail') => {
    switch (status) {
      case 'pass': return 'text-dws-green bg-dws-green/10 border-dws-green/30';
      case 'warn': return 'text-alert-warning bg-alert-warning/10 border-alert-warning/30';
      case 'fail': return 'text-alert-critical bg-alert-critical/10 border-alert-critical/30';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) {return 'text-dws-green';}
    if (score >= 60) {return 'text-alert-warning';}
    if (score >= 40) {return 'text-orange-500';}
    return 'text-alert-critical';
  };

  // ========================================
  // HANDLERS
  // ========================================

  const handleSelectSpec = async () => {
    try {
      const path = await window.electronAPI?.apiSecurity?.selectSpecFile();
      if (path) {
        setSpecPath(path);
      }
    } catch (err) {
      console.error('Failed to select spec file:', err);
    }
  };

  const handleScan = async () => {
    if (!specPath) {return;}

    try {
      await window.electronAPI?.apiSecurity?.scanSpec(specPath);
      setActiveTab('findings');
    } catch (err) {
      console.error('API security scan failed:', err);
    }
  };

  const handleCopyRemediation = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  // Get filtered findings from store
  const filteredFindings = getFilteredFindings();
  const securityScore = getSecurityScore();

  // Current scan summary
  const currentSummary = currentScan?.summary || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-joe-blue/20 to-green-500/20 border border-joe-blue/30">
            <Globe className="text-joe-blue" size={28} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-white">
              API Security Scanner
            </h1>
            <p className="text-gray-400 mt-1">OpenAPI/Swagger Analysis | OWASP API Top 10 2023</p>
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
              ? 'bg-joe-blue/10 text-joe-blue border-b-2 border-joe-blue'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <FileSearch size={18} />
          Scan
        </button>
        <button
          onClick={() => setActiveTab('findings')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'findings'
              ? 'bg-joe-blue/10 text-joe-blue border-b-2 border-joe-blue'
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
          onClick={() => setActiveTab('endpoints')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'endpoints'
              ? 'bg-joe-blue/10 text-joe-blue border-b-2 border-joe-blue'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Server size={18} />
          Endpoints
          {(currentScan?.endpointsAnalyzed ?? 0) > 0 && (
            <span className="ml-1 px-1.5 py-0.5 text-xs bg-joe-blue/20 text-joe-blue rounded">
              {currentScan?.endpointsAnalyzed}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab('owasp')}
          className={`px-4 py-2 rounded-t-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'owasp'
              ? 'bg-joe-blue/10 text-joe-blue border-b-2 border-joe-blue'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Shield size={18} />
          OWASP Top 10
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
                <Zap className="text-joe-blue" size={20} />
                Analyze OpenAPI/Swagger Specification
              </h2>

              <div className="flex gap-4">
                <div className="flex-1">
                  <label className="text-sm text-gray-400 mb-2 block">API Specification File (YAML/JSON)</label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={specPath}
                      onChange={(e) => setSpecPath(e.target.value)}
                      placeholder="Select OpenAPI/Swagger specification file..."
                      className="input-field flex-1"
                    />
                    <button
                      onClick={handleSelectSpec}
                      className="btn-secondary flex items-center gap-2"
                    >
                      <Upload size={16} />
                      Browse
                    </button>
                  </div>
                </div>
                <div className="flex items-end">
                  <button
                    onClick={handleScan}
                    disabled={isScanning || !specPath}
                    className="btn-primary flex items-center gap-2"
                  >
                    {isScanning ? (
                      <RefreshCw size={16} className="animate-spin" />
                    ) : (
                      <Play size={16} />
                    )}
                    {isScanning ? 'Analyzing...' : 'Analyze API'}
                  </button>
                </div>
              </div>

              {error && (
                <div className="mt-4 p-3 bg-alert-critical/10 border border-alert-critical/30 rounded-lg text-alert-critical text-sm">
                  {error}
                </div>
              )}
            </div>

            {/* OWASP API Top 10 2023 Overview */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                <ShieldAlert className="text-joe-blue" size={20} />
                OWASP API Security Top 10 - 2023
              </h3>
              <div className="grid grid-cols-2 gap-3">
                {Object.entries(OWASP_API_TOP_10).map(([key, value]) => (
                  <motion.div
                    key={key}
                    whileHover={{ scale: 1.01 }}
                    className="p-3 bg-dws-dark rounded-lg border border-dws-border hover:border-joe-blue/30 transition-colors"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-joe-blue font-mono text-xs">{key}</span>
                      <span className="text-white font-medium text-sm">{value.name}</span>
                    </div>
                    <p className="text-gray-500 text-xs">{value.description}</p>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* What Gets Checked */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4">Security Checks Performed</h3>
              <div className="grid grid-cols-4 gap-3">
                {[
                  { icon: Lock, name: 'Authentication', desc: 'OAuth, API keys, JWT validation' },
                  { icon: Users, name: 'Authorization', desc: 'BOLA, BFLA, permission checks' },
                  { icon: Activity, name: 'Rate Limiting', desc: 'Resource consumption controls' },
                  { icon: Shield, name: 'Input Validation', desc: 'Schema validation, injection risks' },
                  { icon: Server, name: 'Transport Security', desc: 'HTTPS, TLS configuration' },
                  { icon: Database, name: 'Data Exposure', desc: 'Sensitive data in responses' },
                  { icon: Settings, name: 'Configuration', desc: 'Headers, CORS, versioning' },
                  { icon: Eye, name: 'Documentation', desc: 'Completeness, accuracy' }
                ].map((cat) => (
                  <div key={cat.name} className="flex items-start gap-2 p-3 bg-dws-dark/50 rounded-lg">
                    <cat.icon className="text-joe-blue mt-0.5" size={16} />
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

        {/* Findings Tab */}
        {activeTab === 'findings' && (
          <motion.div
            key="findings"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Summary Cards */}
            {currentScan && (
              <div className="grid grid-cols-7 gap-4">
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="glass-card p-4"
                >
                  <div className="text-center">
                    <BarChart3 className={getScoreColor(securityScore) + ' mx-auto mb-2'} size={24} />
                    <p className={`text-2xl font-bold ${getScoreColor(securityScore)}`}>{securityScore}</p>
                    <p className="text-gray-400 text-sm">Security Score</p>
                  </div>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.1 }}
                  className="glass-card p-4"
                >
                  <div className="text-center">
                    <Server className="text-joe-blue mx-auto mb-2" size={24} />
                    <p className="text-2xl font-bold text-white">{currentScan.endpointsAnalyzed}</p>
                    <p className="text-gray-400 text-sm">Endpoints</p>
                  </div>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.2 }}
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
                  transition={{ delay: 0.3 }}
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
                  transition={{ delay: 0.4 }}
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
                  transition={{ delay: 0.5 }}
                  className="glass-card p-4"
                >
                  <div className="text-center">
                    <CheckCircle className="text-joe-blue mx-auto mb-2" size={24} />
                    <p className="text-2xl font-bold text-joe-blue">{currentSummary.low}</p>
                    <p className="text-gray-400 text-sm">Low</p>
                  </div>
                </motion.div>

                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.6 }}
                  className="glass-card p-4"
                >
                  <div className="text-center">
                    <Clock className="text-gray-400 mx-auto mb-2" size={24} />
                    <p className="text-2xl font-bold text-white">{((currentScan?.duration ?? 0) / 1000).toFixed(1)}s</p>
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
                      onClick={() => {
                        // BUG-007 FIX: Properly compute new array for toggle
                        const newFilters = selectedSeverities.includes(sev)
                          ? selectedSeverities.filter(s => s !== sev)
                          : [...selectedSeverities, sev];
                        setSeverityFilter(newFilters);
                      }}
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
                      <ShieldCheck className="text-dws-green mx-auto mb-3" size={48} />
                      <p className="text-white font-medium">No security issues found!</p>
                      <p className="text-gray-400 text-sm mt-1">Your API passed all security checks</p>
                    </>
                  ) : (
                    <>
                      <FileSearch className="text-gray-500 mx-auto mb-3" size={48} />
                      <p className="text-gray-400">No scan results yet</p>
                      <p className="text-gray-500 text-sm mt-1">Upload an OpenAPI spec to analyze</p>
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
                      className={`p-4 rounded-lg border cursor-pointer transition-colors hover:border-joe-blue/50 ${getSeverityColor(finding.severity)}`}
                      onClick={() => setSelectedFinding(finding)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityBadgeColor(finding.severity)}`}>
                              {finding.severity.toUpperCase()}
                            </span>
                            <span className="text-xs text-joe-blue font-mono">{finding.category}</span>
                          </div>
                          <p className="text-white font-medium mb-1">{finding.title}</p>
                          <p className="text-gray-400 text-sm line-clamp-2">{finding.description}</p>
                          {finding.endpoint && (
                            <div className="flex items-center gap-2 mt-2 text-xs">
                              {finding.method && (
                                <span className={`px-1.5 py-0.5 rounded font-mono ${getMethodColor(finding.method)}`}>
                                  {finding.method}
                                </span>
                              )}
                              <span className="text-gray-500 font-mono">{finding.endpoint}</span>
                            </div>
                          )}
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
                        <span className="text-joe-blue font-mono text-sm">{selectedFinding.category}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => setSelectedFinding(null)}
                        className="text-gray-400 hover:text-white"
                        title="Close"
                      >
                        <XCircle size={24} />
                      </button>
                    </div>

                    <h3 className="text-xl font-bold text-white mb-3">{selectedFinding.title}</h3>
                    <p className="text-gray-300 mb-4">{selectedFinding.description}</p>

                    <div className="space-y-4">
                      {selectedFinding.endpoint && (
                        <div className="p-3 bg-dws-dark rounded-lg">
                          <p className="text-gray-400 text-sm mb-1">Affected Endpoint</p>
                          <div className="flex items-center gap-2">
                            {selectedFinding.method && (
                              <span className={`px-2 py-0.5 rounded font-mono text-sm ${getMethodColor(selectedFinding.method)}`}>
                                {selectedFinding.method}
                              </span>
                            )}
                            <span className="text-white font-mono">{selectedFinding.endpoint}</span>
                          </div>
                          {selectedFinding.parameter && (
                            <p className="text-gray-400 text-sm mt-2">
                              Parameter: <span className="text-white">{selectedFinding.parameter}</span>
                            </p>
                          )}
                        </div>
                      )}

                      <div className="p-3 bg-dws-dark rounded-lg">
                        <p className="text-gray-400 text-sm mb-1">OWASP Category</p>
                        <p className="text-white">{OWASP_API_TOP_10[selectedFinding.category]?.name}</p>
                        <p className="text-gray-500 text-sm mt-1">{OWASP_API_TOP_10[selectedFinding.category]?.description}</p>
                      </div>

                      {selectedFinding.location && (
                        <div className="p-3 bg-dws-dark rounded-lg">
                          <p className="text-gray-400 text-sm mb-1">Location</p>
                          <pre className="text-white text-sm font-mono overflow-x-auto">{selectedFinding.location}</pre>
                        </div>
                      )}

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

        {/* Endpoints Tab */}
        {activeTab === 'endpoints' && (
          <motion.div
            key="endpoints"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* API Info */}
            {currentScan && (
              <div className="glass-card p-6">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h2 className="text-xl font-bold text-white">{currentScan.apiTitle}</h2>
                    <p className="text-gray-400 text-sm">Version {currentScan.apiVersion}</p>
                  </div>
                  {currentScan.baseUrl && (
                    <div className="text-right">
                      <p className="text-gray-400 text-sm">Base URL</p>
                      <p className="text-joe-blue font-mono">{currentScan.baseUrl}</p>
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-4 gap-4">
                  <div className="p-3 bg-dws-dark rounded-lg text-center">
                    <p className="text-2xl font-bold text-white">{currentScan.endpointsAnalyzed}</p>
                    <p className="text-gray-400 text-sm">Total Endpoints</p>
                  </div>
                  <div className="p-3 bg-dws-dark rounded-lg text-center">
                    <p className="text-2xl font-bold text-dws-green">
                      {(currentScan?.endpoints ?? []).filter((e: APIEndpoint) => e.method === 'GET').length}
                    </p>
                    <p className="text-gray-400 text-sm">GET</p>
                  </div>
                  <div className="p-3 bg-dws-dark rounded-lg text-center">
                    <p className="text-2xl font-bold text-joe-blue">
                      {(currentScan?.endpoints ?? []).filter((e: APIEndpoint) => e.method === 'POST').length}
                    </p>
                    <p className="text-gray-400 text-sm">POST</p>
                  </div>
                  <div className="p-3 bg-dws-dark rounded-lg text-center">
                    <p className="text-2xl font-bold text-alert-critical">
                      {(currentScan?.endpoints ?? []).filter((e: APIEndpoint) => e.method === 'DELETE').length}
                    </p>
                    <p className="text-gray-400 text-sm">DELETE</p>
                  </div>
                </div>
              </div>
            )}

            {/* Endpoints List */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                <Server size={18} className="text-joe-blue" />
                API Endpoints ({currentScan?.endpoints?.length ?? 0})
              </h3>

              {!currentScan || (currentScan.endpoints?.length ?? 0) === 0 ? (
                <div className="text-center py-12">
                  <Server className="text-gray-500 mx-auto mb-3" size={48} />
                  <p className="text-gray-400">No endpoints to display</p>
                  <p className="text-gray-500 text-sm mt-1">Run a scan to see API endpoints</p>
                </div>
              ) : (
                <div className="space-y-2 max-h-[500px] overflow-y-auto">
                  {(currentScan.endpoints ?? []).map((endpoint: APIEndpoint, index: number) => (
                    <motion.div
                      key={`${endpoint.method}-${endpoint.path}`}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.02 }}
                      className="p-3 bg-dws-dark rounded-lg border border-dws-border hover:border-joe-blue/30 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <span className={`px-2 py-1 rounded font-mono text-xs font-medium min-w-[60px] text-center ${getMethodColor(endpoint.method)}`}>
                          {endpoint.method}
                        </span>
                        <span className="text-white font-mono text-sm flex-1">{endpoint.path}</span>
                        {endpoint.security && endpoint.security.length > 0 ? (
                          <Lock size={14} className="text-dws-green" />
                        ) : (
                          <Unlock size={14} className="text-alert-warning" />
                        )}
                      </div>
                      {endpoint.summary && (
                        <p className="text-gray-500 text-xs mt-1 ml-[76px]">{endpoint.summary}</p>
                      )}
                      {endpoint.parameters && endpoint.parameters.length > 0 && (
                        <div className="flex items-center gap-2 mt-2 ml-[76px]">
                          {endpoint.parameters.slice(0, 3).map((param: { name: string; in: string; required: boolean }) => (
                            <span
                              key={param.name}
                              className={`px-1.5 py-0.5 text-xs rounded ${
                                param.required ? 'bg-alert-warning/10 text-alert-warning' : 'bg-gray-500/10 text-gray-400'
                              }`}
                            >
                              {param.name}
                            </span>
                          ))}
                          {endpoint.parameters.length > 3 && (
                            <span className="text-gray-500 text-xs">+{endpoint.parameters.length - 3} more</span>
                          )}
                        </div>
                      )}
                    </motion.div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* OWASP Tab */}
        {activeTab === 'owasp' && (
          <motion.div
            key="owasp"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* OWASP Coverage */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                <Shield size={20} className="text-joe-blue" />
                OWASP API Top 10 2023 Coverage
              </h3>

              {currentScan?.owaspCoverage ? (
                <div className="space-y-3">
                  {Object.entries(OWASP_API_TOP_10).map(([key, value]) => {
                    const coverage = currentScan?.owaspCoverage?.[key as OWASPCategory];
                    return (
                      <div
                        key={key}
                        className={`p-4 rounded-lg border ${getOWASPStatusColor(coverage?.status || 'pass')}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            {coverage?.status === 'pass' ? (
                              <CheckCircle className="text-dws-green" size={20} />
                            ) : coverage?.status === 'warn' ? (
                              <AlertCircle className="text-alert-warning" size={20} />
                            ) : (
                              <XCircle className="text-alert-critical" size={20} />
                            )}
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-joe-blue font-mono text-sm">{key}</span>
                                <span className="text-white font-medium">{value.name}</span>
                              </div>
                              <p className="text-gray-400 text-sm">{value.description}</p>
                            </div>
                          </div>
                          <div className="text-right">
                            <span className={`text-2xl font-bold ${
                              coverage?.findings === 0 ? 'text-dws-green' : 'text-alert-critical'
                            }`}>
                              {coverage?.findings || 0}
                            </span>
                            <p className="text-gray-500 text-xs">findings</p>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="space-y-3">
                  {Object.entries(OWASP_API_TOP_10).map(([key, value]) => (
                    <div
                      key={key}
                      className="p-4 rounded-lg border border-dws-border bg-dws-dark"
                    >
                      <div className="flex items-center gap-3">
                        <Shield className="text-gray-500" size={20} />
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-joe-blue font-mono text-sm">{key}</span>
                            <span className="text-white font-medium">{value.name}</span>
                          </div>
                          <p className="text-gray-400 text-sm">{value.description}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Resources */}
            <div className="glass-card p-6">
              <h3 className="text-white font-medium mb-4">Learn More</h3>
              <div className="grid grid-cols-2 gap-4">
                <a
                  href="https://owasp.org/API-Security/editions/2023/en/0x00-header/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-4 bg-dws-dark rounded-lg border border-dws-border hover:border-joe-blue/30 transition-colors flex items-center gap-3"
                >
                  <ExternalLink className="text-joe-blue" size={20} />
                  <div>
                    <p className="text-white font-medium">OWASP API Security Project</p>
                    <p className="text-gray-500 text-sm">Official documentation and guidelines</p>
                  </div>
                </a>
                <a
                  href="https://github.com/OWASP/API-Security"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-4 bg-dws-dark rounded-lg border border-dws-border hover:border-joe-blue/30 transition-colors flex items-center gap-3"
                >
                  <ExternalLink className="text-joe-blue" size={20} />
                  <div>
                    <p className="text-white font-medium">GitHub Repository</p>
                    <p className="text-gray-500 text-sm">Source and community contributions</p>
                  </div>
                </a>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
