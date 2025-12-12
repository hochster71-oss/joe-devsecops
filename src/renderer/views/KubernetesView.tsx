/**
 * J.O.E. Kubernetes Security View
 * DoD-Hardened Kubernetes Cluster Security Dashboard
 *
 * Security Standards:
 * - CIS Kubernetes Benchmark v1.8
 * - NSA/CISA Kubernetes Hardening Guide v1.2
 * - NIST SP 800-190 (Container Security)
 * - Pod Security Standards (PSS)
 */

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Container,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Server,
  Network,
  Lock,
  Key,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Loader2,
  Unplug,
  Plug,
  ChevronDown,
  ChevronRight,
  Box,
  Users,
  Eye,
  FileWarning,
  Brain,
  Sparkles,
  Target,
  Route,
  Zap,
  X
} from 'lucide-react';
import { useKubernetesStore } from '../store/kubernetesStore';
import { ollamaService } from '../../services/ollamaService';

export default function KubernetesView() {
  const {
    connected,
    connecting,
    currentCluster,
    availableContexts,
    connectionError,
    isScanning,
    scanProgress,
    lastScanTime,
    scanResults,
    cisScore,
    pssCompliance,
    rbacRiskScore,
    networkCoverage,
    imageVulnCount,
    criticalFindings,
    loadContexts,
    connect,
    disconnect,
    runFullAudit,
    clearResults
  } = useKubernetesStore();

  const [selectedContext, setSelectedContext] = useState<string>('');
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['cis', 'pss']));
  const [showConnectionPanel, setShowConnectionPanel] = useState(!connected);

  // AI Deep Dive State
  const [aiAnalysisOpen, setAiAnalysisOpen] = useState(false);
  const [aiAnalysisLoading, setAiAnalysisLoading] = useState(false);
  const [aiAnalysisContent, setAiAnalysisContent] = useState<string>('');
  const [aiAnalysisTitle, setAiAnalysisTitle] = useState<string>('');
  const [aiAnalysisType, setAiAnalysisType] = useState<string>('');

  // Load available contexts on mount
  useEffect(() => {
    loadContexts();
  }, [loadContexts]);

  // Auto-select first context
  useEffect(() => {
    if (availableContexts.length > 0 && !selectedContext) {
      setSelectedContext(availableContexts[0]);
    }
  }, [availableContexts, selectedContext]);

  const handleConnect = async () => {
    if (!selectedContext) return;
    const success = await connect({
      name: selectedContext,
      context: selectedContext
    });
    if (success) {
      setShowConnectionPanel(false);
    }
  };

  const handleDisconnect = () => {
    disconnect();
    setShowConnectionPanel(true);
  };

  const handleRunAudit = async () => {
    try {
      await runFullAudit();
    } catch (error) {
      console.error('Audit failed:', error);
    }
  };

  const toggleSection = (section: string) => {
    const newSections = new Set(expandedSections);
    if (newSections.has(section)) {
      newSections.delete(section);
    } else {
      newSections.add(section);
    }
    setExpandedSections(newSections);
  };

  // ========================================
  // AI DEEP DIVE FUNCTIONS
  // ========================================

  /**
   * Deep dive analysis of individual K8s finding
   * Maps to MITRE ATT&CK for Containers
   */
  const handleAnalyzeFinding = async (finding: {
    id: string;
    type: string;
    title: string;
    severity: string;
    description: string;
    remediation: string;
  }) => {
    setAiAnalysisTitle(`AI Analysis: ${finding.title}`);
    setAiAnalysisType(finding.type);
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const analysis = await ollamaService.analyzeK8sFinding({
        id: finding.id,
        type: finding.type,
        title: finding.title,
        severity: finding.severity,
        description: finding.description,
        remediation: finding.remediation
      });
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error analyzing finding: ${error instanceof Error ? error.message : 'Unknown error'}\n\nPlease ensure Ollama is running on localhost:11434.`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  /**
   * AI-driven RBAC attack path analysis
   * Reference: NSA/CISA Guide Section 4
   */
  const handleAnalyzeRBAC = async () => {
    if (!scanResults) return;

    setAiAnalysisTitle('AI RBAC Security Analysis');
    setAiAnalysisType('rbac');
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const analysis = await ollamaService.analyzeRBAC({
        overprivileged: scanResults.rbacAnalysis.overprivilegedAccounts.map(a => ({
          subject: a.subject,
          permissions: a.permissions,
          risk: a.risk
        })),
        clusterAdminCount: scanResults.rbacAnalysis.clusterAdminBindings,
        wildcardPermissions: scanResults.rbacAnalysis.wildcardPermissions.length
      });
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error analyzing RBAC: ${error instanceof Error ? error.message : 'Unknown error'}\n\nPlease ensure Ollama is running.`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  /**
   * AI-driven Pod Security Standards analysis
   * Reference: NIST SP 800-190
   */
  const handleAnalyzePodSecurity = async () => {
    if (!scanResults) return;

    setAiAnalysisTitle('AI Pod Security Analysis');
    setAiAnalysisType('pss');
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const analysis = await ollamaService.analyzePodSecurity(
        scanResults.podSecurity.violations.map(v => ({
          namespace: v.namespace,
          pod: v.pod,
          violations: v.violations,
          severity: v.severity
        }))
      );
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error analyzing pod security: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  /**
   * AI-driven container vulnerability analysis
   * Reference: NIST SP 800-190 Section 4.3
   */
  const handleAnalyzeImages = async () => {
    if (!scanResults) return;

    setAiAnalysisTitle('AI Container Vulnerability Analysis');
    setAiAnalysisType('image');
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const analysis = await ollamaService.analyzeContainerVulnerabilities(
        scanResults.containerImages.map(img => ({
          image: img.image,
          critical: img.vulnerabilities.critical,
          high: img.vulnerabilities.high,
          findings: img.findings?.slice(0, 5)
        }))
      );
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error analyzing images: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  /**
   * AI-driven Network Policy gap analysis
   * Reference: NSA/CISA Guide Section 5
   */
  const handleAnalyzeNetworkPolicies = async () => {
    if (!scanResults) return;

    setAiAnalysisTitle('AI Network Security Analysis');
    setAiAnalysisType('network');
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const analysis = await ollamaService.analyzeNetworkPolicies({
        coverage: scanResults.networkPolicies.coverage,
        unprotectedNamespaces: scanResults.networkPolicies.namespacesWithoutPolicies,
        defaultDenyCount: scanResults.networkPolicies.defaultDenyIngress
      });
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error analyzing network policies: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  /**
   * AI-driven attack path analysis using MITRE ATT&CK
   */
  const handleAnalyzeAttackPaths = async () => {
    if (!scanResults) return;

    setAiAnalysisTitle('AI Attack Path Analysis (MITRE ATT&CK)');
    setAiAnalysisType('attack');
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const analysis = await ollamaService.analyzeAttackPaths({
        cis: scanResults.cisBenchmark.findings
          .filter(f => f.status === 'FAIL')
          .map(f => ({ id: f.id, title: f.title, severity: f.severity })),
        rbac: scanResults.rbacAnalysis.overprivilegedAccounts.map(a => ({
          subject: a.subject,
          risk: a.risk
        })),
        pss: scanResults.podSecurity.violations.map(v => ({
          pod: `${v.namespace}/${v.pod}`,
          violations: v.violations
        })),
        network: { coverage: scanResults.networkPolicies.coverage }
      });
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error analyzing attack paths: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  /**
   * Generate comprehensive AI security report
   */
  const handleGenerateSecurityReport = async () => {
    if (!scanResults) return;

    setAiAnalysisTitle('AI Executive Security Assessment');
    setAiAnalysisType('report');
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const analysis = await ollamaService.generateClusterSecurityReport({
        complianceScore: scanResults.complianceScore,
        cisPassRate: cisScore,
        criticalFindings: criticalFindings.filter(f => f.severity === 'critical').length,
        highFindings: criticalFindings.filter(f => f.severity === 'high').length,
        privilegedPods: scanResults.podSecurity.privilegedPods,
        networkCoverage: scanResults.networkPolicies.coverage
      });
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error generating report: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-alert-critical';
      case 'high': return 'text-alert-high';
      case 'medium': return 'text-alert-warning';
      case 'low': return 'text-alert-low';
      default: return 'text-gray-400';
    }
  };

  const getSeverityBg = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-alert-critical/20';
      case 'high': return 'bg-alert-high/20';
      case 'medium': return 'bg-alert-warning/20';
      case 'low': return 'bg-alert-low/20';
      default: return 'bg-gray-500/20';
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-dws-green';
    if (score >= 60) return 'text-alert-warning';
    if (score >= 40) return 'text-alert-high';
    return 'text-alert-critical';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-2xl font-bold text-white flex items-center gap-3">
            <Container className="text-joe-blue" size={28} />
            Kubernetes Security
          </h1>
          <p className="text-gray-400 mt-1">
            CIS Benchmark v1.8 | NSA/CISA Hardening Guide | NIST SP 800-190
          </p>
        </div>
        <div className="flex items-center gap-3">
          {connected && (
            <>
              <button
                onClick={handleRunAudit}
                disabled={isScanning}
                className="btn-primary flex items-center gap-2"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="animate-spin" size={16} />
                    Scanning... {scanProgress}%
                  </>
                ) : (
                  <>
                    <RefreshCw size={16} />
                    Run Security Audit
                  </>
                )}
              </button>
              <button
                onClick={handleDisconnect}
                className="btn-secondary flex items-center gap-2"
              >
                <Unplug size={16} />
                Disconnect
              </button>
            </>
          )}
        </div>
      </div>

      {/* Connection Panel */}
      {showConnectionPanel && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-6"
        >
          <div className="flex items-center gap-3 mb-4">
            <Plug className="text-joe-blue" size={24} />
            <h2 className="font-heading font-semibold text-white text-lg">
              Connect to Kubernetes Cluster
            </h2>
          </div>

          {connectionError && (
            <div className="mb-4 p-3 bg-alert-critical/20 rounded-lg flex items-center gap-2 text-alert-critical">
              <XCircle size={18} />
              {connectionError}
            </div>
          )}

          <div className="flex items-end gap-4">
            <div className="flex-1">
              <label className="block text-sm text-gray-400 mb-2">
                Kubernetes Context
              </label>
              <select
                value={selectedContext}
                onChange={(e) => setSelectedContext(e.target.value)}
                className="input-field w-full"
              >
                <option value="">Select a context...</option>
                {availableContexts.map((ctx) => (
                  <option key={ctx} value={ctx}>{ctx}</option>
                ))}
              </select>
              <p className="text-xs text-gray-500 mt-1">
                Contexts loaded from ~/.kube/config
              </p>
            </div>
            <button
              onClick={handleConnect}
              disabled={!selectedContext || connecting}
              className="btn-primary flex items-center gap-2 px-6"
            >
              {connecting ? (
                <>
                  <Loader2 className="animate-spin" size={16} />
                  Connecting...
                </>
              ) : (
                <>
                  <Plug size={16} />
                  Connect
                </>
              )}
            </button>
          </div>
        </motion.div>
      )}

      {/* Cluster Info Banner */}
      {connected && currentCluster && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="glass-card p-4 flex items-center justify-between"
        >
          <div className="flex items-center gap-4">
            <div className="w-3 h-3 bg-dws-green rounded-full animate-pulse" />
            <div>
              <span className="text-white font-medium">{currentCluster.name}</span>
              <span className="text-gray-500 ml-2">({currentCluster.server})</span>
            </div>
            <span className="text-gray-400">|</span>
            <span className="text-gray-400">
              <Server size={14} className="inline mr-1" />
              {currentCluster.nodeCount} nodes
            </span>
            <span className="text-gray-400">|</span>
            <span className="text-gray-400">
              <Box size={14} className="inline mr-1" />
              {currentCluster.podCount} pods
            </span>
            <span className="text-gray-400">|</span>
            <span className="text-gray-400">
              v{currentCluster.version}
            </span>
          </div>
          {lastScanTime && (
            <span className="text-sm text-gray-500">
              Last scan: {new Date(lastScanTime).toLocaleString()}
            </span>
          )}
        </motion.div>
      )}

      {/* Metrics Cards */}
      {connected && scanResults && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* CIS Benchmark Score */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-400 text-sm">CIS Benchmark</span>
              <ShieldCheck className="text-joe-blue" size={20} />
            </div>
            <div className={`text-3xl font-bold ${getScoreColor(cisScore)}`}>
              {cisScore}%
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {scanResults.cisBenchmark.passed}/{scanResults.cisBenchmark.totalChecks} checks passed
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              <span className="text-dws-green">{scanResults.cisBenchmark.passed} Pass</span>
              <span className="text-alert-critical">{scanResults.cisBenchmark.failed} Fail</span>
              <span className="text-alert-warning">{scanResults.cisBenchmark.warnings} Warn</span>
            </div>
          </motion.div>

          {/* Pod Security */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="glass-card p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-400 text-sm">Pod Security</span>
              <Container className="text-joe-blue" size={20} />
            </div>
            <div className="text-3xl font-bold text-white">
              {scanResults.podSecurity.totalPods}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              Pods analyzed
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              <span className="text-alert-critical">{pssCompliance.privileged} Priv</span>
              <span className="text-alert-warning">{pssCompliance.baseline} Base</span>
              <span className="text-dws-green">{pssCompliance.restricted} Strict</span>
            </div>
          </motion.div>

          {/* RBAC Risk */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="glass-card p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-400 text-sm">RBAC Security</span>
              <Users className="text-joe-blue" size={20} />
            </div>
            <div className={`text-3xl font-bold ${getScoreColor(rbacRiskScore)}`}>
              {rbacRiskScore}%
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {scanResults.rbacAnalysis.totalServiceAccounts} service accounts
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              <span className="text-alert-critical">
                {scanResults.rbacAnalysis.clusterAdminBindings} cluster-admin
              </span>
              <span className="text-alert-high">
                {scanResults.rbacAnalysis.overprivilegedAccounts.length} overprivileged
              </span>
            </div>
          </motion.div>

          {/* Image Vulnerabilities */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="glass-card p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-400 text-sm">Container Images</span>
              <FileWarning className="text-joe-blue" size={20} />
            </div>
            <div className="text-3xl font-bold text-white">
              {scanResults.containerImages.length}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              Images scanned
            </div>
            <div className="flex gap-2 mt-2 text-xs">
              <span className="text-alert-critical">{imageVulnCount.critical} Crit</span>
              <span className="text-alert-high">{imageVulnCount.high} High</span>
              <span className="text-alert-warning">{imageVulnCount.medium} Med</span>
            </div>
          </motion.div>
        </div>
      )}

      {/* Compliance Score */}
      {connected && scanResults && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-heading font-semibold text-white text-lg flex items-center gap-2">
              <Shield className="text-joe-blue" size={20} />
              Overall Compliance Score
            </h2>
            <span className="text-sm text-gray-400">
              Based on CIS, PSS, RBAC, and Network Policies
            </span>
          </div>

          <div className="flex items-center gap-8">
            <div className={`text-6xl font-bold ${getScoreColor(scanResults.complianceScore)}`}>
              {scanResults.complianceScore}%
            </div>
            <div className="flex-1">
              <div className="h-4 bg-wolf-gray rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${scanResults.complianceScore}%` }}
                  transition={{ duration: 1, ease: 'easeOut' }}
                  className={`h-full ${
                    scanResults.complianceScore >= 80 ? 'bg-dws-green' :
                    scanResults.complianceScore >= 60 ? 'bg-alert-warning' :
                    'bg-alert-critical'
                  }`}
                />
              </div>
              <div className="flex justify-between mt-2 text-sm text-gray-400">
                <span>0%</span>
                <span>DoD Target: 80%</span>
                <span>100%</span>
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* AI Intelligence Panel */}
      {connected && scanResults && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-6 border border-joe-blue/30"
        >
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-heading font-semibold text-white text-lg flex items-center gap-2">
              <Brain className="text-joe-blue" size={20} />
              J.O.E. AI Security Intelligence
            </h2>
            <span className="text-xs text-gray-400 flex items-center gap-1">
              <Sparkles size={12} className="text-joe-purple" />
              Powered by Ollama
            </span>
          </div>

          <p className="text-sm text-gray-400 mb-4">
            Deep dive into your Kubernetes security findings with AI-driven analysis based on
            MITRE ATT&CK, CIS Benchmark, NSA/CISA Hardening Guide, and NIST SP 800-190.
          </p>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <button
              onClick={handleGenerateSecurityReport}
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-gradient-to-br from-joe-blue/20 to-joe-purple/20 border border-joe-blue/30 hover:border-joe-blue/60 transition-all group"
            >
              <Shield className="text-joe-blue group-hover:scale-110 transition-transform" size={24} />
              <span className="text-xs text-white text-center">Executive Report</span>
            </button>

            <button
              onClick={handleAnalyzeAttackPaths}
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-wolf-gray/30 border border-wolf-gray/30 hover:border-alert-critical/50 transition-all group"
            >
              <Route className="text-alert-critical group-hover:scale-110 transition-transform" size={24} />
              <span className="text-xs text-white text-center">Attack Paths</span>
            </button>

            <button
              onClick={handleAnalyzeRBAC}
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-wolf-gray/30 border border-wolf-gray/30 hover:border-alert-high/50 transition-all group"
            >
              <Key className="text-alert-high group-hover:scale-110 transition-transform" size={24} />
              <span className="text-xs text-white text-center">RBAC Analysis</span>
            </button>

            <button
              onClick={handleAnalyzePodSecurity}
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-wolf-gray/30 border border-wolf-gray/30 hover:border-alert-warning/50 transition-all group"
            >
              <Container className="text-alert-warning group-hover:scale-110 transition-transform" size={24} />
              <span className="text-xs text-white text-center">Pod Security</span>
            </button>

            <button
              onClick={handleAnalyzeNetworkPolicies}
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-wolf-gray/30 border border-wolf-gray/30 hover:border-joe-blue/50 transition-all group"
            >
              <Network className="text-joe-blue group-hover:scale-110 transition-transform" size={24} />
              <span className="text-xs text-white text-center">Network Analysis</span>
            </button>

            <button
              onClick={handleAnalyzeImages}
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-wolf-gray/30 border border-wolf-gray/30 hover:border-dws-green/50 transition-all group"
            >
              <Target className="text-dws-green group-hover:scale-110 transition-transform" size={24} />
              <span className="text-xs text-white text-center">Image Vulns</span>
            </button>
          </div>
        </motion.div>
      )}

      {/* Critical Findings */}
      {connected && criticalFindings.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-heading font-semibold text-white text-lg flex items-center gap-2">
              <AlertTriangle className="text-alert-critical" size={20} />
              Critical Findings ({criticalFindings.length})
            </h2>
          </div>

          <div className="space-y-3 max-h-96 overflow-y-auto">
            {criticalFindings.map((finding) => (
              <div
                key={finding.id}
                className={`p-4 rounded-lg ${getSeverityBg(finding.severity)} border border-${finding.severity === 'critical' ? 'alert-critical' : 'alert-high'}/30`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xs px-2 py-0.5 rounded uppercase font-medium ${getSeverityColor(finding.severity)} ${getSeverityBg(finding.severity)}`}>
                        {finding.severity}
                      </span>
                      <span className="text-xs text-gray-500 uppercase">{finding.type}</span>
                    </div>
                    <h3 className="text-white font-medium">{finding.title}</h3>
                    <p className="text-sm text-gray-400 mt-1">{finding.description}</p>
                    <p className="text-sm text-joe-blue mt-2">
                      <strong>Remediation:</strong> {finding.remediation}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleAnalyzeFinding(finding)}
                    className="ml-4 flex items-center gap-1 px-3 py-2 rounded-lg bg-joe-blue/20 border border-joe-blue/30 hover:bg-joe-blue/30 hover:border-joe-blue/50 transition-all text-joe-blue text-xs font-medium"
                  >
                    <Brain size={14} />
                    Deep Dive
                  </button>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Detailed Results Sections */}
      {connected && scanResults && (
        <div className="space-y-4">
          {/* CIS Benchmark Details */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="glass-card overflow-hidden"
          >
            <button
              onClick={() => toggleSection('cis')}
              className="w-full p-4 flex items-center justify-between hover:bg-wolf-gray/30 transition-colors"
            >
              <div className="flex items-center gap-3">
                <ShieldCheck className="text-joe-blue" size={20} />
                <span className="font-medium text-white">CIS Kubernetes Benchmark v1.8</span>
                <span className="text-sm text-gray-400">
                  ({scanResults.cisBenchmark.findings.length} checks)
                </span>
              </div>
              {expandedSections.has('cis') ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
            </button>

            {expandedSections.has('cis') && (
              <div className="border-t border-wolf-gray/30 p-4">
                <div className="grid gap-2 max-h-80 overflow-y-auto">
                  {scanResults.cisBenchmark.findings
                    .filter(f => f.status === 'FAIL' || f.status === 'WARN')
                    .map((finding) => (
                      <div
                        key={finding.id}
                        className="flex items-center gap-3 p-2 rounded bg-wolf-gray/20"
                      >
                        {finding.status === 'FAIL' ? (
                          <XCircle className="text-alert-critical flex-shrink-0" size={16} />
                        ) : (
                          <AlertTriangle className="text-alert-warning flex-shrink-0" size={16} />
                        )}
                        <span className="text-sm text-gray-400 w-16">{finding.id}</span>
                        <span className="text-sm text-white flex-1">{finding.title}</span>
                        <span className={`text-xs px-2 py-0.5 rounded ${getSeverityColor(finding.severity)} ${getSeverityBg(finding.severity)}`}>
                          {finding.severity}
                        </span>
                      </div>
                    ))}
                  {scanResults.cisBenchmark.findings.filter(f => f.status === 'FAIL' || f.status === 'WARN').length === 0 && (
                    <div className="text-center text-gray-500 py-4">
                      <CheckCircle className="mx-auto mb-2 text-dws-green" size={24} />
                      All CIS checks passed!
                    </div>
                  )}
                </div>
              </div>
            )}
          </motion.div>

          {/* Pod Security Standards */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="glass-card overflow-hidden"
          >
            <button
              onClick={() => toggleSection('pss')}
              className="w-full p-4 flex items-center justify-between hover:bg-wolf-gray/30 transition-colors"
            >
              <div className="flex items-center gap-3">
                <Container className="text-joe-blue" size={20} />
                <span className="font-medium text-white">Pod Security Standards</span>
                <span className="text-sm text-gray-400">
                  ({scanResults.podSecurity.violations.length} violations)
                </span>
              </div>
              {expandedSections.has('pss') ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
            </button>

            {expandedSections.has('pss') && (
              <div className="border-t border-wolf-gray/30 p-4">
                <div className="grid gap-2 max-h-80 overflow-y-auto">
                  {scanResults.podSecurity.violations.map((violation, idx) => (
                    <div
                      key={`${violation.namespace}-${violation.pod}-${idx}`}
                      className="p-3 rounded bg-wolf-gray/20"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs px-2 py-0.5 rounded uppercase ${getSeverityColor(violation.severity)} ${getSeverityBg(violation.severity)}`}>
                          {violation.severity}
                        </span>
                        <span className="text-sm text-white font-medium">
                          {violation.namespace}/{violation.pod}
                        </span>
                      </div>
                      <ul className="text-sm text-gray-400 list-disc list-inside">
                        {violation.violations.map((v, i) => (
                          <li key={i}>{v}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                  {scanResults.podSecurity.violations.length === 0 && (
                    <div className="text-center text-gray-500 py-4">
                      <CheckCircle className="mx-auto mb-2 text-dws-green" size={24} />
                      All pods meet security standards!
                    </div>
                  )}
                </div>
              </div>
            )}
          </motion.div>

          {/* Network Policies */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="glass-card overflow-hidden"
          >
            <button
              onClick={() => toggleSection('network')}
              className="w-full p-4 flex items-center justify-between hover:bg-wolf-gray/30 transition-colors"
            >
              <div className="flex items-center gap-3">
                <Network className="text-joe-blue" size={20} />
                <span className="font-medium text-white">Network Policies</span>
                <span className="text-sm text-gray-400">
                  ({networkCoverage}% coverage)
                </span>
              </div>
              {expandedSections.has('network') ? <ChevronDown size={20} /> : <ChevronRight size={20} />}
            </button>

            {expandedSections.has('network') && (
              <div className="border-t border-wolf-gray/30 p-4">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">{scanResults.networkPolicies.totalPolicies}</div>
                    <div className="text-xs text-gray-400">Total Policies</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-dws-green">{scanResults.networkPolicies.namespacesWithPolicies}</div>
                    <div className="text-xs text-gray-400">Namespaces Protected</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-alert-warning">{scanResults.networkPolicies.namespacesWithoutPolicies.length}</div>
                    <div className="text-xs text-gray-400">Namespaces Unprotected</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-joe-blue">{scanResults.networkPolicies.defaultDenyIngress}</div>
                    <div className="text-xs text-gray-400">Default Deny Policies</div>
                  </div>
                </div>

                {scanResults.networkPolicies.namespacesWithoutPolicies.length > 0 && (
                  <div className="p-3 rounded bg-alert-warning/10 border border-alert-warning/30">
                    <div className="flex items-center gap-2 text-alert-warning mb-2">
                      <AlertTriangle size={16} />
                      <span className="font-medium">Namespaces without Network Policies:</span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {scanResults.networkPolicies.namespacesWithoutPolicies.map((ns) => (
                        <span key={ns} className="px-2 py-1 bg-wolf-gray rounded text-sm text-white">
                          {ns}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </motion.div>
        </div>
      )}

      {/* Empty State */}
      {connected && !scanResults && !isScanning && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="glass-card p-12 text-center"
        >
          <Shield className="mx-auto mb-4 text-gray-500" size={48} />
          <h3 className="text-xl font-medium text-white mb-2">Ready to Scan</h3>
          <p className="text-gray-400 mb-6">
            Click "Run Security Audit" to perform a comprehensive security analysis
            of your Kubernetes cluster using CIS Benchmark and DoD standards.
          </p>
          <button onClick={handleRunAudit} className="btn-primary">
            <RefreshCw size={16} className="mr-2" />
            Run Security Audit
          </button>
        </motion.div>
      )}

      {/* Not Connected State */}
      {!connected && !showConnectionPanel && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="glass-card p-12 text-center"
        >
          <Unplug className="mx-auto mb-4 text-gray-500" size={48} />
          <h3 className="text-xl font-medium text-white mb-2">Not Connected</h3>
          <p className="text-gray-400 mb-6">
            Connect to a Kubernetes cluster to begin security scanning.
          </p>
          <button onClick={() => setShowConnectionPanel(true)} className="btn-primary">
            <Plug size={16} className="mr-2" />
            Connect to Cluster
          </button>
        </motion.div>
      )}

      {/* AI Analysis Modal */}
      <AnimatePresence>
        {aiAnalysisOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
            onClick={() => setAiAnalysisOpen(false)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-wolf-gray-darker border border-joe-blue/30 rounded-xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl"
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between p-4 border-b border-wolf-gray/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-joe-blue/20">
                    <Brain className="text-joe-blue" size={24} />
                  </div>
                  <div>
                    <h2 className="font-heading font-semibold text-white text-lg">
                      {aiAnalysisTitle}
                    </h2>
                    <p className="text-xs text-gray-400 flex items-center gap-1">
                      <Sparkles size={10} className="text-joe-purple" />
                      J.O.E. AI-Driven Security Intelligence
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setAiAnalysisOpen(false)}
                  className="p-2 rounded-lg hover:bg-wolf-gray/30 transition-colors"
                  title="Close AI Analysis"
                  aria-label="Close AI Analysis"
                >
                  <X className="text-gray-400" size={20} />
                </button>
              </div>

              {/* Modal Content */}
              <div className="flex-1 overflow-y-auto p-6">
                {aiAnalysisLoading ? (
                  <div className="flex flex-col items-center justify-center py-12">
                    <div className="relative">
                      <Loader2 className="animate-spin text-joe-blue" size={48} />
                      <Brain className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-joe-purple" size={20} />
                    </div>
                    <p className="text-gray-400 mt-4">J.O.E. is analyzing...</p>
                    <p className="text-xs text-gray-500 mt-1">
                      Querying Ollama AI with security context
                    </p>
                  </div>
                ) : (
                  <div className="prose prose-invert max-w-none">
                    {/* Reference Banner */}
                    <div className="mb-4 p-3 rounded-lg bg-joe-blue/10 border border-joe-blue/20 text-xs text-gray-400">
                      <strong className="text-joe-blue">Security Standards Referenced:</strong>{' '}
                      {aiAnalysisType === 'rbac' && 'NSA/CISA Kubernetes Hardening Guide v1.2 Section 4'}
                      {aiAnalysisType === 'pss' && 'NIST SP 800-190, Kubernetes Pod Security Standards'}
                      {aiAnalysisType === 'network' && 'NSA/CISA Guide Section 5, Zero Trust Architecture'}
                      {aiAnalysisType === 'image' && 'NIST SP 800-190 Section 4.3, SLSA Framework'}
                      {aiAnalysisType === 'attack' && 'MITRE ATT&CK for Containers Framework'}
                      {aiAnalysisType === 'report' && 'CIS Benchmark v1.8, NIST SP 800-53, DoD DevSecOps Reference'}
                      {aiAnalysisType === 'cis' && 'CIS Kubernetes Benchmark v1.8'}
                    </div>

                    {/* AI Response Content */}
                    <div className="whitespace-pre-wrap text-gray-300 leading-relaxed">
                      {aiAnalysisContent.split('\n').map((line, idx) => {
                        // Format headers
                        if (line.startsWith('## ')) {
                          return (
                            <h2 key={idx} className="text-xl font-bold text-white mt-6 mb-3 flex items-center gap-2">
                              <Zap size={18} className="text-joe-blue" />
                              {line.replace('## ', '')}
                            </h2>
                          );
                        }
                        if (line.startsWith('### ')) {
                          return (
                            <h3 key={idx} className="text-lg font-semibold text-white mt-4 mb-2">
                              {line.replace('### ', '')}
                            </h3>
                          );
                        }
                        if (line.startsWith('**') && line.endsWith('**')) {
                          return (
                            <p key={idx} className="font-bold text-joe-blue mt-4 mb-2">
                              {line.replace(/\*\*/g, '')}
                            </p>
                          );
                        }
                        if (line.startsWith('- ') || line.startsWith('* ')) {
                          return (
                            <div key={idx} className="flex items-start gap-2 ml-4 my-1">
                              <span className="text-joe-blue mt-1.5">•</span>
                              <span>{line.replace(/^[-*] /, '')}</span>
                            </div>
                          );
                        }
                        if (line.match(/^\d+\. /)) {
                          return (
                            <div key={idx} className="flex items-start gap-2 ml-4 my-1">
                              <span className="text-joe-purple font-bold">{line.match(/^\d+/)?.[0]}.</span>
                              <span>{line.replace(/^\d+\. /, '')}</span>
                            </div>
                          );
                        }
                        if (line.startsWith('```')) {
                          return (
                            <div key={idx} className="bg-black/30 rounded p-3 font-mono text-sm my-2 border border-wolf-gray/30">
                              {line.replace(/```\w*/, '')}
                            </div>
                          );
                        }
                        if (line.includes('`') && !line.startsWith('```')) {
                          const parts = line.split(/(`[^`]+`)/g);
                          return (
                            <p key={idx} className="my-1">
                              {parts.map((part, i) =>
                                part.startsWith('`') ? (
                                  <code key={i} className="bg-black/30 px-1.5 py-0.5 rounded text-joe-blue text-sm">
                                    {part.replace(/`/g, '')}
                                  </code>
                                ) : (
                                  part
                                )
                              )}
                            </p>
                          );
                        }
                        if (line.trim() === '') {
                          return <div key={idx} className="h-2" />;
                        }
                        return <p key={idx} className="my-1">{line}</p>;
                      })}
                    </div>
                  </div>
                )}
              </div>

              {/* Modal Footer */}
              <div className="p-4 border-t border-wolf-gray/30 flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs text-gray-500">
                  <Shield size={14} />
                  <span>Analysis generated by J.O.E. AI Security Intelligence</span>
                </div>
                <button
                  type="button"
                  onClick={() => setAiAnalysisOpen(false)}
                  className="btn-secondary"
                >
                  Close
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
