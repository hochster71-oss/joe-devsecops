/**
 * J.O.E. GitLab Security View
 * Repository Security Dashboard with AI-Driven Analysis
 *
 * Security Standards:
 * - OWASP ASVS v4.0 (Application Security)
 * - NIST SP 800-53 SA-11 (Developer Security Testing)
 * - DoD DevSecOps Reference Design
 * - SLSA Framework v1.0 (Supply Chain Security)
 */

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  GitBranch,
  Shield,
  Code,
  Key,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Loader2,
  Unplug,
  Plug,
  Search,
  Package,
  GitPullRequest,
  Eye,
  EyeOff,
  Brain,
  Sparkles,
  Zap,
  X,
  ExternalLink,
  FolderGit2
} from 'lucide-react';
import { useGitLabStore } from '../store/gitlabStore';
import { ollamaService } from '../../services/ollamaService';

export default function GitLabView() {
  const {
    connected,
    connecting,
    gitlabUrl,
    currentUser,
    connectionError,
    projects,
    selectedProject,
    loadingProjects,
    isScanning,
    scanProgress,
    lastScanTime,
    scanResults,
    sastScore,
    secretsCount,
    pipelineScore,
    dependencyVulnCount,
    criticalFindings,
    connect,
    disconnect,
    loadProjects: _loadProjects,
    selectProject,
    scanProject,
    clearResults: _clearResults
  } = useGitLabStore();

  // Connection form state
  const [gitlabUrlInput, setGitlabUrlInput] = useState('https://gitlab.com');
  const [tokenInput, setTokenInput] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [showConnectionPanel, setShowConnectionPanel] = useState(!connected);
  const [searchQuery, setSearchQuery] = useState('');

  // Expandable sections
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['sast', 'secrets']));

  // AI Deep Dive State
  const [aiAnalysisOpen, setAiAnalysisOpen] = useState(false);
  const [aiAnalysisLoading, setAiAnalysisLoading] = useState(false);
  const [aiAnalysisContent, setAiAnalysisContent] = useState<string>('');
  const [aiAnalysisTitle, setAiAnalysisTitle] = useState<string>('');
  const [aiAnalysisType, setAiAnalysisType] = useState<string>('');

  // Filter projects by search
  const filteredProjects = projects.filter(p =>
    p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    p.pathWithNamespace.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleConnect = async () => {
    if (!gitlabUrlInput || !tokenInput) {return;}
    const success = await connect(gitlabUrlInput, tokenInput);
    if (success) {
      setShowConnectionPanel(false);
      setTokenInput(''); // Clear token from memory
    }
  };

  const handleDisconnect = () => {
    disconnect();
    setShowConnectionPanel(true);
  };

  const handleScan = async () => {
    if (!selectedProject) {return;}
    try {
      await scanProject();
    } catch (error) {
      console.error('Scan failed:', error);
    }
  };

  const _toggleSection = (section: string) => {
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

  const handleAnalyzeFinding = async (finding: {
    id: string;
    type: string;
    title: string;
    severity: string;
    description: string;
    remediation: string;
    file?: string;
    line?: number;
  }) => {
    setAiAnalysisTitle(`AI Analysis: ${finding.title}`);
    setAiAnalysisType(finding.type);
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const context = `
Finding Type: ${finding.type}
Title: ${finding.title}
Severity: ${finding.severity}
File: ${finding.file || 'N/A'}
Line: ${finding.line || 'N/A'}
Description: ${finding.description}
Current Remediation: ${finding.remediation}`;

      const analysis = await ollamaService.chat(
        `As a DevSecOps security expert, analyze this security finding and provide:
1. **Risk Assessment**: Explain the severity and potential impact
2. **Attack Vector**: How could this be exploited?
3. **Root Cause**: Why does this vulnerability exist?
4. **Remediation Steps**: Specific code changes or configurations needed
5. **Prevention**: How to prevent this in the future (CI/CD gates, code reviews)
6. **OWASP/CWE Reference**: Map to relevant security standards`,
        context
      );
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error: ${error instanceof Error ? error.message : 'Unknown error'}\n\nEnsure Ollama is running.`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  const handleAnalyzeSAST = async () => {
    if (!scanResults) {return;}

    setAiAnalysisTitle('AI SAST Analysis Report');
    setAiAnalysisType('sast');
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const context = `
SAST Scan Results for ${scanResults.project.pathWithNamespace}:
Total Findings: ${scanResults.sastFindings.length}
Critical: ${scanResults.sastFindings.filter(f => f.severity === 'critical').length}
High: ${scanResults.sastFindings.filter(f => f.severity === 'high').length}
Medium: ${scanResults.sastFindings.filter(f => f.severity === 'medium').length}

Top Findings:
${scanResults.sastFindings.slice(0, 10).map(f => `- [${f.severity.toUpperCase()}] ${f.title} in ${f.file}:${f.line}`).join('\n')}`;

      const analysis = await ollamaService.chat(
        `Analyze this SAST scan report per OWASP ASVS v4.0 and provide:
1. **Executive Summary**: Overall code security posture
2. **Risk Priority**: Which findings to fix first and why
3. **Pattern Analysis**: Common vulnerability patterns detected
4. **Remediation Roadmap**: Prioritized list of fixes
5. **CI/CD Integration**: How to add SAST gates to prevent these
6. **Developer Training**: Topics the team should focus on`,
        context
      );
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  const handleAnalyzeSecrets = async () => {
    if (!scanResults) {return;}

    setAiAnalysisTitle('AI Secret Detection Analysis');
    setAiAnalysisType('secrets');
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const context = `
Secrets Detected: ${scanResults.secretsDetected.length}
Types Found:
${[...new Set(scanResults.secretsDetected.map(s => s.type))].map(t => `- ${t}: ${scanResults.secretsDetected.filter(s => s.type === t).length}`).join('\n')}

Files Affected:
${[...new Set(scanResults.secretsDetected.map(s => s.file))].slice(0, 10).join('\n')}`;

      const analysis = await ollamaService.chat(
        `Analyze these secret detection findings per NIST SP 800-53 IA-5:
1. **Incident Response**: Immediate actions required (rotation, revocation)
2. **Impact Assessment**: What systems/data could be compromised?
3. **Root Cause**: Why were secrets committed to code?
4. **Git History**: How to remove secrets from git history (BFG, filter-branch)
5. **Secrets Management**: Recommend secrets management solution (Vault, AWS SM)
6. **Prevention**: Pre-commit hooks and CI checks to prevent future leaks`,
        context
      );
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  const handleAnalyzePipeline = async () => {
    if (!scanResults) {return;}

    setAiAnalysisTitle('AI Pipeline Security Analysis');
    setAiAnalysisType('pipeline');
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const ps = scanResults.pipelineSecurity;
      const context = `
Pipeline Security Score: ${ps.score}%
Has SAST: ${ps.hasSASTJob}
Has Dependency Scan: ${ps.hasDependencyScan}
Has Container Scan: ${ps.hasContainerScan}
Has Secret Detection: ${ps.hasSecretDetection}
Has License Compliance: ${ps.hasLicenseCompliance}

Issues:
${ps.issues.map(i => `- [${i.severity.toUpperCase()}] ${i.title}: ${i.description}`).join('\n')}`;

      const analysis = await ollamaService.chat(
        `Analyze this CI/CD pipeline security per DoD DevSecOps Reference Design:
1. **Maturity Assessment**: Rate the pipeline's DevSecOps maturity (1-5)
2. **Missing Security Gates**: What security stages should be added?
3. **SLSA Compliance**: Current SLSA level and how to improve
4. **Recommended Pipeline**: Provide example .gitlab-ci.yml security stages
5. **Tool Recommendations**: Best tools for each missing capability
6. **Quick Wins**: Easiest improvements to implement first`,
        context
      );
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  const handleGenerateReport = async () => {
    if (!scanResults) {return;}

    setAiAnalysisTitle('AI Security Assessment Report');
    setAiAnalysisType('report');
    setAiAnalysisOpen(true);
    setAiAnalysisLoading(true);
    setAiAnalysisContent('');

    try {
      const context = `
Project: ${scanResults.project.pathWithNamespace}
Compliance Score: ${scanResults.complianceScore}%
SAST Findings: ${scanResults.sastFindings.length} (${scanResults.sastFindings.filter(f => f.severity === 'critical').length} critical)
Secrets Detected: ${scanResults.secretsDetected.length}
Pipeline Score: ${scanResults.pipelineSecurity.score}%
Dependency Vulnerabilities: ${scanResults.dependencyVulnerabilities.length}`;

      const analysis = await ollamaService.chat(
        `Generate an executive security assessment for this repository:
1. **Security Grade**: A-F rating with justification
2. **Risk Summary**: Top 3 risks that need immediate attention
3. **Compliance Status**: OWASP ASVS, NIST 800-53, SLSA readiness
4. **30-Day Remediation Plan**: Prioritized action items
5. **Resource Estimate**: Developer effort needed for remediation
6. **Benchmark Comparison**: How does this compare to industry standards?`,
        context
      );
      setAiAnalysisContent(analysis);
    } catch (error) {
      setAiAnalysisContent(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
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
    if (score >= 80) {return 'text-dws-green';}
    if (score >= 60) {return 'text-alert-warning';}
    if (score >= 40) {return 'text-alert-high';}
    return 'text-alert-critical';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-2xl font-bold text-white flex items-center gap-3">
            <GitBranch className="text-joe-purple" size={28} />
            GitLab Security
          </h1>
          <p className="text-gray-400 mt-1">
            OWASP ASVS v4.0 | NIST SP 800-53 | SLSA Framework
          </p>
        </div>
        <div className="flex items-center gap-3">
          {connected && selectedProject && (
            <>
              <button
                onClick={handleScan}
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
                    Scan Repository
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
            <Plug className="text-joe-purple" size={24} />
            <h2 className="font-heading font-semibold text-white text-lg">
              Connect to GitLab
            </h2>
          </div>

          {connectionError && (
            <div className="mb-4 p-3 bg-alert-critical/20 rounded-lg flex items-center gap-2 text-alert-critical">
              <XCircle size={18} />
              {connectionError}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-400 mb-2">
                GitLab URL
              </label>
              <input
                type="url"
                value={gitlabUrlInput}
                onChange={(e) => setGitlabUrlInput(e.target.value)}
                placeholder="https://gitlab.com"
                className="input-field w-full"
              />
              <p className="text-xs text-gray-500 mt-1">
                Self-hosted: https://gitlab.yourcompany.com
              </p>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-2">
                Personal Access Token (PAT)
              </label>
              <div className="relative">
                <input
                  type={showToken ? 'text' : 'password'}
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  placeholder="glpat-xxxxxxxxxxxxxxxxxxxx"
                  className="input-field w-full pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowToken(!showToken)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                >
                  {showToken ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              <p className="text-xs text-gray-500 mt-1">
                Required scopes: read_api, read_repository
              </p>
            </div>

            <button
              onClick={handleConnect}
              disabled={!gitlabUrlInput || !tokenInput || connecting}
              className="btn-primary flex items-center gap-2 w-full justify-center"
            >
              {connecting ? (
                <>
                  <Loader2 className="animate-spin" size={16} />
                  Connecting...
                </>
              ) : (
                <>
                  <Plug size={16} />
                  Connect to GitLab
                </>
              )}
            </button>
          </div>
        </motion.div>
      )}

      {/* Connected User Banner */}
      {connected && currentUser && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="glass-card p-4 flex items-center justify-between"
        >
          <div className="flex items-center gap-4">
            <div className="w-3 h-3 bg-dws-green rounded-full animate-pulse" />
            <div>
              <span className="text-white font-medium">{currentUser.name}</span>
              <span className="text-gray-500 ml-2">@{currentUser.username}</span>
            </div>
            <span className="text-gray-400">|</span>
            <span className="text-gray-400">{gitlabUrl}</span>
          </div>
          {lastScanTime && (
            <span className="text-sm text-gray-500">
              Last scan: {new Date(lastScanTime).toLocaleString()}
            </span>
          )}
        </motion.div>
      )}

      {/* Project Selector */}
      {connected && !selectedProject && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-heading font-semibold text-white text-lg flex items-center gap-2">
              <FolderGit2 className="text-joe-purple" size={20} />
              Select a Project to Scan
            </h2>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={16} />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search projects..."
                className="input-field pl-10 w-64"
              />
            </div>
          </div>

          {loadingProjects ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="animate-spin text-joe-purple" size={32} />
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-96 overflow-y-auto">
              {filteredProjects.map((project) => (
                <button
                  key={project.id}
                  onClick={() => selectProject(project)}
                  className="p-4 rounded-lg bg-wolf-gray/30 border border-wolf-gray/30 hover:border-joe-purple/50 hover:bg-wolf-gray/50 transition-all text-left"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <GitBranch size={16} className="text-joe-purple" />
                    <span className="text-white font-medium truncate">{project.name}</span>
                  </div>
                  <p className="text-xs text-gray-500 truncate">{project.pathWithNamespace}</p>
                  <div className="flex items-center gap-2 mt-2 text-xs text-gray-400">
                    <span className={`px-2 py-0.5 rounded ${project.visibility === 'private' ? 'bg-alert-warning/20 text-alert-warning' : 'bg-dws-green/20 text-dws-green'}`}>
                      {project.visibility}
                    </span>
                    <span>{project.defaultBranch}</span>
                  </div>
                </button>
              ))}
              {filteredProjects.length === 0 && (
                <div className="col-span-full text-center py-8 text-gray-500">
                  No projects found
                </div>
              )}
            </div>
          )}
        </motion.div>
      )}

      {/* Selected Project Banner */}
      {connected && selectedProject && !scanResults && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="glass-card p-6 text-center"
        >
          <GitBranch className="mx-auto mb-4 text-joe-purple" size={48} />
          <h3 className="text-xl font-medium text-white mb-2">{selectedProject.name}</h3>
          <p className="text-gray-400 mb-4">{selectedProject.pathWithNamespace}</p>
          <div className="flex items-center justify-center gap-4 mb-6">
            <a
              href={selectedProject.webUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-joe-purple hover:underline flex items-center gap-1 text-sm"
            >
              <ExternalLink size={14} />
              View on GitLab
            </a>
            <button
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              onClick={() => selectProject(null as any)}
              className="text-gray-400 hover:text-white text-sm"
            >
              Change Project
            </button>
          </div>
          <button onClick={handleScan} disabled={isScanning} className="btn-primary">
            {isScanning ? (
              <>
                <Loader2 className="animate-spin mr-2" size={16} />
                Scanning... {scanProgress}%
              </>
            ) : (
              <>
                <RefreshCw size={16} className="mr-2" />
                Run Security Scan
              </>
            )}
          </button>
        </motion.div>
      )}

      {/* Scan Results */}
      {connected && scanResults && (
        <>
          {/* Metrics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* SAST Score */}
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass-card p-4"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Code Security</span>
                <Code className="text-joe-purple" size={20} />
              </div>
              <div className={`text-3xl font-bold ${getScoreColor(sastScore)}`}>
                {sastScore}%
              </div>
              <div className="text-xs text-gray-500 mt-1">
                {scanResults.sastFindings.length} findings
              </div>
              <div className="flex gap-2 mt-2 text-xs">
                <span className="text-alert-critical">{scanResults.sastFindings.filter(f => f.severity === 'critical').length} Crit</span>
                <span className="text-alert-high">{scanResults.sastFindings.filter(f => f.severity === 'high').length} High</span>
              </div>
            </motion.div>

            {/* Secrets */}
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="glass-card p-4"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Secrets Detected</span>
                <Key className={secretsCount > 0 ? 'text-alert-critical' : 'text-dws-green'} size={20} />
              </div>
              <div className={`text-3xl font-bold ${secretsCount > 0 ? 'text-alert-critical' : 'text-dws-green'}`}>
                {secretsCount}
              </div>
              <div className="text-xs text-gray-500 mt-1">
                {secretsCount > 0 ? 'REQUIRES IMMEDIATE ACTION' : 'No secrets found'}
              </div>
            </motion.div>

            {/* Pipeline */}
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="glass-card p-4"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Pipeline Security</span>
                <GitPullRequest className="text-joe-purple" size={20} />
              </div>
              <div className={`text-3xl font-bold ${getScoreColor(pipelineScore)}`}>
                {pipelineScore}%
              </div>
              <div className="text-xs text-gray-500 mt-1">
                {scanResults.pipelineSecurity.issues.length} issues
              </div>
              <div className="flex gap-2 mt-2 text-xs">
                {scanResults.pipelineSecurity.hasSASTJob && <span className="text-dws-green">SAST</span>}
                {scanResults.pipelineSecurity.hasDependencyScan && <span className="text-dws-green">Deps</span>}
                {scanResults.pipelineSecurity.hasSecretDetection && <span className="text-dws-green">Secrets</span>}
              </div>
            </motion.div>

            {/* Dependencies */}
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="glass-card p-4"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Dependencies</span>
                <Package className="text-joe-purple" size={20} />
              </div>
              <div className="text-3xl font-bold text-white">
                {scanResults.dependencyVulnerabilities.length}
              </div>
              <div className="text-xs text-gray-500 mt-1">
                Vulnerable packages
              </div>
              <div className="flex gap-2 mt-2 text-xs">
                <span className="text-alert-critical">{dependencyVulnCount.critical} Crit</span>
                <span className="text-alert-high">{dependencyVulnCount.high} High</span>
              </div>
            </motion.div>
          </div>

          {/* Compliance Score */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card p-6"
          >
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-heading font-semibold text-white text-lg flex items-center gap-2">
                <Shield className="text-joe-purple" size={20} />
                Overall Compliance Score
              </h2>
              <span className="text-sm text-gray-400">
                Based on SAST, Secrets, Pipeline, and Dependencies
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

          {/* AI Intelligence Panel */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card p-6 border border-joe-purple/30"
          >
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-heading font-semibold text-white text-lg flex items-center gap-2">
                <Brain className="text-joe-purple" size={20} />
                J.O.E. AI Security Intelligence
              </h2>
              <span className="text-xs text-gray-400 flex items-center gap-1">
                <Sparkles size={12} className="text-joe-blue" />
                Powered by Ollama
              </span>
            </div>

            <p className="text-sm text-gray-400 mb-4">
              Deep dive into your repository security with AI analysis based on
              OWASP ASVS, NIST SP 800-53, and DoD DevSecOps standards.
            </p>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <button
                onClick={handleGenerateReport}
                className="flex flex-col items-center gap-2 p-4 rounded-lg bg-gradient-to-br from-joe-purple/20 to-joe-blue/20 border border-joe-purple/30 hover:border-joe-purple/60 transition-all group"
              >
                <Shield className="text-joe-purple group-hover:scale-110 transition-transform" size={24} />
                <span className="text-xs text-white text-center">Security Report</span>
              </button>

              <button
                onClick={handleAnalyzeSAST}
                className="flex flex-col items-center gap-2 p-4 rounded-lg bg-wolf-gray/30 border border-wolf-gray/30 hover:border-alert-high/50 transition-all group"
              >
                <Code className="text-alert-high group-hover:scale-110 transition-transform" size={24} />
                <span className="text-xs text-white text-center">SAST Analysis</span>
              </button>

              <button
                onClick={handleAnalyzeSecrets}
                className="flex flex-col items-center gap-2 p-4 rounded-lg bg-wolf-gray/30 border border-wolf-gray/30 hover:border-alert-critical/50 transition-all group"
              >
                <Key className="text-alert-critical group-hover:scale-110 transition-transform" size={24} />
                <span className="text-xs text-white text-center">Secrets Analysis</span>
              </button>

              <button
                onClick={handleAnalyzePipeline}
                className="flex flex-col items-center gap-2 p-4 rounded-lg bg-wolf-gray/30 border border-wolf-gray/30 hover:border-joe-blue/50 transition-all group"
              >
                <GitPullRequest className="text-joe-blue group-hover:scale-110 transition-transform" size={24} />
                <span className="text-xs text-white text-center">Pipeline Analysis</span>
              </button>
            </div>
          </motion.div>

          {/* Critical Findings */}
          {criticalFindings.length > 0 && (
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
                        {finding.file && (
                          <p className="text-xs text-gray-500 mt-1">
                            {finding.file}{finding.line ? `:${finding.line}` : ''}
                          </p>
                        )}
                        <p className="text-sm text-gray-400 mt-1">{finding.description}</p>
                        <p className="text-sm text-joe-purple mt-2">
                          <strong>Fix:</strong> {finding.remediation}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleAnalyzeFinding(finding)}
                        className="ml-4 flex items-center gap-1 px-3 py-2 rounded-lg bg-joe-purple/20 border border-joe-purple/30 hover:bg-joe-purple/30 hover:border-joe-purple/50 transition-all text-joe-purple text-xs font-medium"
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
        </>
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
            Connect to GitLab to scan repositories for security vulnerabilities.
          </p>
          <button onClick={() => setShowConnectionPanel(true)} className="btn-primary">
            <Plug size={16} className="mr-2" />
            Connect to GitLab
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
              className="bg-wolf-gray-darker border border-joe-purple/30 rounded-xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl"
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between p-4 border-b border-wolf-gray/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-joe-purple/20">
                    <Brain className="text-joe-purple" size={24} />
                  </div>
                  <div>
                    <h2 className="font-heading font-semibold text-white text-lg">
                      {aiAnalysisTitle}
                    </h2>
                    <p className="text-xs text-gray-400 flex items-center gap-1">
                      <Sparkles size={10} className="text-joe-blue" />
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
                      <Loader2 className="animate-spin text-joe-purple" size={48} />
                      <Brain className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-joe-blue" size={20} />
                    </div>
                    <p className="text-gray-400 mt-4">J.O.E. is analyzing...</p>
                    <p className="text-xs text-gray-500 mt-1">
                      Querying Ollama AI with security context
                    </p>
                  </div>
                ) : (
                  <div className="prose prose-invert max-w-none">
                    {/* Reference Banner */}
                    <div className="mb-4 p-3 rounded-lg bg-joe-purple/10 border border-joe-purple/20 text-xs text-gray-400">
                      <strong className="text-joe-purple">Security Standards:</strong>{' '}
                      {aiAnalysisType === 'sast' && 'OWASP ASVS v4.0, CWE Top 25'}
                      {aiAnalysisType === 'secrets' && 'NIST SP 800-53 IA-5, DoD STIG'}
                      {aiAnalysisType === 'pipeline' && 'DoD DevSecOps Reference, SLSA Framework'}
                      {aiAnalysisType === 'report' && 'OWASP, NIST, SLSA, DoD DevSecOps'}
                      {aiAnalysisType === 'dependency' && 'NIST SP 800-53 RA-5, OWASP Dependency-Check'}
                    </div>

                    {/* AI Response Content */}
                    <div className="whitespace-pre-wrap text-gray-300 leading-relaxed">
                      {aiAnalysisContent.split('\n').map((line, idx) => {
                        if (line.startsWith('## ')) {
                          return (
                            <h2 key={idx} className="text-xl font-bold text-white mt-6 mb-3 flex items-center gap-2">
                              <Zap size={18} className="text-joe-purple" />
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
                            <p key={idx} className="font-bold text-joe-purple mt-4 mb-2">
                              {line.replace(/\*\*/g, '')}
                            </p>
                          );
                        }
                        if (line.startsWith('- ') || line.startsWith('* ')) {
                          return (
                            <div key={idx} className="flex items-start gap-2 ml-4 my-1">
                              <span className="text-joe-purple mt-1.5">•</span>
                              <span>{line.replace(/^[-*] /, '')}</span>
                            </div>
                          );
                        }
                        if (line.match(/^\d+\. /)) {
                          return (
                            <div key={idx} className="flex items-start gap-2 ml-4 my-1">
                              <span className="text-joe-blue font-bold">{line.match(/^\d+/)?.[0]}.</span>
                              <span>{line.replace(/^\d+\. /, '')}</span>
                            </div>
                          );
                        }
                        if (line.includes('`') && !line.startsWith('```')) {
                          const parts = line.split(/(`[^`]+`)/g);
                          return (
                            <p key={idx} className="my-1">
                              {parts.map((part, i) =>
                                part.startsWith('`') ? (
                                  <code key={i} className="bg-black/30 px-1.5 py-0.5 rounded text-joe-purple text-sm">
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
                  <span>Analysis by J.O.E. AI Security Intelligence</span>
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
