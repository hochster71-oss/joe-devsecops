import { useState } from 'react';
import { motion } from 'framer-motion';
import Modal from '../components/common/Modal';
import {
  GitBranch,
  CheckCircle,
  XCircle,
  Clock,
  Play,
  Download,
  Settings,
  Terminal,
  FileCode,
  Shield,
  AlertTriangle,
  ChevronRight,
  Copy,
  ExternalLink,
  Activity,
  Zap,
  Lock,
  Eye
} from 'lucide-react';

interface PipelineStage {
  name: string;
  status: 'success' | 'failed' | 'running' | 'pending';
  duration?: string;
  logs?: string[];
}

interface Pipeline {
  id: string;
  name: string;
  platform: string;
  status: 'success' | 'failed' | 'running' | 'pending';
  lastRun: string;
  duration: string;
  stages: PipelineStage[];
  branch: string;
  commit: string;
  trigger: string;
  securityGates: {
    sast: boolean;
    sca: boolean;
    secrets: boolean;
    container: boolean;
  };
}

const mockPipelines: Pipeline[] = [
  {
    id: '1',
    name: 'Security Scan Pipeline',
    platform: 'GitHub Actions',
    status: 'success',
    lastRun: '2 hours ago',
    duration: '3m 42s',
    branch: 'main',
    commit: 'a1b2c3d',
    trigger: 'Push to main',
    stages: [
      { name: 'Checkout', status: 'success', duration: '8s', logs: ['Checking out repository...', 'Fetched 1.2GB in 5s'] },
      { name: 'Semgrep', status: 'success', duration: '45s', logs: ['Running SAST scan...', 'Found 0 critical issues', 'Found 2 low issues'] },
      { name: 'Trivy', status: 'success', duration: '1m 12s', logs: ['Scanning container image...', 'No high/critical vulnerabilities'] },
      { name: 'SBOM', status: 'success', duration: '32s', logs: ['Generating CycloneDX SBOM...', 'Found 847 components'] },
      { name: 'Report', status: 'success', duration: '15s', logs: ['Publishing report to artifacts...', 'Upload complete'] }
    ],
    securityGates: { sast: true, sca: true, secrets: true, container: true }
  },
  {
    id: '2',
    name: 'Container Security',
    platform: 'Azure Pipelines',
    status: 'running',
    lastRun: 'In progress',
    duration: '1m 15s',
    branch: 'feature/auth-update',
    commit: 'e5f6g7h',
    trigger: 'Pull Request #142',
    stages: [
      { name: 'Build', status: 'success', duration: '28s', logs: ['Building Docker image...', 'Build successful'] },
      { name: 'Trivy Scan', status: 'running', logs: ['Scanning for vulnerabilities...'] },
      { name: 'Push', status: 'pending' },
      { name: 'Deploy', status: 'pending' }
    ],
    securityGates: { sast: true, sca: true, secrets: false, container: true }
  },
  {
    id: '3',
    name: 'Compliance Check',
    platform: 'GitLab CI',
    status: 'failed',
    lastRun: '1 day ago',
    duration: '5m 22s',
    branch: 'develop',
    commit: 'i8j9k0l',
    trigger: 'Scheduled (nightly)',
    stages: [
      { name: 'OPA', status: 'success', duration: '1m 05s', logs: ['Running policy checks...', 'All policies passed'] },
      { name: 'Checkov', status: 'success', duration: '2m 12s', logs: ['Scanning IaC files...', 'Found 3 misconfigurations'] },
      { name: 'CMMC Score', status: 'failed', duration: '2m 05s', logs: ['Calculating CMMC Level 1 score...', 'ERROR: Score 68% below threshold (80%)', 'Missing controls: SI.L1-3.14.1, SC.L1-3.13.1'] }
    ],
    securityGates: { sast: false, sca: true, secrets: true, container: false }
  }
];

// Pipeline config templates
const pipelineTemplates: Record<string, { description: string; features: string[]; config: string }> = {
  'GitHub Actions': {
    description: 'Native GitHub CI/CD with seamless integration for repositories hosted on GitHub.',
    features: ['Matrix builds', 'Reusable workflows', 'OIDC auth', 'Artifact caching'],
    config: `name: J.O.E. Security Pipeline
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
      - name: Generate SBOM
        run: cyclonedx-npm --output sbom.json`
  },
  'Azure Pipelines': {
    description: 'Microsoft Azure DevOps CI/CD with enterprise-grade features and integrations.',
    features: ['YAML pipelines', 'Service connections', 'Environments', 'Approvals'],
    config: `trigger:
  - main
pool:
  vmImage: 'ubuntu-latest'
stages:
  - stage: Security
    jobs:
      - job: Scan
        steps:
          - task: Semgrep@1
          - task: ContainerScan@0
          - task: SBOM@1`
  },
  'GitLab CI': {
    description: 'GitLab native CI/CD with built-in security scanning and compliance features.',
    features: ['Auto DevOps', 'DAST/SAST', 'Dependency scanning', 'Container scanning'],
    config: `stages:
  - test
  - security
  - deploy

semgrep:
  stage: security
  image: returntocorp/semgrep
  script:
    - semgrep --config auto .

trivy:
  stage: security
  image: aquasec/trivy
  script:
    - trivy fs --severity HIGH,CRITICAL .`
  },
  'Jenkins': {
    description: 'Open-source automation server with extensive plugin ecosystem.',
    features: ['Pipeline as Code', 'Distributed builds', 'Plugin ecosystem', 'Blue Ocean UI'],
    config: `pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'semgrep --config auto .'
                sh 'trivy fs .'
            }
        }
        stage('SBOM') {
            steps {
                sh 'cyclonedx-npm --output sbom.json'
            }
        }
    }
}`
  }
};

export default function PipelineView() {
  const [selectedPipeline, setSelectedPipeline] = useState<Pipeline | null>(null);
  const [selectedPlatform, setSelectedPlatform] = useState<string | null>(null);
  const [copiedConfig, setCopiedConfig] = useState(false);

  const getStatusConfig = (status: string) => {
    switch (status) {
      case 'success':
        return { icon: CheckCircle, color: 'text-dws-green', bg: 'bg-dws-green/10', border: 'border-dws-green/30' };
      case 'failed':
        return { icon: XCircle, color: 'text-alert-critical', bg: 'bg-alert-critical/10', border: 'border-alert-critical/30' };
      case 'running':
        return { icon: Clock, color: 'text-joe-blue', bg: 'bg-joe-blue/10', border: 'border-joe-blue/30' };
      default:
        return { icon: Clock, color: 'text-gray-500', bg: 'bg-gray-500/10', border: 'border-gray-500/30' };
    }
  };

  const handleCopyConfig = (config: string) => {
    navigator.clipboard.writeText(config);
    setCopiedConfig(true);
    setTimeout(() => setCopiedConfig(false), 2000);
  };

  // Stats for quick view
  const stats = {
    total: mockPipelines.length,
    success: mockPipelines.filter(p => p.status === 'success').length,
    running: mockPipelines.filter(p => p.status === 'running').length,
    failed: mockPipelines.filter(p => p.status === 'failed').length
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-joe-blue/10 border border-joe-blue/30">
            <GitBranch className="text-joe-blue" size={28} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-white">Pipeline Security</h1>
            <p className="text-gray-400 mt-1">CI/CD security gates and pipeline management</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button className="btn-secondary flex items-center gap-2">
            <Download size={16} />
            Export Configs
          </button>
          <button className="btn-primary flex items-center gap-2">
            <Play size={16} />
            Run All
          </button>
        </div>
      </div>

      {/* Stats Cards - Clickable */}
      <div className="grid grid-cols-4 gap-4">
        <motion.button
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-card p-4 text-left hover:border-joe-blue/50 transition-colors group"
        >
          <div className="flex items-center gap-3">
            <Activity className="text-joe-blue" size={20} />
            <div>
              <p className="text-2xl font-bold text-white">{stats.total}</p>
              <p className="text-gray-500 text-sm">Total Pipelines</p>
            </div>
          </div>
        </motion.button>

        <motion.button
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="glass-card p-4 text-left hover:border-dws-green/50 transition-colors group bg-dws-green/5"
        >
          <div className="flex items-center gap-3">
            <CheckCircle className="text-dws-green" size={20} />
            <div>
              <p className="text-2xl font-bold text-dws-green">{stats.success}</p>
              <p className="text-gray-500 text-sm">Successful</p>
            </div>
          </div>
        </motion.button>

        <motion.button
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="glass-card p-4 text-left hover:border-joe-blue/50 transition-colors group bg-joe-blue/5"
        >
          <div className="flex items-center gap-3">
            <Clock className="text-joe-blue" size={20} />
            <div>
              <p className="text-2xl font-bold text-joe-blue">{stats.running}</p>
              <p className="text-gray-500 text-sm">Running</p>
            </div>
          </div>
        </motion.button>

        <motion.button
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="glass-card p-4 text-left hover:border-alert-critical/50 transition-colors group bg-alert-critical/5"
        >
          <div className="flex items-center gap-3">
            <XCircle className="text-alert-critical" size={20} />
            <div>
              <p className="text-2xl font-bold text-alert-critical">{stats.failed}</p>
              <p className="text-gray-500 text-sm">Failed</p>
            </div>
          </div>
        </motion.button>
      </div>

      {/* Pipeline Cards - Clickable */}
      <div className="space-y-4">
        {mockPipelines.map((pipeline, index) => {
          const config = getStatusConfig(pipeline.status);
          const Icon = config.icon;

          return (
            <motion.button
              key={pipeline.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              onClick={() => setSelectedPipeline(pipeline)}
              className="w-full glass-card p-6 text-left hover:bg-dws-elevated transition-colors group"
            >
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-4">
                  <div className={`p-3 rounded-lg ${config.bg} border ${config.border}`}>
                    <GitBranch className={config.color} size={24} />
                  </div>
                  <div>
                    <h3 className="text-white font-semibold text-lg flex items-center gap-2">
                      {pipeline.name}
                      <ChevronRight className="text-gray-600 group-hover:text-joe-blue transition-colors" size={18} />
                    </h3>
                    <div className="flex items-center gap-3 text-sm">
                      <span className="text-gray-500">{pipeline.platform}</span>
                      <span className="text-gray-600">|</span>
                      <span className="text-joe-blue font-mono text-xs">{pipeline.branch}</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  {/* Security Gates */}
                  <div className="flex items-center gap-1">
                    <Shield className={pipeline.securityGates.sast ? 'text-dws-green' : 'text-gray-600'} size={14} title="SAST" />
                    <Lock className={pipeline.securityGates.secrets ? 'text-dws-green' : 'text-gray-600'} size={14} title="Secrets" />
                    <Eye className={pipeline.securityGates.container ? 'text-dws-green' : 'text-gray-600'} size={14} title="Container" />
                  </div>
                  <div className="text-right">
                    <p className="text-gray-400 text-sm">{pipeline.lastRun}</p>
                    <p className="text-gray-500 text-xs">{pipeline.duration}</p>
                  </div>
                  <div className={`p-2 rounded-lg ${config.bg} border ${config.border}`}>
                    <Icon className={`${config.color} ${pipeline.status === 'running' ? 'animate-spin' : ''}`} size={20} />
                  </div>
                </div>
              </div>

              {/* Pipeline Stages */}
              <div className="flex items-center gap-2 overflow-x-auto">
                {pipeline.stages.map((stage, i) => {
                  const stageConfig = getStatusConfig(stage.status);
                  return (
                    <div key={stage.name} className="flex items-center">
                      <div className={`
                        px-3 py-1.5 rounded text-sm flex items-center gap-2
                        ${stageConfig.bg} ${stageConfig.color} border ${stageConfig.border}
                      `}>
                        {stage.status === 'running' && <Clock size={12} className="animate-spin" />}
                        {stage.name}
                        {stage.duration && <span className="text-xs opacity-70">({stage.duration})</span>}
                      </div>
                      {i < pipeline.stages.length - 1 && (
                        <div className="w-8 h-0.5 bg-dws-border mx-1" />
                      )}
                    </div>
                  );
                })}
              </div>
            </motion.button>
          );
        })}
      </div>

      {/* Quick Actions - Clickable */}
      <div className="glass-card p-6">
        <h3 className="font-heading font-semibold text-white mb-4 flex items-center gap-2">
          <FileCode className="text-joe-blue" size={20} />
          Generate Pipeline Configuration
        </h3>
        <p className="text-gray-500 text-sm mb-4">Click a platform to view and copy J.O.E. security pipeline configuration</p>
        <div className="grid grid-cols-4 gap-4">
          {Object.keys(pipelineTemplates).map(platform => (
            <button
              key={platform}
              onClick={() => setSelectedPlatform(platform)}
              className="btn-secondary flex items-center justify-center gap-2 hover:border-joe-blue/50 hover:bg-joe-blue/10 transition-colors"
            >
              <Settings size={16} />
              {platform}
            </button>
          ))}
        </div>
      </div>

      {/* Pipeline Detail Modal */}
      <Modal
        isOpen={!!selectedPipeline}
        onClose={() => setSelectedPipeline(null)}
        title={selectedPipeline?.name}
        subtitle={`${selectedPipeline?.platform} | ${selectedPipeline?.branch}`}
        size="xl"
        headerIcon={<GitBranch size={24} />}
        variant={selectedPipeline?.status === 'success' ? 'success' : selectedPipeline?.status === 'failed' ? 'critical' : 'info'}
        footer={
          <div className="flex items-center justify-between">
            <span className="text-gray-500 text-sm">Commit: {selectedPipeline?.commit}</span>
            <div className="flex items-center gap-3">
              <button onClick={() => setSelectedPipeline(null)} className="btn-secondary">
                Close
              </button>
              <button className="btn-primary flex items-center gap-2">
                <Play size={16} />
                Re-run Pipeline
              </button>
            </div>
          </div>
        }
      >
        {selectedPipeline && (
          <div className="space-y-6">
            {/* Pipeline Info */}
            <div className="grid grid-cols-4 gap-4">
              <div className="glass-card p-4">
                <p className="text-gray-500 text-sm">Status</p>
                <p className={`text-lg font-bold capitalize ${getStatusConfig(selectedPipeline.status).color}`}>
                  {selectedPipeline.status}
                </p>
              </div>
              <div className="glass-card p-4">
                <p className="text-gray-500 text-sm">Duration</p>
                <p className="text-lg font-bold text-white">{selectedPipeline.duration}</p>
              </div>
              <div className="glass-card p-4">
                <p className="text-gray-500 text-sm">Trigger</p>
                <p className="text-sm font-medium text-joe-blue">{selectedPipeline.trigger}</p>
              </div>
              <div className="glass-card p-4">
                <p className="text-gray-500 text-sm">Commit</p>
                <p className="text-sm font-mono text-white">{selectedPipeline.commit}</p>
              </div>
            </div>

            {/* Security Gates */}
            <div>
              <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                <Shield size={16} className="text-joe-blue" />
                Security Gates
              </h4>
              <div className="grid grid-cols-4 gap-3">
                {Object.entries(selectedPipeline.securityGates).map(([gate, passed]) => (
                  <div
                    key={gate}
                    className={`p-3 rounded-lg border ${passed ? 'bg-dws-green/10 border-dws-green/30' : 'bg-alert-critical/10 border-alert-critical/30'}`}
                  >
                    <div className="flex items-center gap-2">
                      {passed ? <CheckCircle size={16} className="text-dws-green" /> : <XCircle size={16} className="text-alert-critical" />}
                      <span className={`text-sm font-medium uppercase ${passed ? 'text-dws-green' : 'text-alert-critical'}`}>
                        {gate}
                      </span>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">{passed ? 'Passed' : 'Not configured'}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Stage Details */}
            <div>
              <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                <Terminal size={16} className="text-joe-blue" />
                Pipeline Stages
              </h4>
              <div className="space-y-3">
                {selectedPipeline.stages.map((stage, i) => {
                  const stageConfig = getStatusConfig(stage.status);
                  const StageIcon = stageConfig.icon;
                  return (
                    <div key={stage.name} className={`p-4 rounded-lg ${stageConfig.bg} border ${stageConfig.border}`}>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-3">
                          <span className="w-6 h-6 rounded-full bg-dws-dark flex items-center justify-center text-xs font-bold text-gray-400">
                            {i + 1}
                          </span>
                          <span className="text-white font-medium">{stage.name}</span>
                          <StageIcon size={16} className={`${stageConfig.color} ${stage.status === 'running' ? 'animate-spin' : ''}`} />
                        </div>
                        {stage.duration && (
                          <span className="text-gray-500 text-sm">{stage.duration}</span>
                        )}
                      </div>
                      {stage.logs && stage.logs.length > 0 && (
                        <div className="mt-2 p-2 bg-dws-dark/50 rounded text-xs font-mono text-gray-400 space-y-1">
                          {stage.logs.map((log, li) => (
                            <div key={li} className={log.includes('ERROR') ? 'text-alert-critical' : log.includes('Found 0') || log.includes('No high') ? 'text-dws-green' : ''}>
                              $ {log}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </Modal>

      {/* Platform Config Modal */}
      <Modal
        isOpen={!!selectedPlatform}
        onClose={() => setSelectedPlatform(null)}
        title={`${selectedPlatform} Configuration`}
        subtitle="J.O.E. Security Pipeline Template"
        size="lg"
        headerIcon={<FileCode size={24} />}
        variant="info"
        footer={
          <div className="flex items-center justify-between">
            <a
              href={selectedPlatform === 'GitHub Actions' ? 'https://docs.github.com/actions' :
                    selectedPlatform === 'Azure Pipelines' ? 'https://learn.microsoft.com/azure/devops/pipelines' :
                    selectedPlatform === 'GitLab CI' ? 'https://docs.gitlab.com/ee/ci/' :
                    'https://www.jenkins.io/doc/'}
              target="_blank"
              rel="noopener noreferrer"
              className="text-joe-blue text-sm flex items-center gap-1 hover:underline"
            >
              View Documentation <ExternalLink size={14} />
            </a>
            <div className="flex items-center gap-3">
              <button onClick={() => setSelectedPlatform(null)} className="btn-secondary">
                Close
              </button>
              <button
                onClick={() => selectedPlatform && handleCopyConfig(pipelineTemplates[selectedPlatform].config)}
                className="btn-primary flex items-center gap-2"
              >
                <Copy size={16} />
                {copiedConfig ? 'Copied!' : 'Copy Config'}
              </button>
            </div>
          </div>
        }
      >
        {selectedPlatform && pipelineTemplates[selectedPlatform] && (
          <div className="space-y-6">
            {/* Description */}
            <div>
              <p className="text-gray-300">{pipelineTemplates[selectedPlatform].description}</p>
            </div>

            {/* Features */}
            <div>
              <h4 className="font-semibold text-white mb-3">Key Features</h4>
              <div className="flex flex-wrap gap-2">
                {pipelineTemplates[selectedPlatform].features.map(feature => (
                  <span key={feature} className="px-3 py-1 bg-joe-blue/10 text-joe-blue border border-joe-blue/30 rounded-full text-sm">
                    {feature}
                  </span>
                ))}
              </div>
            </div>

            {/* Config Preview */}
            <div>
              <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                <Terminal size={16} className="text-joe-blue" />
                Pipeline Configuration
              </h4>
              <div className="relative">
                <pre className="p-4 bg-dws-dark rounded-lg overflow-x-auto text-sm font-mono text-gray-300 border border-dws-border">
                  {pipelineTemplates[selectedPlatform].config}
                </pre>
                <button
                  onClick={() => handleCopyConfig(pipelineTemplates[selectedPlatform].config)}
                  className="absolute top-2 right-2 p-2 bg-dws-elevated rounded hover:bg-dws-card transition-colors"
                  title="Copy to clipboard"
                >
                  <Copy size={14} className={copiedConfig ? 'text-dws-green' : 'text-gray-400'} />
                </button>
              </div>
            </div>

            {/* Security Features */}
            <div className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg">
              <h4 className="font-semibold text-dws-green mb-2 flex items-center gap-2">
                <Zap size={16} />
                J.O.E. Security Features Included
              </h4>
              <ul className="text-sm text-gray-300 space-y-1">
                <li className="flex items-center gap-2">
                  <CheckCircle size={14} className="text-dws-green" /> SAST scanning with Semgrep
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle size={14} className="text-dws-green" /> Container scanning with Trivy
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle size={14} className="text-dws-green" /> SBOM generation (CycloneDX)
                </li>
                <li className="flex items-center gap-2">
                  <CheckCircle size={14} className="text-dws-green" /> Automated security reports
                </li>
              </ul>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
