import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Modal, { ConfirmModal } from '../components/common/Modal';
import {
  ClipboardCheck,
  CheckCircle,
  AlertCircle,
  XCircle,
  HelpCircle,
  Download,
  RefreshCw,
  Shield,
  FileText,
  Clock,
  ExternalLink,
  ChevronRight,
  Target,
  AlertTriangle,
  BookOpen,
  Wrench,
  Eye
} from 'lucide-react';

/**
 * CMMC 2.0 Compliance View
 *
 * J.O.E. Self-Assessment for CMMC Level 1 (Foundational)
 * Based on NIST SP 800-171 Rev 2 security requirements
 *
 * Reference: https://www.acq.osd.mil/cmmc/
 */

interface Evidence {
  type: 'policy' | 'technical' | 'process' | 'audit';
  description: string;
  status: 'collected' | 'pending' | 'missing';
  file?: string;
}

interface Remediation {
  step: number;
  action: string;
  priority: 'high' | 'medium' | 'low';
  effort: string;
  completed: boolean;
}

interface Control {
  id: string;
  title: string;
  status: 'compliant' | 'partially-compliant' | 'non-compliant' | 'not-assessed';
  description: string;
  requirement: string;
  domain: string;
  nistRef: string;
  assessmentDate: string;
  evidence: Evidence[];
  remediations: Remediation[];
  findings: string[];
  notes: string;
}

// J.O.E. DevSecOps Arsenal CMMC 2.0 Self-Assessment Data
const joeControls: Control[] = [
  {
    id: 'AC.L1-3.1.1',
    title: 'Authorized Access Control',
    status: 'compliant',
    description: 'Limit system access to authorized users, processes acting on behalf of authorized users, and devices.',
    requirement: 'J.O.E. must implement access controls limiting system functionality to authorized users.',
    domain: 'Access Control',
    nistRef: 'NIST SP 800-171 3.1.1',
    assessmentDate: new Date(Date.now() - 86400000).toISOString(),
    evidence: [
      { type: 'technical', description: 'User authentication via authStore.ts', status: 'collected', file: 'src/renderer/store/authStore.ts' },
      { type: 'technical', description: 'Role-based access (Administrator/Standard)', status: 'collected', file: 'src/renderer/store/authStore.ts' },
      { type: 'process', description: 'Login flow with credential validation', status: 'collected', file: 'src/renderer/views/LoginView.tsx' }
    ],
    remediations: [],
    findings: [],
    notes: 'J.O.E. implements user authentication with role differentiation between Administrator and Standard User accounts.'
  },
  {
    id: 'AC.L1-3.1.2',
    title: 'Transaction & Function Control',
    status: 'compliant',
    description: 'Limit system access to the types of transactions and functions that authorized users are permitted to execute.',
    requirement: 'Different user roles should have different access levels to J.O.E. functionality.',
    domain: 'Access Control',
    nistRef: 'NIST SP 800-171 3.1.2',
    assessmentDate: new Date(Date.now() - 86400000).toISOString(),
    evidence: [
      { type: 'technical', description: 'Role-based navigation and feature access', status: 'collected', file: 'src/renderer/App.tsx' },
      { type: 'technical', description: 'User role stored in application state', status: 'collected', file: 'src/renderer/store/authStore.ts' }
    ],
    remediations: [],
    findings: [],
    notes: 'Administrator users have full access; Standard users have limited configuration access.'
  },
  {
    id: 'AC.L1-3.1.20',
    title: 'External Connections',
    status: 'partially-compliant',
    description: 'Verify and control/limit connections to and use of external systems.',
    requirement: 'J.O.E. must validate and control external system connections (Ollama, external APIs).',
    domain: 'Access Control',
    nistRef: 'NIST SP 800-171 3.1.20',
    assessmentDate: new Date(Date.now() - 172800000).toISOString(),
    evidence: [
      { type: 'technical', description: 'Ollama connection validation', status: 'collected', file: 'src/renderer/views/AiChatView.tsx' },
      { type: 'policy', description: 'External endpoint allowlist', status: 'missing' }
    ],
    remediations: [
      { step: 1, action: 'Implement URL validation for Ollama endpoint configuration', priority: 'medium', effort: '2-4 hours', completed: false },
      { step: 2, action: 'Add allowlist for permitted external connections', priority: 'medium', effort: '4-8 hours', completed: false }
    ],
    findings: ['Ollama API endpoint not validated against allowlist'],
    notes: 'External connections to Ollama AI service need additional validation controls.'
  },
  {
    id: 'IA.L1-3.5.1',
    title: 'Identification',
    status: 'compliant',
    description: 'Identify system users, processes acting on behalf of users, and devices.',
    requirement: 'J.O.E. must uniquely identify users accessing the system.',
    domain: 'Identification & Authentication',
    nistRef: 'NIST SP 800-171 3.5.1',
    assessmentDate: new Date(Date.now() - 86400000).toISOString(),
    evidence: [
      { type: 'technical', description: 'Unique user identification in login system', status: 'collected', file: 'src/renderer/views/LoginView.tsx' },
      { type: 'technical', description: 'User session tracking', status: 'collected', file: 'src/renderer/store/authStore.ts' }
    ],
    remediations: [],
    findings: [],
    notes: 'Users are uniquely identified by username and role.'
  },
  {
    id: 'IA.L1-3.5.2',
    title: 'Authentication',
    status: 'partially-compliant',
    description: 'Authenticate (or verify) the identities of users, processes, or devices.',
    requirement: 'J.O.E. must authenticate users before granting access.',
    domain: 'Identification & Authentication',
    nistRef: 'NIST SP 800-171 3.5.2',
    assessmentDate: new Date(Date.now() - 172800000).toISOString(),
    evidence: [
      { type: 'technical', description: 'Password-based authentication implemented', status: 'collected', file: 'src/renderer/views/LoginView.tsx' },
      { type: 'technical', description: 'Authentication state management', status: 'collected', file: 'src/renderer/store/authStore.ts' }
    ],
    remediations: [
      { step: 1, action: 'Remove hardcoded credentials from authStore.ts', priority: 'high', effort: '1-2 hours', completed: false },
      { step: 2, action: 'Implement secure credential storage (encrypted)', priority: 'high', effort: '4-8 hours', completed: false },
      { step: 3, action: 'Add password complexity requirements', priority: 'medium', effort: '2-4 hours', completed: false }
    ],
    findings: ['Hardcoded credentials in authentication store', 'No password complexity enforcement'],
    notes: 'Authentication exists but credentials are hardcoded. Requires secure credential management.'
  },
  {
    id: 'MP.L1-3.8.3',
    title: 'Media Sanitization',
    status: 'compliant',
    description: 'Sanitize or destroy system media containing CUI before disposal or reuse.',
    requirement: 'J.O.E. logs and temporary data should be properly sanitized.',
    domain: 'Media Protection',
    nistRef: 'NIST SP 800-171 3.8.3',
    assessmentDate: new Date(Date.now() - 259200000).toISOString(),
    evidence: [
      { type: 'technical', description: 'No persistent CUI storage in current implementation', status: 'collected' },
      { type: 'process', description: 'Session-based data cleared on logout', status: 'collected' }
    ],
    remediations: [],
    findings: [],
    notes: 'J.O.E. currently operates as session-based with no persistent CUI storage.'
  },
  {
    id: 'PE.L1-3.10.1',
    title: 'Physical Access Logs',
    status: 'compliant',
    description: 'Limit physical access to organizational systems, equipment, and storage.',
    requirement: 'Desktop application - physical access is user workstation responsibility.',
    domain: 'Physical Protection',
    nistRef: 'NIST SP 800-171 3.10.1',
    assessmentDate: new Date(Date.now() - 259200000).toISOString(),
    evidence: [
      { type: 'policy', description: 'Desktop application inherits workstation physical security', status: 'collected' }
    ],
    remediations: [],
    findings: [],
    notes: 'Physical security is inherited from the Windows workstation security posture.'
  },
  {
    id: 'SC.L1-3.13.1',
    title: 'Boundary Protection',
    status: 'partially-compliant',
    description: 'Monitor, control, and protect communications at external system boundaries.',
    requirement: 'J.O.E. must implement secure communication boundaries with external services.',
    domain: 'System & Communications Protection',
    nistRef: 'NIST SP 800-171 3.13.1',
    assessmentDate: new Date(Date.now() - 172800000).toISOString(),
    evidence: [
      { type: 'technical', description: 'Electron app boundary (main/renderer process isolation)', status: 'collected', file: 'src/main/main.ts' },
      { type: 'technical', description: 'IPC bridge implementation', status: 'collected', file: 'src/main/preload.ts' }
    ],
    remediations: [
      { step: 1, action: 'Disable nodeIntegration in Electron BrowserWindow', priority: 'high', effort: '2-4 hours', completed: false },
      { step: 2, action: 'Implement Content Security Policy headers', priority: 'medium', effort: '2-4 hours', completed: false },
      { step: 3, action: 'Enable contextIsolation for renderer process', priority: 'high', effort: '1-2 hours', completed: false }
    ],
    findings: ['nodeIntegration enabled in Electron configuration', 'Missing Content Security Policy'],
    notes: 'Electron security best practices not fully implemented. nodeIntegration should be disabled.'
  },
  {
    id: 'SC.L1-3.13.5',
    title: 'Transmission Confidentiality',
    status: 'compliant',
    description: 'Implement cryptographic mechanisms to protect the confidentiality of CUI during transmission.',
    requirement: 'Communications with external services should use encryption.',
    domain: 'System & Communications Protection',
    nistRef: 'NIST SP 800-171 3.13.5',
    assessmentDate: new Date(Date.now() - 86400000).toISOString(),
    evidence: [
      { type: 'technical', description: 'Ollama connection via localhost (no network transmission)', status: 'collected' },
      { type: 'technical', description: 'External links use HTTPS', status: 'collected' }
    ],
    remediations: [],
    findings: [],
    notes: 'AI service communicates via localhost. External references use HTTPS.'
  },
  {
    id: 'SI.L1-3.14.1',
    title: 'Flaw Remediation',
    status: 'non-compliant',
    description: 'Identify, report, and correct system flaws in a timely manner.',
    requirement: 'J.O.E. must have a process for identifying and remediating security flaws.',
    domain: 'System & Information Integrity',
    nistRef: 'NIST SP 800-171 3.14.1',
    assessmentDate: new Date(Date.now() - 86400000).toISOString(),
    evidence: [
      { type: 'technical', description: 'Security scanning tools integrated (conceptual)', status: 'pending' },
      { type: 'process', description: 'Vulnerability management process', status: 'missing' }
    ],
    remediations: [
      { step: 1, action: 'Enable automated dependency vulnerability scanning', priority: 'high', effort: '4-8 hours', completed: false },
      { step: 2, action: 'Implement security finding tracking and remediation workflow', priority: 'high', effort: '8-16 hours', completed: false },
      { step: 3, action: 'Update vulnerable dependencies (lodash, express)', priority: 'high', effort: '2-4 hours', completed: false }
    ],
    findings: ['lodash vulnerability CVE-2021-23337 unpatched', 'express vulnerability CVE-2024-29041 unpatched', 'No automated vulnerability remediation process'],
    notes: 'Multiple known vulnerabilities in dependencies. Need structured remediation process.'
  },
  {
    id: 'SI.L1-3.14.2',
    title: 'Malicious Code Protection',
    status: 'compliant',
    description: 'Provide protection from malicious code at appropriate locations.',
    requirement: 'J.O.E. should protect against malicious code execution.',
    domain: 'System & Information Integrity',
    nistRef: 'NIST SP 800-171 3.14.2',
    assessmentDate: new Date(Date.now() - 86400000).toISOString(),
    evidence: [
      { type: 'technical', description: 'No arbitrary code execution features', status: 'collected' },
      { type: 'technical', description: 'AI responses displayed as text only', status: 'collected', file: 'src/renderer/views/AiChatView.tsx' }
    ],
    remediations: [],
    findings: [],
    notes: 'AI chat displays responses as text without code execution capabilities.'
  },
  {
    id: 'SI.L1-3.14.4',
    title: 'Security Alerts',
    status: 'partially-compliant',
    description: 'Update malicious code protection mechanisms when new releases are available.',
    requirement: 'J.O.E. should notify users of security updates and patches.',
    domain: 'System & Information Integrity',
    nistRef: 'NIST SP 800-171 3.14.4',
    assessmentDate: new Date(Date.now() - 172800000).toISOString(),
    evidence: [
      { type: 'technical', description: 'Dashboard displays security findings', status: 'collected', file: 'src/renderer/views/DashboardView.tsx' },
      { type: 'process', description: 'Auto-update mechanism', status: 'missing' }
    ],
    remediations: [
      { step: 1, action: 'Implement Electron auto-updater for security patches', priority: 'medium', effort: '8-16 hours', completed: false },
      { step: 2, action: 'Add update notification system', priority: 'low', effort: '4-8 hours', completed: false }
    ],
    findings: ['No auto-update mechanism for security patches'],
    notes: 'Security findings are displayed but no automated update mechanism exists.'
  }
];

export default function ComplianceView() {
  const [selectedControl, setSelectedControl] = useState<Control | null>(null);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showReEvaluateModal, setShowReEvaluateModal] = useState(false);
  const [exportFormat, setExportFormat] = useState<'pdf' | 'csv' | 'json'>('pdf');
  const [filter, setFilter] = useState<'all' | 'compliant' | 'partial' | 'non-compliant'>('all');
  const [isEvaluating, setIsEvaluating] = useState(false);

  const getStatusConfig = (status: string) => {
    switch (status) {
      case 'compliant':
        return { icon: CheckCircle, color: 'text-dws-green', bg: 'bg-dws-green/10', border: 'border-dws-green/30', label: 'Compliant' };
      case 'partially-compliant':
        return { icon: AlertCircle, color: 'text-alert-warning', bg: 'bg-alert-warning/10', border: 'border-alert-warning/30', label: 'Partial' };
      case 'non-compliant':
        return { icon: XCircle, color: 'text-alert-critical', bg: 'bg-alert-critical/10', border: 'border-alert-critical/30', label: 'Non-Compliant' };
      default:
        return { icon: HelpCircle, color: 'text-gray-500', bg: 'bg-gray-500/10', border: 'border-gray-500/30', label: 'Not Assessed' };
    }
  };

  const getEvidenceIcon = (type: Evidence['type']) => {
    switch (type) {
      case 'policy': return FileText;
      case 'technical': return Shield;
      case 'process': return Target;
      case 'audit': return Eye;
    }
  };

  const filteredControls = joeControls.filter(control => {
    if (filter === 'all') return true;
    if (filter === 'compliant') return control.status === 'compliant';
    if (filter === 'partial') return control.status === 'partially-compliant';
    if (filter === 'non-compliant') return control.status === 'non-compliant';
    return true;
  });

  const compliantCount = joeControls.filter(c => c.status === 'compliant').length;
  const partialCount = joeControls.filter(c => c.status === 'partially-compliant').length;
  const nonCompliantCount = joeControls.filter(c => c.status === 'non-compliant').length;
  const score = Math.round((compliantCount + partialCount * 0.5) / joeControls.length * 100);

  const handleReEvaluate = () => {
    setIsEvaluating(true);
    setShowReEvaluateModal(false);
    // Simulate re-evaluation
    setTimeout(() => {
      setIsEvaluating(false);
    }, 3000);
  };

  const formatDate = (isoString: string) => {
    return new Date(isoString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-joe-blue/10 border border-joe-blue/30">
            <ClipboardCheck className="text-joe-blue" size={28} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-white">CMMC 2.0 Compliance Matrix</h1>
            <p className="text-gray-400 mt-1">J.O.E. DevSecOps Arsenal Self-Assessment • Level 1 Foundational</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowExportModal(true)}
            className="btn-secondary flex items-center gap-2"
          >
            <Download size={16} />
            Export Report
          </button>
          <button
            onClick={() => setShowReEvaluateModal(true)}
            disabled={isEvaluating}
            className="btn-primary flex items-center gap-2"
          >
            <RefreshCw size={16} className={isEvaluating ? 'animate-spin' : ''} />
            {isEvaluating ? 'Evaluating...' : 'Re-evaluate'}
          </button>
        </div>
      </div>

      {/* Score Overview */}
      <div className="grid grid-cols-4 gap-4">
        <motion.button
          onClick={() => setFilter('all')}
          className={`glass-card p-6 col-span-1 text-left transition-all ${filter === 'all' ? 'ring-2 ring-joe-blue' : ''}`}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
        >
          <div className="text-center">
            <motion.p
              className="text-5xl font-bold text-joe-blue"
              initial={{ opacity: 0, scale: 0.5 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ type: 'spring', delay: 0.1 }}
            >
              {score}%
            </motion.p>
            <p className="text-gray-400 mt-2">Compliance Score</p>
            <div className="mt-3 h-2 bg-dws-dark rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-joe-blue to-dws-green"
                initial={{ width: 0 }}
                animate={{ width: `${score}%` }}
                transition={{ duration: 1, delay: 0.3 }}
              />
            </div>
          </div>
        </motion.button>

        <motion.button
          onClick={() => setFilter('compliant')}
          className={`glass-card p-4 flex items-center gap-4 transition-all ${filter === 'compliant' ? 'ring-2 ring-dws-green' : ''}`}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
        >
          <div className="p-3 rounded-lg bg-dws-green/10">
            <CheckCircle className="text-dws-green" size={24} />
          </div>
          <div>
            <p className="text-2xl font-bold text-white">{compliantCount}</p>
            <p className="text-gray-400 text-sm">Compliant</p>
          </div>
        </motion.button>

        <motion.button
          onClick={() => setFilter('partial')}
          className={`glass-card p-4 flex items-center gap-4 transition-all ${filter === 'partial' ? 'ring-2 ring-alert-warning' : ''}`}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
        >
          <div className="p-3 rounded-lg bg-alert-warning/10">
            <AlertCircle className="text-alert-warning" size={24} />
          </div>
          <div>
            <p className="text-2xl font-bold text-white">{partialCount}</p>
            <p className="text-gray-400 text-sm">Partial</p>
          </div>
        </motion.button>

        <motion.button
          onClick={() => setFilter('non-compliant')}
          className={`glass-card p-4 flex items-center gap-4 transition-all ${filter === 'non-compliant' ? 'ring-2 ring-alert-critical' : ''}`}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
        >
          <div className="p-3 rounded-lg bg-alert-critical/10">
            <XCircle className="text-alert-critical" size={24} />
          </div>
          <div>
            <p className="text-2xl font-bold text-white">{nonCompliantCount}</p>
            <p className="text-gray-400 text-sm">Non-Compliant</p>
          </div>
        </motion.button>
      </div>

      {/* Controls List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Control Assessment</h2>
          <span className="text-gray-500 text-sm">
            Showing {filteredControls.length} of {joeControls.length} controls
          </span>
        </div>

        <AnimatePresence mode="popLayout">
          {filteredControls.map((control, index) => {
            const config = getStatusConfig(control.status);
            const Icon = config.icon;

            return (
              <motion.button
                key={control.id}
                layout
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 10 }}
                transition={{ delay: index * 0.03 }}
                onClick={() => setSelectedControl(control)}
                className="w-full glass-card p-4 flex items-center gap-4 hover:bg-dws-elevated transition-colors group text-left"
              >
                <div className={`p-2 rounded-lg ${config.bg} border ${config.border}`}>
                  <Icon size={20} className={config.color} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-joe-blue text-sm">{control.id}</span>
                    <span className="text-white font-medium truncate">{control.title}</span>
                  </div>
                  <p className="text-gray-500 text-sm mt-1 truncate">{control.description}</p>
                  <div className="flex items-center gap-4 mt-2">
                    <span className="text-xs text-gray-600">{control.domain}</span>
                    {control.findings.length > 0 && (
                      <span className="text-xs text-alert-critical flex items-center gap-1">
                        <AlertTriangle size={12} />
                        {control.findings.length} finding{control.findings.length > 1 ? 's' : ''}
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`badge ${
                    control.status === 'compliant' ? 'badge-low' :
                    control.status === 'partially-compliant' ? 'badge-medium' : 'badge-critical'
                  }`}>
                    {config.label}
                  </span>
                  <ChevronRight className="text-gray-600 group-hover:text-joe-blue transition-colors" size={20} />
                </div>
              </motion.button>
            );
          })}
        </AnimatePresence>
      </div>

      {/* Control Detail Modal */}
      <Modal
        isOpen={!!selectedControl}
        onClose={() => setSelectedControl(null)}
        title={selectedControl?.title}
        subtitle={`${selectedControl?.id} | ${selectedControl?.domain}`}
        size="xl"
        headerIcon={<Shield size={24} />}
        variant={
          selectedControl?.status === 'compliant' ? 'success' :
          selectedControl?.status === 'non-compliant' ? 'critical' : 'warning'
        }
        footer={
          <div className="flex items-center justify-between">
            <a
              href={`https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-joe-blue text-sm flex items-center gap-1 hover:underline"
            >
              View NIST SP 800-171 <ExternalLink size={14} />
            </a>
            <div className="flex items-center gap-3">
              <button onClick={() => setSelectedControl(null)} className="btn-secondary">
                Close
              </button>
              {selectedControl?.status !== 'compliant' && (
                <button className="btn-primary flex items-center gap-2">
                  <Wrench size={16} />
                  Start Remediation
                </button>
              )}
            </div>
          </div>
        }
      >
        {selectedControl && (
          <div className="space-y-6">
            {/* Status and Assessment Info */}
            <div className="flex items-center gap-4">
              <span className={`px-3 py-1 text-sm rounded-full border ${getStatusConfig(selectedControl.status).bg} ${getStatusConfig(selectedControl.status).color} ${getStatusConfig(selectedControl.status).border}`}>
                {getStatusConfig(selectedControl.status).label}
              </span>
              <span className="text-gray-500 text-sm flex items-center gap-1">
                <Clock size={14} />
                Last assessed: {formatDate(selectedControl.assessmentDate)}
              </span>
            </div>

            {/* Requirement */}
            <div>
              <h4 className="font-semibold text-white mb-2 flex items-center gap-2">
                <BookOpen size={16} className="text-joe-blue" />
                Requirement
              </h4>
              <p className="text-gray-300">{selectedControl.requirement}</p>
              <p className="text-gray-500 text-sm mt-2">Reference: {selectedControl.nistRef}</p>
            </div>

            {/* Evidence */}
            <div>
              <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                <FileText size={16} className="text-joe-blue" />
                Evidence ({selectedControl.evidence.length})
              </h4>
              <div className="space-y-2">
                {selectedControl.evidence.map((ev, i) => {
                  const EvIcon = getEvidenceIcon(ev.type);
                  return (
                    <div key={i} className="flex items-center gap-3 p-3 bg-dws-dark rounded-lg">
                      <EvIcon size={16} className="text-gray-400" />
                      <div className="flex-1">
                        <p className="text-gray-300 text-sm">{ev.description}</p>
                        {ev.file && (
                          <p className="text-joe-blue text-xs font-mono mt-1">{ev.file}</p>
                        )}
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        ev.status === 'collected' ? 'bg-dws-green/10 text-dws-green' :
                        ev.status === 'pending' ? 'bg-alert-warning/10 text-alert-warning' :
                        'bg-alert-critical/10 text-alert-critical'
                      }`}>
                        {ev.status}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Findings */}
            {selectedControl.findings.length > 0 && (
              <div>
                <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                  <AlertTriangle size={16} className="text-alert-critical" />
                  Findings ({selectedControl.findings.length})
                </h4>
                <div className="space-y-2">
                  {selectedControl.findings.map((finding, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 bg-alert-critical/10 border border-alert-critical/30 rounded-lg">
                      <XCircle size={16} className="text-alert-critical flex-shrink-0" />
                      <p className="text-gray-300 text-sm">{finding}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Remediations */}
            {selectedControl.remediations.length > 0 && (
              <div>
                <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                  <Wrench size={16} className="text-dws-green" />
                  Remediation Steps
                </h4>
                <div className="space-y-2">
                  {selectedControl.remediations.map((rem) => (
                    <div key={rem.step} className="flex items-start gap-3 p-3 bg-dws-dark rounded-lg">
                      <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                        rem.completed ? 'bg-dws-green text-white' : 'bg-dws-elevated text-gray-400'
                      }`}>
                        {rem.step}
                      </span>
                      <div className="flex-1">
                        <p className="text-gray-300 text-sm">{rem.action}</p>
                        <div className="flex items-center gap-3 mt-1">
                          <span className={`text-xs ${
                            rem.priority === 'high' ? 'text-alert-critical' :
                            rem.priority === 'medium' ? 'text-alert-warning' : 'text-gray-500'
                          }`}>
                            {rem.priority.toUpperCase()} priority
                          </span>
                          <span className="text-xs text-gray-600">Est. {rem.effort}</span>
                        </div>
                      </div>
                      {rem.completed && (
                        <CheckCircle size={16} className="text-dws-green" />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Notes */}
            {selectedControl.notes && (
              <div className="p-4 bg-joe-blue/10 border border-joe-blue/30 rounded-lg">
                <h4 className="font-semibold text-joe-blue mb-2">Assessment Notes</h4>
                <p className="text-gray-300 text-sm">{selectedControl.notes}</p>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* Export Modal */}
      <Modal
        isOpen={showExportModal}
        onClose={() => setShowExportModal(false)}
        title="Export Compliance Report"
        subtitle="Generate CMMC 2.0 assessment documentation"
        size="md"
        headerIcon={<Download size={24} />}
        variant="info"
        footer={
          <div className="flex items-center justify-end gap-3">
            <button onClick={() => setShowExportModal(false)} className="btn-secondary">
              Cancel
            </button>
            <button
              onClick={() => setShowExportModal(false)}
              className="btn-primary flex items-center gap-2"
            >
              <Download size={16} />
              Export Report
            </button>
          </div>
        }
      >
        <div className="space-y-4">
          <p className="text-gray-300">
            Generate a comprehensive CMMC 2.0 Level 1 compliance report for the J.O.E. DevSecOps Arsenal.
          </p>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Export Format</label>
            <div className="grid grid-cols-3 gap-3">
              {(['pdf', 'csv', 'json'] as const).map(format => (
                <button
                  key={format}
                  onClick={() => setExportFormat(format)}
                  className={`p-3 rounded-lg border transition-colors ${
                    exportFormat === format
                      ? 'bg-joe-blue/10 border-joe-blue text-joe-blue'
                      : 'bg-dws-dark border-dws-border text-gray-400 hover:border-gray-500'
                  }`}
                >
                  <p className="font-medium uppercase">{format}</p>
                  <p className="text-xs mt-1">
                    {format === 'pdf' && 'Full report'}
                    {format === 'csv' && 'Spreadsheet'}
                    {format === 'json' && 'Machine readable'}
                  </p>
                </button>
              ))}
            </div>
          </div>

          <div className="p-4 bg-dws-dark rounded-lg">
            <h4 className="font-medium text-white mb-2">Report Contents</h4>
            <ul className="text-sm text-gray-400 space-y-1">
              <li className="flex items-center gap-2">
                <CheckCircle size={14} className="text-dws-green" />
                Executive Summary & Score
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle size={14} className="text-dws-green" />
                Control-by-Control Assessment
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle size={14} className="text-dws-green" />
                Evidence Documentation
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle size={14} className="text-dws-green" />
                Remediation Roadmap
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle size={14} className="text-dws-green" />
                Risk Assessment Summary
              </li>
            </ul>
          </div>
        </div>
      </Modal>

      {/* Re-evaluate Confirmation Modal */}
      <ConfirmModal
        isOpen={showReEvaluateModal}
        onClose={() => setShowReEvaluateModal(false)}
        onConfirm={handleReEvaluate}
        title="Re-evaluate Compliance"
        message="This will run a fresh CMMC 2.0 assessment against the J.O.E. DevSecOps Arsenal codebase. This may take several minutes to complete."
        confirmText="Start Evaluation"
        cancelText="Cancel"
        variant="info"
      />
    </div>
  );
}
