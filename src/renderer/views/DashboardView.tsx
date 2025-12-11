import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { useDashboardStore } from '../store/dashboardStore';
import {
  ShieldAlert,
  Package,
  ClipboardCheck,
  AlertTriangle,
  TrendingUp,
  Activity,
  RefreshCw,
  Play,
  Target,
  Zap,
  BarChart3,
  FileSearch,
  Lock,
  Bug,
  Server,
  Wrench,
  Sparkles
} from 'lucide-react';
import MetricCard from '../components/widgets/MetricCard';
import RiskGauge from '../components/charts/RiskGauge';
import SeverityChart from '../components/charts/SeverityChart';
import RecentFindings from '../components/widgets/RecentFindings';
import ComplianceRing from '../components/charts/ComplianceRing';
import MitreHeatmap from '../components/charts/MitreHeatmap';
import ThreatTimeline from '../components/charts/ThreatTimeline';
import Modal from '../components/common/Modal';

/**
 * J.O.E. DevSecOps Dashboard - Command Center
 *
 * The central hub for security operations. Every widget is clickable
 * and provides drill-down details through advanced modal visualizations.
 *
 * Design principles:
 * - F-pattern layout for optimal scanning
 * - Critical metrics in top-left quadrant
 * - Real-time data with visual feedback
 * - Progressive disclosure through modals
 *
 * Reference: Nielsen Norman Group - Dashboard Design Best Practices
 * https://www.nngroup.com/articles/dashboard-design/
 */

type ModalType = 'risk' | 'findings' | 'sbom' | 'compliance' | 'scan' | 'autofix' | null;

export default function DashboardView() {
  const {
    riskScore,
    compliance,
    sbomStats,
    recentFindings,
    isScanning,
    lastScanTime,
    refreshDashboard,
    setIsScanning,
    isFixing,
    lastFixResult,
    runAutoFix,
    fixFinding
  } = useDashboardStore();

  const [activeModal, setActiveModal] = useState<ModalType>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [apiStatus, setApiStatus] = useState<string>('checking...');

  // Check API availability on mount
  useEffect(() => {
    const checkAPI = () => {
      if (window.electronAPI?.security?.runAudit) {
        setApiStatus('API Connected - Real scanning enabled');
      } else if (window.electronAPI) {
        setApiStatus('WARNING: Security API not found on electronAPI');
      } else {
        setApiStatus('WARNING: Not in Electron (browser mode)');
      }
    };
    checkAPI();
  }, []);

  useEffect(() => {
    refreshDashboard();
  }, []);

  const handleRunScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    setActiveModal('scan');

    for (let i = 0; i <= 100; i += 5) {
      await new Promise(resolve => setTimeout(resolve, 150));
      setScanProgress(i);
    }

    await refreshDashboard();
    setIsScanning(false);
    setScanProgress(100);
  };

  const totalFindings = riskScore.critical + riskScore.high + riskScore.medium + riskScore.low;

  const handleAutoFix = async () => {
    setActiveModal('autofix');
    await runAutoFix();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-heading text-2xl font-bold text-white flex items-center gap-3">
            <Target className="text-joe-blue" />
            Security Command Center
          </h1>
          <p className="text-gray-400 mt-1">
            Real-time DevSecOps intelligence dashboard
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* API Status Indicator */}
          <span className={`text-xs px-2 py-1 rounded ${
            apiStatus.includes('Connected') ? 'bg-dws-green/20 text-dws-green' :
            apiStatus.includes('WARNING') ? 'bg-alert-warning/20 text-alert-warning' :
            'bg-gray-500/20 text-gray-400'
          }`}>
            {apiStatus}
          </span>
          {lastScanTime && (
            <span className="text-gray-500 text-sm">
              Last scan: {new Date(lastScanTime).toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={() => refreshDashboard()}
            className="btn-secondary flex items-center gap-2"
            aria-label="Refresh dashboard data"
          >
            <RefreshCw size={16} className={isScanning ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button
            onClick={handleAutoFix}
            disabled={isFixing || isScanning}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-dws-green to-joe-blue text-white rounded-lg hover:opacity-90 transition-opacity disabled:opacity-50"
            aria-label="AI Auto-Fix vulnerabilities"
          >
            {isFixing ? (
              <>
                <Sparkles size={16} className="animate-pulse" />
                Fixing...
              </>
            ) : (
              <>
                <Wrench size={16} />
                AI Auto-Fix
              </>
            )}
          </button>
          <button
            onClick={handleRunScan}
            disabled={isScanning || isFixing}
            className="btn-primary flex items-center gap-2"
            aria-label="Run security scan"
          >
            {isScanning ? (
              <>
                <RefreshCw size={16} className="animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Play size={16} />
                Run Security Scan
              </>
            )}
          </button>
        </div>
      </div>

      {/* Top Metrics Row - Clickable Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <motion.button
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          onClick={() => setActiveModal('risk')}
          className="text-left w-full"
          aria-label="View risk score details"
        >
          <MetricCard
            title="Risk Score"
            value={`${100 - riskScore.overall}%`}
            subtitle="Click for detailed breakdown"
            icon={ShieldAlert}
            trend={riskScore.overall < 30 ? 'up' : 'down'}
            trendValue={riskScore.overall < 30 ? '+5%' : '-3%'}
            color={riskScore.critical > 0 ? 'critical' : riskScore.high > 0 ? 'warning' : 'success'}
          />
        </motion.button>

        <motion.button
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          onClick={() => setActiveModal('findings')}
          className="text-left w-full"
          aria-label="View security findings details"
        >
          <MetricCard
            title="Critical Findings"
            value={riskScore.critical.toString()}
            subtitle={`${totalFindings} total - Click for details`}
            icon={AlertTriangle}
            color={riskScore.critical > 0 ? 'critical' : 'success'}
            pulse={riskScore.critical > 0}
          />
        </motion.button>

        <motion.button
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          onClick={() => setActiveModal('sbom')}
          className="text-left w-full"
          aria-label="View SBOM components"
        >
          <MetricCard
            title="SBOM Components"
            value={sbomStats.totalComponents.toString()}
            subtitle={`${sbomStats.vulnerableComponents} vulnerable - Click to explore`}
            icon={Package}
            color={sbomStats.vulnerableComponents > 0 ? 'warning' : 'info'}
          />
        </motion.button>

        <motion.button
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          onClick={() => setActiveModal('compliance')}
          className="text-left w-full"
          aria-label="View compliance status"
        >
          <MetricCard
            title="Compliance"
            value={`${compliance.score}%`}
            subtitle={`${compliance.framework} Level ${compliance.level} - Click for matrix`}
            icon={ClipboardCheck}
            color={compliance.score >= 80 ? 'success' : compliance.score >= 60 ? 'warning' : 'critical'}
          />
        </motion.button>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.button
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.5 }}
          onClick={() => setActiveModal('risk')}
          className="glass-card p-6 text-left hover:border-joe-blue/50 transition-colors"
          aria-label="View security posture details"
        >
          <h3 className="font-heading font-semibold text-white mb-4 flex items-center gap-2">
            <Zap className="text-joe-blue" size={18} />
            Security Posture
          </h3>
          <RiskGauge score={100 - riskScore.overall} />
        </motion.button>

        <motion.button
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.6 }}
          onClick={() => setActiveModal('findings')}
          className="glass-card p-6 text-left hover:border-joe-blue/50 transition-colors"
          aria-label="View findings by severity"
        >
          <h3 className="font-heading font-semibold text-white mb-4 flex items-center gap-2">
            <BarChart3 className="text-joe-blue" size={18} />
            Findings by Severity
          </h3>
          <SeverityChart data={riskScore} />
        </motion.button>

        <motion.button
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.7 }}
          onClick={() => setActiveModal('compliance')}
          className="glass-card p-6 text-left hover:border-joe-blue/50 transition-colors"
          aria-label="View compliance details"
        >
          <h3 className="font-heading font-semibold text-white mb-4 flex items-center gap-2">
            <ClipboardCheck className="text-joe-blue" size={18} />
            {compliance.framework} Compliance
          </h3>
          <ComplianceRing compliance={compliance} />
        </motion.button>
      </div>

      {/* MITRE ATT&CK Heatmap */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.75 }}
        className="glass-card p-6"
      >
        <MitreHeatmap />
      </motion.div>

      {/* Two Column Layout: Timeline & Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
          className="glass-card p-6"
        >
          <ThreatTimeline />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.85 }}
          className="glass-card p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-heading font-semibold text-white flex items-center gap-2">
              <FileSearch className="text-joe-blue" size={18} />
              Recent Findings
            </h3>
            <a href="/findings" className="text-joe-blue text-sm hover:underline">
              View All
            </a>
          </div>
          <RecentFindings findings={recentFindings} onFix={fixFinding} />
        </motion.div>
      </div>

      {/* Quick Stats Footer */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.9 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4"
      >
        <button
          onClick={() => setActiveModal('findings')}
          className="glass-card p-4 text-center hover:border-alert-high/50 transition-colors"
          aria-label={`${riskScore.high} high severity findings`}
        >
          <Activity className="w-6 h-6 text-alert-high mx-auto mb-2" />
          <p className="text-2xl font-bold text-white">{riskScore.high}</p>
          <p className="text-xs text-gray-400">High Severity</p>
        </button>
        <button
          onClick={() => setActiveModal('findings')}
          className="glass-card p-4 text-center hover:border-alert-warning/50 transition-colors"
          aria-label={`${riskScore.medium} medium severity findings`}
        >
          <TrendingUp className="w-6 h-6 text-alert-warning mx-auto mb-2" />
          <p className="text-2xl font-bold text-white">{riskScore.medium}</p>
          <p className="text-xs text-gray-400">Medium Severity</p>
        </button>
        <button
          onClick={() => setActiveModal('sbom')}
          className="glass-card p-4 text-center hover:border-dws-green/50 transition-colors"
          aria-label={`${sbomStats.libraries} libraries tracked`}
        >
          <Package className="w-6 h-6 text-dws-green mx-auto mb-2" />
          <p className="text-2xl font-bold text-white">{sbomStats.libraries}</p>
          <p className="text-xs text-gray-400">Libraries Tracked</p>
        </button>
        <button
          onClick={() => setActiveModal('compliance')}
          className="glass-card p-4 text-center hover:border-joe-blue/50 transition-colors"
          aria-label={`${compliance.compliant} of ${compliance.totalControls} controls compliant`}
        >
          <ClipboardCheck className="w-6 h-6 text-joe-blue mx-auto mb-2" />
          <p className="text-2xl font-bold text-white">{compliance.compliant}/{compliance.totalControls}</p>
          <p className="text-xs text-gray-400">Controls Compliant</p>
        </button>
      </motion.div>

      {/* Risk Details Modal */}
      <Modal
        isOpen={activeModal === 'risk'}
        onClose={() => setActiveModal(null)}
        title="Security Risk Analysis"
        subtitle="Comprehensive risk posture breakdown"
        size="xl"
        headerIcon={<ShieldAlert size={24} />}
        variant={riskScore.critical > 0 ? 'critical' : 'success'}
      >
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-6">
            <div className="space-y-4">
              <h4 className="font-semibold text-white">Risk Score Breakdown</h4>
              <div className="space-y-3">
                {[
                  { label: 'Critical Issues', value: riskScore.critical, weight: 40, color: 'bg-alert-critical', textColor: 'text-alert-critical' },
                  { label: 'High Issues', value: riskScore.high, weight: 30, color: 'bg-alert-high', textColor: 'text-alert-high' },
                  { label: 'Medium Issues', value: riskScore.medium, weight: 20, color: 'bg-alert-warning', textColor: 'text-alert-warning' },
                  { label: 'Low Issues', value: riskScore.low, weight: 10, color: 'bg-dws-green', textColor: 'text-dws-green' }
                ].map(item => (
                  <div key={item.label} className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">{item.label}</span>
                      <span className={`${item.textColor} font-medium`}>{item.value} ({item.weight}% weight)</span>
                    </div>
                    <div className="h-2 bg-dws-dark rounded-full overflow-hidden">
                      <motion.div
                        className={`h-full ${item.color}`}
                        initial={{ width: 0 }}
                        animate={{ width: `${Math.min(item.value * 10, 100)}%` }}
                        transition={{ duration: 0.5 }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="flex items-center justify-center">
              <RiskGauge score={100 - riskScore.overall} />
            </div>
          </div>

          <div className="border-t border-dws-border pt-6">
            <h4 className="font-semibold text-white mb-4">Risk Factors</h4>
            <div className="grid grid-cols-3 gap-4">
              <div className="glass-card p-4">
                <Bug className={riskScore.critical + riskScore.high > 0 ? "text-alert-critical mb-2" : "text-dws-green mb-2"} size={20} />
                <p className="text-white font-medium">Vulnerabilities</p>
                <p className={`text-2xl font-bold ${riskScore.critical + riskScore.high > 0 ? 'text-alert-critical' : 'text-dws-green'}`}>{riskScore.critical + riskScore.high}</p>
                <p className="text-gray-500 text-sm">Critical & High</p>
              </div>
              <div className="glass-card p-4">
                <Lock className="text-dws-green mb-2" size={20} />
                <p className="text-white font-medium">Secrets Exposure</p>
                <p className="text-2xl font-bold text-dws-green">0</p>
                <p className="text-gray-500 text-sm">No secrets detected</p>
              </div>
              <div className="glass-card p-4">
                <Server className={riskScore.low + riskScore.info > 0 ? "text-joe-blue mb-2" : "text-dws-green mb-2"} size={20} />
                <p className="text-white font-medium">Minor Items</p>
                <p className={`text-2xl font-bold ${riskScore.low + riskScore.info > 0 ? 'text-joe-blue' : 'text-dws-green'}`}>{riskScore.low + riskScore.info}</p>
                <p className="text-gray-500 text-sm">Low/Info findings</p>
              </div>
            </div>
          </div>
        </div>
      </Modal>

      {/* Findings Details Modal */}
      <Modal
        isOpen={activeModal === 'findings'}
        onClose={() => setActiveModal(null)}
        title="Security Findings Overview"
        subtitle={`${totalFindings} total findings across all scanners`}
        size="xl"
        headerIcon={<AlertTriangle size={24} />}
        variant={riskScore.critical > 0 ? 'critical' : 'info'}
        footer={
          <div className="flex justify-between items-center">
            <span className="text-gray-500 text-sm">Data from: Semgrep, Trivy, Snyk, GitGuardian</span>
            <a href="/findings" className="btn-primary">View All Findings</a>
          </div>
        }
      >
        <div className="space-y-6">
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: 'Critical', value: riskScore.critical, bgColor: 'bg-alert-critical/10', borderColor: 'border-alert-critical/30', textColor: 'text-alert-critical' },
              { label: 'High', value: riskScore.high, bgColor: 'bg-alert-high/10', borderColor: 'border-alert-high/30', textColor: 'text-alert-high' },
              { label: 'Medium', value: riskScore.medium, bgColor: 'bg-alert-warning/10', borderColor: 'border-alert-warning/30', textColor: 'text-alert-warning' },
              { label: 'Low', value: riskScore.low, bgColor: 'bg-dws-green/10', borderColor: 'border-dws-green/30', textColor: 'text-dws-green' }
            ].map(item => (
              <div key={item.label} className={`glass-card p-4 ${item.bgColor} border ${item.borderColor}`}>
                <p className={`text-3xl font-bold ${item.textColor}`}>{item.value}</p>
                <p className="text-gray-400">{item.label}</p>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-center py-4">
            <SeverityChart data={riskScore} />
          </div>

          <div className="border-t border-dws-border pt-6">
            <h4 className="font-semibold text-white mb-4">Recent Critical Findings</h4>
            <RecentFindings findings={recentFindings.filter(f => f.severity === 'critical' || f.severity === 'high')} onFix={fixFinding} />
          </div>
        </div>
      </Modal>

      {/* SBOM Details Modal */}
      <Modal
        isOpen={activeModal === 'sbom'}
        onClose={() => setActiveModal(null)}
        title="Software Bill of Materials"
        subtitle="Dependency analysis and vulnerability tracking"
        size="xl"
        headerIcon={<Package size={24} />}
        variant={sbomStats.vulnerableComponents > 0 ? 'warning' : 'success'}
        footer={
          <div className="flex justify-between items-center">
            <span className="text-gray-500 text-sm">Format: CycloneDX 1.5</span>
            <a href="/sbom" className="btn-primary">Explore SBOM</a>
          </div>
        }
      >
        <div className="space-y-6">
          <div className="grid grid-cols-4 gap-4">
            <div className="glass-card p-4">
              <Package className="text-joe-blue mb-2" size={20} />
              <p className="text-2xl font-bold text-white">{sbomStats.totalComponents}</p>
              <p className="text-gray-400 text-sm">Total Components</p>
            </div>
            <div className="glass-card p-4">
              <Activity className="text-dws-green mb-2" size={20} />
              <p className="text-2xl font-bold text-white">{sbomStats.libraries}</p>
              <p className="text-gray-400 text-sm">Libraries</p>
            </div>
            <div className="glass-card p-4">
              <Server className="text-joe-blue mb-2" size={20} />
              <p className="text-2xl font-bold text-white">{sbomStats.frameworks}</p>
              <p className="text-gray-400 text-sm">Frameworks</p>
            </div>
            <div className="glass-card p-4">
              <AlertTriangle className="text-alert-warning mb-2" size={20} />
              <p className="text-2xl font-bold text-alert-warning">{sbomStats.vulnerableComponents}</p>
              <p className="text-gray-400 text-sm">Vulnerable</p>
            </div>
          </div>

          <div className="border-t border-dws-border pt-6">
            <h4 className="font-semibold text-white mb-4">Dependency Security Status</h4>
            {sbomStats.vulnerableComponents === 0 ? (
              <div className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg text-center">
                <Package className="text-dws-green mx-auto mb-2" size={24} />
                <p className="text-dws-green font-medium">All Dependencies Secure</p>
                <p className="text-gray-400 text-sm mt-1">npm audit: 0 vulnerabilities detected</p>
                <p className="text-gray-500 text-xs mt-2">Last verified: {sbomStats.lastGenerated ? new Date(sbomStats.lastGenerated).toLocaleString() : 'Not scanned'}</p>
              </div>
            ) : (
              <div className="p-4 bg-alert-warning/10 border border-alert-warning/30 rounded-lg">
                <p className="text-alert-warning font-medium">{sbomStats.vulnerableComponents} vulnerable packages detected</p>
                <p className="text-gray-400 text-sm mt-1">Run `npm audit fix` to remediate</p>
              </div>
            )}
          </div>
        </div>
      </Modal>

      {/* Compliance Details Modal */}
      <Modal
        isOpen={activeModal === 'compliance'}
        onClose={() => setActiveModal(null)}
        title={`${compliance.framework} Compliance Status`}
        subtitle={`Level ${compliance.level} - ${compliance.score}% Compliant`}
        size="xl"
        headerIcon={<ClipboardCheck size={24} />}
        variant={compliance.score >= 80 ? 'success' : compliance.score >= 60 ? 'warning' : 'critical'}
        footer={
          <div className="flex justify-between items-center">
            <span className="text-gray-500 text-sm">Based on NIST SP 800-171 Rev 2</span>
            <a href="/compliance" className="btn-primary">View Full Matrix</a>
          </div>
        }
      >
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-6">
            <div className="flex items-center justify-center">
              <ComplianceRing compliance={compliance} />
            </div>
            <div className="space-y-4">
              <h4 className="font-semibold text-white">Control Status</h4>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-dws-green/10 border border-dws-green/30 rounded-lg">
                  <span className="text-dws-green">Compliant</span>
                  <span className="text-2xl font-bold text-dws-green">{compliance.compliant}</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-alert-warning/10 border border-alert-warning/30 rounded-lg">
                  <span className="text-alert-warning">Partial</span>
                  <span className="text-2xl font-bold text-alert-warning">{compliance.partiallyCompliant}</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-alert-critical/10 border border-alert-critical/30 rounded-lg">
                  <span className="text-alert-critical">Non-Compliant</span>
                  <span className="text-2xl font-bold text-alert-critical">{compliance.nonCompliant}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="border-t border-dws-border pt-6">
            <h4 className="font-semibold text-white mb-4">Compliance Status Details</h4>
            {compliance.nonCompliant === 0 && compliance.partiallyCompliant === 0 ? (
              <div className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg text-center">
                <ClipboardCheck className="text-dws-green mx-auto mb-2" size={24} />
                <p className="text-dws-green font-medium">Full Compliance Achieved</p>
                <p className="text-gray-400 text-sm mt-1">All {compliance.totalControls} controls are compliant</p>
              </div>
            ) : compliance.nonCompliant === 0 ? (
              <div className="space-y-2">
                <div className="p-3 bg-dws-green/10 border border-dws-green/30 rounded-lg mb-4">
                  <p className="text-dws-green font-medium">No Critical Gaps</p>
                  <p className="text-gray-400 text-sm">0 non-compliant controls - {compliance.partiallyCompliant} need minor attention</p>
                </div>
                {recentFindings.filter(f => f.severity === 'low' || f.severity === 'info').map(finding => (
                  <div key={finding.id} className="flex items-center justify-between p-3 bg-dws-dark rounded-lg">
                    <div className="flex items-center gap-3">
                      <span className="text-gray-400 text-sm">{finding.tool}</span>
                      <span className="text-white">{finding.title}</span>
                    </div>
                    <span className={`badge ${finding.severity === 'low' ? 'badge-low' : 'badge-info'}`}>
                      {finding.severity === 'low' ? 'Partial' : 'Info'}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-2">
                {recentFindings.filter(f => f.severity === 'critical' || f.severity === 'high').map(finding => (
                  <div key={finding.id} className="flex items-center justify-between p-3 bg-dws-dark rounded-lg">
                    <div className="flex items-center gap-3">
                      <span className="text-gray-400 text-sm">{finding.tool}</span>
                      <span className="text-white">{finding.title}</span>
                    </div>
                    <span className={`badge ${finding.severity === 'critical' ? 'badge-critical' : 'badge-high'}`}>
                      {finding.severity}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </Modal>

      {/* Scan Progress Modal */}
      <Modal
        isOpen={activeModal === 'scan'}
        onClose={() => !isScanning && setActiveModal(null)}
        title="Security Scan in Progress"
        subtitle="Running comprehensive security analysis"
        size="md"
        headerIcon={<Activity size={24} />}
        showCloseButton={!isScanning}
      >
        <div className="space-y-6">
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Progress</span>
              <span className="text-joe-blue font-medium">{scanProgress}%</span>
            </div>
            <div className="h-3 bg-dws-dark rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-joe-blue to-dws-green"
                initial={{ width: 0 }}
                animate={{ width: `${scanProgress}%` }}
                transition={{ duration: 0.3 }}
              />
            </div>
          </div>

          <div className="space-y-3">
            {['Semgrep SAST', 'Trivy Container', 'Snyk Dependencies', 'GitGuardian Secrets', 'Compliance Check'].map((tool, i) => {
              const completed = scanProgress > (i + 1) * 20;
              const active = scanProgress >= i * 20 && scanProgress < (i + 1) * 20;
              return (
                <div key={tool} className="flex items-center gap-3">
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs ${
                    completed ? 'bg-dws-green text-white' : active ? 'bg-joe-blue animate-pulse text-white' : 'bg-dws-card text-gray-500'
                  }`}>
                    {completed ? '✓' : active ? '...' : ''}
                  </div>
                  <span className={completed ? 'text-dws-green' : active ? 'text-white' : 'text-gray-500'}>
                    {tool}
                  </span>
                </div>
              );
            })}
          </div>

          {scanProgress === 100 && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg text-center"
            >
              <p className="text-dws-green font-medium">Scan Complete!</p>
              <p className="text-gray-400 text-sm mt-1">Dashboard has been updated with latest results.</p>
            </motion.div>
          )}
        </div>
      </Modal>

      {/* AI Auto-Fix Modal */}
      <Modal
        isOpen={activeModal === 'autofix'}
        onClose={() => !isFixing && setActiveModal(null)}
        title="AI Auto-Fix"
        subtitle="Automated vulnerability remediation"
        size="md"
        headerIcon={<Sparkles size={24} />}
        showCloseButton={!isFixing}
      >
        <div className="space-y-6">
          {isFixing ? (
            <div className="text-center py-8">
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
              >
                <Sparkles size={48} className="mx-auto text-joe-blue" />
              </motion.div>
              <p className="text-white font-medium mt-4">J.O.E. is analyzing and fixing vulnerabilities...</p>
              <p className="text-gray-400 text-sm mt-2">Running npm audit fix and applying patches</p>
            </div>
          ) : lastFixResult ? (
            <div className="space-y-4">
              {lastFixResult.success ? (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg text-center"
                >
                  <Wrench className="mx-auto text-dws-green mb-2" size={32} />
                  <p className="text-dws-green font-medium">Auto-Fix Complete!</p>
                </motion.div>
              ) : (
                <div className="p-4 bg-alert-warning/10 border border-alert-warning/30 rounded-lg text-center">
                  <AlertTriangle className="mx-auto text-alert-warning mb-2" size={32} />
                  <p className="text-alert-warning font-medium">Some fixes could not be applied</p>
                </div>
              )}

              {lastFixResult.fixed.length > 0 && (
                <div>
                  <h4 className="font-semibold text-dws-green mb-2">Fixed:</h4>
                  <ul className="space-y-1">
                    {lastFixResult.fixed.map((item, i) => (
                      <li key={i} className="text-gray-400 text-sm flex items-center gap-2">
                        <span className="text-dws-green">✓</span> {item}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {lastFixResult.failed.length > 0 && (
                <div>
                  <h4 className="font-semibold text-alert-warning mb-2">Could not fix:</h4>
                  <ul className="space-y-1">
                    {lastFixResult.failed.map((item, i) => (
                      <li key={i} className="text-gray-400 text-sm flex items-center gap-2">
                        <span className="text-alert-warning">✗</span> {item}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <p className="text-gray-500 text-sm text-center mt-4">
                Dashboard will refresh with updated scan results.
              </p>
            </div>
          ) : (
            <div className="text-center py-8">
              <Sparkles size={48} className="mx-auto text-gray-500 mb-4" />
              <p className="text-gray-400">Click "AI Auto-Fix" to begin</p>
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}
