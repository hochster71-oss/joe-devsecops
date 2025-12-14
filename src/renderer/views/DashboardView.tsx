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
  Zap,
  BarChart3,
  FileSearch,
  Lock,
  Bug,
  Server,
  Wrench,
  Sparkles,
  Brain,
  Cpu,
  Network,
  Shield,
  Eye,
  Radar,
  Boxes,
  GitBranch,
  Terminal,
  Fingerprint
} from 'lucide-react';
import RiskGauge from '../components/charts/RiskGauge';
import SeverityChart from '../components/charts/SeverityChart';
import RecentFindings from '../components/widgets/RecentFindings';
import ComplianceRing from '../components/charts/ComplianceRing';
import MitreHeatmap from '../components/charts/MitreHeatmap';
import ThreatTimeline from '../components/charts/ThreatTimeline';
import Modal from '../components/common/Modal';
import AINetworkBackground from '../components/backgrounds/AINetworkBackground';

/**
 * J.O.E. DevSecOps Dashboard - 4K Command Center
 *
 * Advanced AI-powered security operations dashboard with:
 * - 4K resolution support with scalable graphics
 * - Neural network animated background
 * - Real-time threat visualization
 * - Holographic-style UI elements
 */

type ModalType = 'risk' | 'findings' | 'sbom' | 'compliance' | 'scan' | 'autofix' | null;

// Animated counter component for impressive number displays
const _AnimatedCounter = ({ value, duration = 2000 }: { value: number; duration?: number }) => {
  const [count, setCount] = useState(0);

  useEffect(() => {
    let start = 0;
    const end = value;
    const incrementTime = duration / end;
    const timer = setInterval(() => {
      start += 1;
      setCount(start);
      if (start >= end) {clearInterval(timer);}
    }, incrementTime);
    return () => clearInterval(timer);
  }, [value, duration]);

  return <span>{count}</span>;
};

// Glowing orb component for AI status
const AIStatusOrb = ({ active }: { active: boolean }) => (
  <div className="relative">
    <motion.div
      className={`w-4 h-4 rounded-full ${active ? 'bg-joe-blue' : 'bg-gray-600'}`}
      animate={active ? {
        boxShadow: [
          '0 0 20px rgba(0, 180, 216, 0.5)',
          '0 0 40px rgba(0, 180, 216, 0.8)',
          '0 0 20px rgba(0, 180, 216, 0.5)'
        ]
      } : {}}
      transition={{ duration: 2, repeat: Infinity }}
    />
    {active && (
      <motion.div
        className="absolute inset-0 rounded-full bg-joe-blue"
        animate={{ scale: [1, 2, 1], opacity: [0.5, 0, 0.5] }}
        transition={{ duration: 2, repeat: Infinity }}
      />
    )}
  </div>
);

// Holographic card wrapper
const HoloCard = ({ children, className = '', onClick, glow = 'blue' }: {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
  glow?: 'blue' | 'green' | 'red' | 'yellow';
}) => {
  const glowColors = {
    blue: 'hover:shadow-[0_0_30px_rgba(0,180,216,0.3)] border-joe-blue/20 hover:border-joe-blue/50',
    green: 'hover:shadow-[0_0_30px_rgba(34,197,94,0.3)] border-dws-green/20 hover:border-dws-green/50',
    red: 'hover:shadow-[0_0_30px_rgba(239,68,68,0.3)] border-alert-critical/20 hover:border-alert-critical/50',
    yellow: 'hover:shadow-[0_0_30px_rgba(234,179,8,0.3)] border-alert-warning/20 hover:border-alert-warning/50'
  };

  return (
    <motion.div
      whileHover={{ scale: 1.02, y: -2 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className={`
        relative overflow-hidden rounded-2xl
        bg-gradient-to-br from-dws-card/90 to-dws-elevated/90
        backdrop-blur-xl border transition-all duration-300
        ${glowColors[glow]}
        ${onClick ? 'cursor-pointer' : ''}
        ${className}
      `}
    >
      {/* Holographic shimmer effect */}
      <div className="absolute inset-0 opacity-10">
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent -skew-x-12 animate-shimmer" />
      </div>
      {/* Scan line effect */}
      <motion.div
        className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-joe-blue/50 to-transparent"
        animate={{ top: ['0%', '100%'] }}
        transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
      />
      <div className="relative z-10">{children}</div>
    </motion.div>
  );
};

// Large metric display for 4K
const MegaMetric = ({
  icon: Icon,
  value,
  label,
  sublabel,
  trend,
  color = 'blue',
  onClick,
  pulse = false
}: {
  icon: React.ElementType;
  value: string | number;
  label: string;
  sublabel?: string;
  trend?: { value: string; up: boolean };
  color?: 'blue' | 'green' | 'red' | 'yellow';
  onClick?: () => void;
  pulse?: boolean;
}) => {
  const colors = {
    blue: { text: 'text-joe-blue', bg: 'bg-joe-blue/10', glow: 'shadow-joe-blue/20' },
    green: { text: 'text-dws-green', bg: 'bg-dws-green/10', glow: 'shadow-dws-green/20' },
    red: { text: 'text-alert-critical', bg: 'bg-alert-critical/10', glow: 'shadow-alert-critical/20' },
    yellow: { text: 'text-alert-warning', bg: 'bg-alert-warning/10', glow: 'shadow-alert-warning/20' }
  };

  return (
    <HoloCard onClick={onClick} glow={color} className="p-6 lg:p-8">
      <div className="flex items-start justify-between">
        <div className={`p-3 lg:p-4 rounded-xl ${colors[color].bg}`}>
          <Icon className={`w-8 h-8 lg:w-10 lg:h-10 ${colors[color].text}`} />
        </div>
        {trend && (
          <div className={`flex items-center gap-1 text-sm ${trend.up ? 'text-dws-green' : 'text-alert-critical'}`}>
            <TrendingUp className={`w-4 h-4 ${!trend.up && 'rotate-180'}`} />
            {trend.value}
          </div>
        )}
      </div>
      <div className="mt-4 lg:mt-6">
        <motion.div
          className={`text-4xl lg:text-6xl font-bold ${colors[color].text}`}
          animate={pulse ? { opacity: [1, 0.7, 1] } : {}}
          transition={{ duration: 1.5, repeat: Infinity }}
        >
          {value}
        </motion.div>
        <div className="text-lg lg:text-xl text-white font-medium mt-2">{label}</div>
        {sublabel && <div className="text-sm lg:text-base text-gray-500 mt-1">{sublabel}</div>}
      </div>
    </HoloCard>
  );
};

// AI Brain visualization
const AIBrainViz = () => (
  <div className="relative w-full h-32 lg:h-40 flex items-center justify-center">
    <motion.div
      className="absolute w-24 h-24 lg:w-32 lg:h-32 rounded-full bg-joe-blue/5 border border-joe-blue/20"
      animate={{ scale: [1, 1.2, 1], opacity: [0.5, 0.2, 0.5] }}
      transition={{ duration: 3, repeat: Infinity }}
    />
    <motion.div
      className="absolute w-16 h-16 lg:w-24 lg:h-24 rounded-full bg-joe-blue/10 border border-joe-blue/30"
      animate={{ scale: [1, 1.1, 1], opacity: [0.7, 0.4, 0.7] }}
      transition={{ duration: 2, repeat: Infinity }}
    />
    <motion.div
      className="relative z-10 p-4 lg:p-6 rounded-full bg-gradient-to-br from-joe-blue/20 to-dws-green/20 border border-joe-blue/50"
      animate={{ rotate: 360 }}
      transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
    >
      <Brain className="w-8 h-8 lg:w-12 lg:h-12 text-joe-blue" />
    </motion.div>
    {/* Orbiting elements */}
    {[0, 1, 2].map((i) => (
      <motion.div
        key={i}
        className="absolute w-3 h-3 lg:w-4 lg:h-4 rounded-full bg-dws-green"
        style={{ boxShadow: '0 0 10px rgba(34, 197, 94, 0.5)' }}
        animate={{
          rotate: 360,
          x: [Math.cos(i * 2.1) * 50, Math.cos(i * 2.1 + Math.PI) * 50],
          y: [Math.sin(i * 2.1) * 50, Math.sin(i * 2.1 + Math.PI) * 50]
        }}
        transition={{ duration: 4 + i, repeat: Infinity, ease: 'linear' }}
      />
    ))}
  </div>
);

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
  const [aiActive, _setAiActive] = useState(true);
  const [currentTime, setCurrentTime] = useState(new Date());

  // Update time every second
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const checkAPI = () => {
      if (typeof window.electronAPI?.security?.runAudit === 'function') {
        setApiStatus('J.O.E. ONLINE');
      } else if (window.electronAPI) {
        setApiStatus('LIMITED MODE');
      } else {
        setApiStatus('BROWSER MODE');
      }
    };
    checkAPI();
  }, []);

  useEffect(() => {
    refreshDashboard();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRunScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    setActiveModal('scan');

    for (let i = 0; i <= 100; i += 2) {
      await new Promise(resolve => setTimeout(resolve, 80));
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

  const securityScore = 100 - riskScore.overall;

  return (
    <div className="relative min-h-screen">
      {/* AI Neural Network Background */}
      <AINetworkBackground />

      {/* Main Content */}
      <div className="relative z-10 space-y-6 lg:space-y-8 p-2">
        {/* Header - 4K Optimized */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4"
        >
          <div className="flex items-center gap-4 lg:gap-6">
            {/* AI Status Logo */}
            <motion.div
              className="relative p-4 lg:p-6 rounded-2xl bg-gradient-to-br from-joe-blue/20 to-dws-green/10 border border-joe-blue/30"
              animate={{ boxShadow: ['0 0 20px rgba(0, 180, 216, 0.2)', '0 0 40px rgba(0, 180, 216, 0.4)', '0 0 20px rgba(0, 180, 216, 0.2)'] }}
              transition={{ duration: 3, repeat: Infinity }}
            >
              <Shield className="w-10 h-10 lg:w-14 lg:h-14 text-joe-blue" />
              <motion.div
                className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-dws-green"
                animate={{ scale: [1, 1.2, 1] }}
                transition={{ duration: 1, repeat: Infinity }}
              />
            </motion.div>

            <div>
              <h1 className="font-heading text-3xl lg:text-5xl font-bold text-white flex items-center gap-3">
                J.O.E. Command Center
              </h1>
              <div className="flex items-center gap-4 mt-2">
                <div className="flex items-center gap-2">
                  <AIStatusOrb active={aiActive} />
                  <span className="text-joe-blue font-medium text-lg">AI ACTIVE</span>
                </div>
                <span className="text-gray-600">|</span>
                <span className="text-gray-400 font-mono text-lg">
                  {currentTime.toLocaleTimeString()}
                </span>
                <span className="text-gray-600">|</span>
                <span className={`font-medium text-lg ${
                  apiStatus === 'J.O.E. ONLINE' ? 'text-dws-green' : 'text-alert-warning'
                }`}>
                  {apiStatus}
                </span>
              </div>
            </div>
          </div>

          {/* Action Buttons - 4K sized */}
          <div className="flex items-center gap-3 lg:gap-4">
            {lastScanTime && (
              <span className="text-gray-500 text-base lg:text-lg hidden lg:block">
                Last scan: {new Date(lastScanTime).toLocaleTimeString()}
              </span>
            )}
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => refreshDashboard()}
              data-testid="dashboard-refresh-button"
              className="flex items-center gap-2 px-4 lg:px-6 py-3 lg:py-4 rounded-xl bg-dws-card border border-dws-border hover:border-joe-blue/50 transition-all text-base lg:text-lg"
            >
              <RefreshCw size={20} className={isScanning ? 'animate-spin text-joe-blue' : 'text-gray-400'} />
              <span className="text-white">Refresh</span>
            </motion.button>

            <motion.button
              whileHover={{ scale: 1.05, boxShadow: '0 0 30px rgba(34, 197, 94, 0.3)' }}
              whileTap={{ scale: 0.95 }}
              onClick={handleAutoFix}
              disabled={isFixing || isScanning}
              data-testid="dashboard-autofix-button"
              className="flex items-center gap-2 px-4 lg:px-6 py-3 lg:py-4 rounded-xl bg-gradient-to-r from-dws-green to-joe-blue text-white font-medium disabled:opacity-50 transition-all text-base lg:text-lg"
            >
              {isFixing ? (
                <>
                  <Sparkles size={20} className="animate-pulse" />
                  AI Fixing...
                </>
              ) : (
                <>
                  <Brain size={20} />
                  AI Auto-Fix
                </>
              )}
            </motion.button>

            <motion.button
              whileHover={{ scale: 1.05, boxShadow: '0 0 30px rgba(0, 180, 216, 0.4)' }}
              whileTap={{ scale: 0.95 }}
              onClick={handleRunScan}
              disabled={isScanning || isFixing}
              data-testid="dashboard-scan-button"
              className="flex items-center gap-2 px-6 lg:px-8 py-3 lg:py-4 rounded-xl bg-joe-blue text-white font-medium disabled:opacity-50 transition-all text-base lg:text-lg"
            >
              {isScanning ? (
                <>
                  <Radar size={20} className="animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Play size={20} />
                  Security Scan
                </>
              )}
            </motion.button>
          </div>
        </motion.div>

        {/* Main Metrics Grid - 4K Layout */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 lg:gap-6">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
            <MegaMetric
              icon={Shield}
              value={`${securityScore}%`}
              label="Security Score"
              sublabel="Overall posture rating"
              trend={{ value: '+5%', up: true }}
              color={securityScore >= 80 ? 'green' : securityScore >= 50 ? 'yellow' : 'red'}
              onClick={() => setActiveModal('risk')}
            />
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
            <MegaMetric
              icon={AlertTriangle}
              value={riskScore.critical}
              label="Critical Threats"
              sublabel={`${totalFindings} total findings`}
              color={riskScore.critical > 0 ? 'red' : 'green'}
              onClick={() => setActiveModal('findings')}
              pulse={riskScore.critical > 0}
            />
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
            <MegaMetric
              icon={Boxes}
              value={sbomStats.totalComponents}
              label="SBOM Components"
              sublabel={`${sbomStats.vulnerableComponents} vulnerable`}
              color={sbomStats.vulnerableComponents > 0 ? 'yellow' : 'blue'}
              onClick={() => setActiveModal('sbom')}
            />
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
            <MegaMetric
              icon={ClipboardCheck}
              value={`${compliance.score}%`}
              label="Compliance"
              sublabel={`${compliance.framework} Level ${compliance.level}`}
              color={compliance.score >= 80 ? 'green' : compliance.score >= 60 ? 'yellow' : 'red'}
              onClick={() => setActiveModal('compliance')}
            />
          </motion.div>
        </div>

        {/* AI Status Bar */}
        <motion.div
          initial={{ opacity: 0, scaleX: 0 }}
          animate={{ opacity: 1, scaleX: 1 }}
          transition={{ delay: 0.5 }}
        >
          <HoloCard className="p-4 lg:p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6 lg:gap-8">
                <div className="flex items-center gap-3">
                  <Cpu className="w-6 h-6 lg:w-8 lg:h-8 text-joe-blue" />
                  <div>
                    <div className="text-white font-medium text-base lg:text-lg">AI Analysis Engine</div>
                    <div className="text-dws-green text-sm lg:text-base">Active - Processing</div>
                  </div>
                </div>
                <div className="hidden lg:block h-12 w-px bg-dws-border" />
                <div className="hidden lg:flex items-center gap-3">
                  <Network className="w-6 h-6 lg:w-8 lg:h-8 text-dws-green" />
                  <div>
                    <div className="text-white font-medium text-base lg:text-lg">Threat Intel</div>
                    <div className="text-gray-400 text-sm lg:text-base">Connected to NVD, CISA KEV</div>
                  </div>
                </div>
                <div className="hidden xl:block h-12 w-px bg-dws-border" />
                <div className="hidden xl:flex items-center gap-3">
                  <Fingerprint className="w-6 h-6 lg:w-8 lg:h-8 text-joe-blue" />
                  <div>
                    <div className="text-white font-medium text-base lg:text-lg">Pattern Detection</div>
                    <div className="text-gray-400 text-sm lg:text-base">20+ secret patterns active</div>
                  </div>
                </div>
              </div>
              <AIBrainViz />
            </div>
          </HoloCard>
        </motion.div>

        {/* Charts Row - 4K Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-6">
          <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.6 }}>
            <HoloCard onClick={() => setActiveModal('risk')} className="p-6 lg:p-8 h-full">
              <h3 className="font-heading font-semibold text-white text-lg lg:text-xl mb-6 flex items-center gap-3">
                <Zap className="text-joe-blue" size={24} />
                Security Posture
              </h3>
              <div className="flex items-center justify-center py-4">
                <RiskGauge score={securityScore} />
              </div>
            </HoloCard>
          </motion.div>

          <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.7 }}>
            <HoloCard onClick={() => setActiveModal('findings')} className="p-6 lg:p-8 h-full">
              <h3 className="font-heading font-semibold text-white text-lg lg:text-xl mb-6 flex items-center gap-3">
                <BarChart3 className="text-joe-blue" size={24} />
                Severity Distribution
              </h3>
              <SeverityChart data={riskScore} />
            </HoloCard>
          </motion.div>

          <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.8 }}>
            <HoloCard onClick={() => setActiveModal('compliance')} className="p-6 lg:p-8 h-full">
              <h3 className="font-heading font-semibold text-white text-lg lg:text-xl mb-6 flex items-center gap-3">
                <ClipboardCheck className="text-joe-blue" size={24} />
                {compliance.framework} Compliance
              </h3>
              <div className="flex items-center justify-center py-4">
                <ComplianceRing compliance={compliance} />
              </div>
            </HoloCard>
          </motion.div>
        </div>

        {/* MITRE ATT&CK Heatmap - Full Width */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.85 }}>
          <HoloCard className="p-6 lg:p-8">
            <MitreHeatmap />
          </HoloCard>
        </motion.div>

        {/* Timeline & Findings - Two Column */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-6">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.9 }}>
            <HoloCard className="p-6 lg:p-8">
              <ThreatTimeline />
            </HoloCard>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.95 }}>
            <HoloCard className="p-6 lg:p-8">
              <div className="flex items-center justify-between mb-6">
                <h3 className="font-heading font-semibold text-white text-lg lg:text-xl flex items-center gap-3">
                  <FileSearch className="text-joe-blue" size={24} />
                  Recent Findings
                </h3>
                <a href="/findings" className="text-joe-blue hover:underline text-base lg:text-lg">View All</a>
              </div>
              <RecentFindings findings={recentFindings} onFix={fixFinding} />
            </HoloCard>
          </motion.div>
        </div>

        {/* Quick Stats - 4K Grid */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1 }}
          className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-4"
        >
          {[
            { icon: Bug, value: riskScore.high, label: 'High Severity', color: 'text-alert-high', onClick: () => setActiveModal('findings') },
            { icon: AlertTriangle, value: riskScore.medium, label: 'Medium', color: 'text-alert-warning', onClick: () => setActiveModal('findings') },
            { icon: Package, value: sbomStats.libraries, label: 'Libraries', color: 'text-dws-green', onClick: () => setActiveModal('sbom') },
            { icon: GitBranch, value: sbomStats.frameworks, label: 'Frameworks', color: 'text-joe-blue', onClick: () => setActiveModal('sbom') },
            { icon: Lock, value: compliance.compliant, label: 'Compliant', color: 'text-dws-green', onClick: () => setActiveModal('compliance') },
            { icon: Eye, value: 24, label: 'Monitored', color: 'text-joe-blue', onClick: () => {} }
          ].map((stat, i) => (
            <HoloCard key={i} onClick={stat.onClick} className="p-4 lg:p-6 text-center">
              <stat.icon className={`w-6 h-6 lg:w-8 lg:h-8 ${stat.color} mx-auto mb-3`} />
              <p className={`text-2xl lg:text-4xl font-bold ${stat.color}`}>{stat.value}</p>
              <p className="text-gray-400 text-sm lg:text-base mt-1">{stat.label}</p>
            </HoloCard>
          ))}
        </motion.div>

        {/* Footer Status */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.1 }}
          className="flex items-center justify-center gap-6 text-gray-500 text-sm lg:text-base py-4"
        >
          <span>Powered by Dark Wolf Solutions</span>
          <span>|</span>
          <span className="flex items-center gap-2">
            <Terminal size={16} />
            J.O.E. v1.0.0
          </span>
          <span>|</span>
          <span className="text-dws-green flex items-center gap-2">
            <motion.div
              className="w-2 h-2 rounded-full bg-dws-green"
              animate={{ opacity: [1, 0.5, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            />
            All Systems Operational
          </span>
        </motion.div>
      </div>

      {/* Modals */}
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
              <h4 className="font-semibold text-white text-lg">Risk Score Breakdown</h4>
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
              <RiskGauge score={securityScore} />
            </div>
          </div>
        </div>
      </Modal>

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

      <Modal
        isOpen={activeModal === 'sbom'}
        onClose={() => setActiveModal(null)}
        title="Software Bill of Materials"
        subtitle="AI-Driven Dependency Analysis"
        size="xl"
        headerIcon={<Package size={24} />}
        variant={sbomStats.vulnerableComponents > 0 ? 'warning' : 'success'}
        footer={<a href="/supply-chain" className="btn-primary">Full SBOM Explorer</a>}
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
              <AlertTriangle className={sbomStats.vulnerableComponents > 0 ? "text-alert-warning mb-2" : "text-dws-green mb-2"} size={20} />
              <p className={`text-2xl font-bold ${sbomStats.vulnerableComponents > 0 ? 'text-alert-warning' : 'text-dws-green'}`}>{sbomStats.vulnerableComponents}</p>
              <p className="text-gray-400 text-sm">Vulnerable</p>
            </div>
          </div>
        </div>
      </Modal>

      <Modal
        isOpen={activeModal === 'compliance'}
        onClose={() => setActiveModal(null)}
        title={`${compliance.framework} Compliance Status`}
        subtitle={`Level ${compliance.level} - ${compliance.score}% Compliant`}
        size="xl"
        headerIcon={<ClipboardCheck size={24} />}
        variant={compliance.score >= 80 ? 'success' : compliance.score >= 60 ? 'warning' : 'critical'}
        footer={<a href="/compliance" className="btn-primary">View Full Matrix</a>}
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
        </div>
      </Modal>

      <Modal
        isOpen={activeModal === 'scan'}
        onClose={() => !isScanning && setActiveModal(null)}
        title="Security Scan in Progress"
        subtitle="AI-powered comprehensive analysis"
        size="md"
        headerIcon={<Radar size={24} />}
        showCloseButton={!isScanning}
      >
        <div className="space-y-6">
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Progress</span>
              <span className="text-joe-blue font-medium">{scanProgress}%</span>
            </div>
            <div className="h-4 bg-dws-dark rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-joe-blue via-dws-green to-joe-blue"
                initial={{ width: 0 }}
                animate={{ width: `${scanProgress}%` }}
                style={{ backgroundSize: '200% 100%' }}
                transition={{ duration: 0.3 }}
              />
            </div>
          </div>

          <div className="space-y-3">
            {['SAST Analysis', 'Container Scan', 'Dependency Check', 'Secret Detection', 'Compliance Audit'].map((tool, i) => {
              const completed = scanProgress > (i + 1) * 20;
              const active = scanProgress >= i * 20 && scanProgress < (i + 1) * 20;
              return (
                <div key={tool} className="flex items-center gap-3">
                  <motion.div
                    className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                      completed ? 'bg-dws-green text-white' : active ? 'bg-joe-blue text-white' : 'bg-dws-card text-gray-500'
                    }`}
                    animate={active ? { scale: [1, 1.1, 1] } : {}}
                    transition={{ duration: 0.5, repeat: Infinity }}
                  >
                    {completed ? '✓' : active ? <Radar size={16} className="animate-spin" /> : ''}
                  </motion.div>
                  <span className={`text-lg ${completed ? 'text-dws-green' : active ? 'text-white' : 'text-gray-500'}`}>
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
              className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-xl text-center"
            >
              <p className="text-dws-green font-medium text-lg">Scan Complete!</p>
              <p className="text-gray-400 mt-1">Dashboard has been updated with latest results.</p>
            </motion.div>
          )}
        </div>
      </Modal>

      <Modal
        isOpen={activeModal === 'autofix'}
        onClose={() => !isFixing && setActiveModal(null)}
        title="AI Auto-Fix"
        subtitle="Automated vulnerability remediation"
        size="md"
        headerIcon={<Brain size={24} />}
        showCloseButton={!isFixing}
      >
        <div className="space-y-6">
          {isFixing ? (
            <div className="text-center py-8">
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
              >
                <Brain size={64} className="mx-auto text-joe-blue" />
              </motion.div>
              <p className="text-white font-medium text-lg mt-6">J.O.E. AI is analyzing vulnerabilities...</p>
              <p className="text-gray-400 mt-2">Running intelligent remediation</p>
            </div>
          ) : lastFixResult ? (
            <div className="space-y-4">
              {lastFixResult.success ? (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="p-6 bg-dws-green/10 border border-dws-green/30 rounded-xl text-center"
                >
                  <Wrench className="mx-auto text-dws-green mb-3" size={40} />
                  <p className="text-dws-green font-medium text-xl">Auto-Fix Complete!</p>
                </motion.div>
              ) : (
                <div className="p-6 bg-alert-warning/10 border border-alert-warning/30 rounded-xl text-center">
                  <AlertTriangle className="mx-auto text-alert-warning mb-3" size={40} />
                  <p className="text-alert-warning font-medium text-xl">Some fixes could not be applied</p>
                </div>
              )}

              {lastFixResult.fixed.length > 0 && (
                <div>
                  <h4 className="font-semibold text-dws-green mb-2 text-lg">Fixed:</h4>
                  <ul className="space-y-1">
                    {lastFixResult.fixed.map((item, i) => (
                      <li key={i} className="text-gray-400 flex items-center gap-2">
                        <span className="text-dws-green">✓</span> {item.title} - {item.action}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {lastFixResult.failed.length > 0 && (
                <div>
                  <h4 className="font-semibold text-alert-warning mb-2 text-lg">Could not fix:</h4>
                  <ul className="space-y-1">
                    {lastFixResult.failed.map((item, i) => (
                      <li key={i} className="text-gray-400 flex items-center gap-2">
                        <span className="text-alert-warning">✗</span> {item.title} - {item.reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {lastFixResult.poam && lastFixResult.poam.length > 0 && (
                <div>
                  <h4 className="font-semibold text-blue-400 mb-2 text-lg">POAM Items (Requires Manual Remediation):</h4>
                  <ul className="space-y-2">
                    {lastFixResult.poam.map((item, i) => (
                      <li key={i} className="text-gray-400 p-2 bg-blue-900/20 rounded border border-blue-500/30">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                            item.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                            item.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                            item.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-blue-500/20 text-blue-400'
                          }`}>{item.severity.toUpperCase()}</span>
                          <span className="font-medium text-white">{item.title}</span>
                        </div>
                        <p className="text-sm mt-1 text-gray-500">Reason: {item.reason}</p>
                        <p className="text-sm text-blue-400">Milestone: {item.milestoneDays} days</p>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center py-8">
              <Brain size={64} className="mx-auto text-gray-500 mb-4" />
              <p className="text-gray-400 text-lg">Click "AI Auto-Fix" to begin</p>
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}
