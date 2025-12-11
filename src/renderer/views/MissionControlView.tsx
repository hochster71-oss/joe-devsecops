import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Modal from '../components/common/Modal';
import {
  Rocket,
  Shield,
  Brain,
  Zap,
  Target,
  Users,
  BarChart3,
  Layers,
  ChevronRight,
  ExternalLink,
  Bot,
  Lock,
  Eye,
  Cpu,
  Database,
  Network,
  Activity,
  Award,
  TrendingUp,
  Clock,
  CheckCircle,
  AlertTriangle
} from 'lucide-react';
import {
  JOE_IDENTITY,
  CORE_MISSION,
  DSO_MATURITY_LEVELS,
  KPI_FRAMEWORK,
  SYSTEM_ARCHITECTURE,
  AGENT_DEFINITIONS,
  RISK_TIERS,
  SUPPORTED_FRAMEWORKS,
  type MaturityLevel
} from '../../core/joe-specification';

/**
 * Mission Control View
 *
 * Showcases J.O.E.'s full capabilities, architecture, and operational specification.
 * The command center for understanding and configuring the Joint Operations Engine.
 */

export default function MissionControlView() {
  const [selectedAgent, setSelectedAgent] = useState<typeof AGENT_DEFINITIONS[0] | null>(null);
  const [selectedKpi, setSelectedKpi] = useState<typeof KPI_FRAMEWORK[0] | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'agents' | 'architecture' | 'kpis'>('overview');

  const capabilityIcons = {
    'Reason': Brain,
    'Predict': TrendingUp,
    'Govern': Shield,
    'Enforce': Lock,
    'Optimize': Zap,
    'Adapt': Activity
  };

  const agentIcons: Record<string, typeof Shield> = {
    'build_agent': Cpu,
    'security_agent': Shield,
    'governance_agent': Award,
    'runtime_defense_agent': Eye,
    'threat_intelligence_agent': AlertTriangle,
    'supply_chain_agent': Network,
    'data_protection_agent': Database,
    'observability_agent': BarChart3,
    'resilience_agent': Activity,
    'quality_test_agent': CheckCircle,
    'developer_assist_agent': Users,
    'economic_optimization_agent': TrendingUp
  };

  const planeIcons = {
    control: Shield,
    data: Database,
    intelligence: Brain,
    execution: Zap
  };

  const maturityColors: Record<MaturityLevel, string> = {
    'Initial': 'text-alert-critical',
    'Defined': 'text-alert-warning',
    'Integrated': 'text-joe-blue',
    'Automated': 'text-dws-green',
    'Autonomous': 'text-purple-400'
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-joe-blue/20 to-dws-green/20 border border-joe-blue/30">
            <Rocket className="text-joe-blue" size={28} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-white flex items-center gap-2">
              {JOE_IDENTITY.name} Mission Control
            </h1>
            <p className="text-gray-400 mt-1">{JOE_IDENTITY.fullName} • v{JOE_IDENTITY.version}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-gray-500 text-sm">Architected by</span>
          <span className="text-joe-blue font-medium">{JOE_IDENTITY.architect}</span>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-2 border-b border-dws-border pb-2">
        {(['overview', 'agents', 'architecture', 'kpis'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-t-lg font-medium transition-colors ${
              activeTab === tab
                ? 'bg-joe-blue/10 text-joe-blue border-b-2 border-joe-blue'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <motion.div
            key="overview"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Identity Card */}
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Bot className="text-joe-blue" size={20} />
                Identity
              </h2>
              <p className="text-gray-300 leading-relaxed mb-6">
                {JOE_IDENTITY.description}
              </p>

              {/* Core Capabilities */}
              <div className="grid grid-cols-6 gap-3">
                {JOE_IDENTITY.capabilities.map((cap, i) => {
                  const Icon = capabilityIcons[cap as keyof typeof capabilityIcons] || Zap;
                  return (
                    <motion.div
                      key={cap}
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: i * 0.1 }}
                      className="glass-card p-4 text-center"
                    >
                      <Icon className="text-joe-blue mx-auto mb-2" size={24} />
                      <span className="text-white text-sm font-medium">{cap}</span>
                    </motion.div>
                  );
                })}
              </div>
            </div>

            {/* Mission */}
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Target className="text-dws-green" size={20} />
                Core Mission
              </h2>
              <p className="text-gray-400 mb-4 italic">{CORE_MISSION.principle}</p>
              <div className="grid grid-cols-3 gap-4">
                {CORE_MISSION.objectives.map((obj, i) => (
                  <motion.div
                    key={obj.name}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.15 }}
                    className="p-4 bg-dws-dark rounded-lg border border-dws-border"
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <span className="w-6 h-6 rounded-full bg-joe-blue flex items-center justify-center text-white text-sm font-bold">
                        {obj.priority}
                      </span>
                      <span className="text-white font-medium">{obj.name}</span>
                    </div>
                    <p className="text-gray-500 text-sm">{obj.description}</p>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Maturity Model */}
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Layers className="text-joe-blue" size={20} />
                DSO Maturity Model
              </h2>
              <div className="flex gap-2">
                {(Object.entries(DSO_MATURITY_LEVELS) as [MaturityLevel, typeof DSO_MATURITY_LEVELS[MaturityLevel]][]).map(([level, data], i) => (
                  <motion.div
                    key={level}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.1 }}
                    className="flex-1 p-4 bg-dws-dark rounded-lg border border-dws-border hover:border-joe-blue/50 transition-colors cursor-pointer group"
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`text-2xl font-bold ${maturityColors[level]}`}>L{data.level}</span>
                      <ChevronRight className="text-gray-600 group-hover:text-joe-blue transition-colors" size={16} />
                    </div>
                    <p className={`font-medium ${maturityColors[level]}`}>{level}</p>
                    <p className="text-gray-500 text-xs mt-1 line-clamp-2">{data.description}</p>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Supported Frameworks */}
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <Award className="text-dws-green" size={20} />
                Supported Compliance Frameworks
              </h2>
              <div className="grid grid-cols-4 gap-3">
                {SUPPORTED_FRAMEWORKS.map((fw) => (
                  <div
                    key={fw.id}
                    className="p-3 bg-dws-dark rounded-lg border border-dws-border"
                  >
                    <p className="text-white font-medium text-sm">{fw.name}</p>
                    <p className="text-gray-500 text-xs mt-1">{fw.controlCount} controls</p>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {/* Agents Tab */}
        {activeTab === 'agents' && (
          <motion.div
            key="agents"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-4"
          >
            <p className="text-gray-400">
              J.O.E. operates using {AGENT_DEFINITIONS.length} specialized autonomous agents that communicate through a unified knowledge graph.
            </p>
            <div className="grid grid-cols-2 gap-4">
              {AGENT_DEFINITIONS.map((agent, i) => {
                const Icon = agentIcons[agent.id] || Bot;
                return (
                  <motion.button
                    key={agent.id}
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: i * 0.05 }}
                    onClick={() => setSelectedAgent(agent)}
                    className="glass-card p-4 text-left hover:bg-dws-elevated transition-colors group"
                  >
                    <div className="flex items-start gap-4">
                      <div className="p-3 rounded-lg bg-joe-blue/10 border border-joe-blue/30">
                        <Icon className="text-joe-blue" size={24} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <h3 className="text-white font-medium">{agent.name}</h3>
                          <ChevronRight className="text-gray-600 group-hover:text-joe-blue transition-colors" size={18} />
                        </div>
                        <p className="text-gray-500 text-sm mt-1 line-clamp-2">{agent.role}</p>
                        <div className="flex flex-wrap gap-1 mt-2">
                          {agent.kpiInfluence.slice(0, 2).map(kpi => (
                            <span key={kpi} className="text-xs px-2 py-0.5 bg-dws-dark rounded text-joe-blue">
                              {kpi.replace(/_/g, ' ')}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </motion.button>
                );
              })}
            </div>
          </motion.div>
        )}

        {/* Architecture Tab */}
        {activeTab === 'architecture' && (
          <motion.div
            key="architecture"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-6"
          >
            {/* Architecture Diagram */}
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-white mb-4">System Architecture</h2>
              <pre className="text-joe-blue text-sm font-mono bg-dws-dark p-4 rounded-lg overflow-x-auto">
                {SYSTEM_ARCHITECTURE.diagram}
              </pre>
            </div>

            {/* Four Planes */}
            <div className="grid grid-cols-2 gap-4">
              {Object.entries(SYSTEM_ARCHITECTURE.planes).map(([key, plane], i) => {
                const Icon = planeIcons[key as keyof typeof planeIcons] || Layers;
                return (
                  <motion.div
                    key={key}
                    initial={{ opacity: 0, x: i % 2 === 0 ? -20 : 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.1 }}
                    className="glass-card p-5"
                  >
                    <div className="flex items-center gap-3 mb-3">
                      <div className="p-2 rounded-lg bg-joe-blue/10">
                        <Icon className="text-joe-blue" size={20} />
                      </div>
                      <h3 className="text-white font-medium">{plane.name}</h3>
                    </div>
                    <p className="text-gray-400 text-sm mb-3">{plane.description}</p>
                    <div className="flex flex-wrap gap-2">
                      {plane.components.map(comp => (
                        <span key={comp} className="text-xs px-2 py-1 bg-dws-dark border border-dws-border rounded text-gray-300">
                          {comp}
                        </span>
                      ))}
                    </div>
                  </motion.div>
                );
              })}
            </div>

            {/* Risk Tiers */}
            <div className="glass-card p-6">
              <h2 className="text-lg font-semibold text-white mb-4">Risk Classification</h2>
              <div className="flex gap-3">
                {Object.entries(RISK_TIERS).map(([tier, data]) => (
                  <div
                    key={tier}
                    className="flex-1 p-3 rounded-lg border"
                    style={{ borderColor: data.color + '50', backgroundColor: data.color + '10' }}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <div className="w-3 h-3 rounded-full" style={{ backgroundColor: data.color }} />
                      <span className="font-medium" style={{ color: data.color }}>{tier}</span>
                    </div>
                    <p className="text-xs text-gray-400">{data.min}-{data.max} score</p>
                    <p className="text-xs text-gray-500 mt-1">{data.action}</p>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {/* KPIs Tab */}
        {activeTab === 'kpis' && (
          <motion.div
            key="kpis"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="space-y-4"
          >
            <p className="text-gray-400">
              J.O.E. measures impact through {KPI_FRAMEWORK.length} key performance indicators.
            </p>
            <div className="grid grid-cols-3 gap-4">
              {KPI_FRAMEWORK.map((kpi, i) => (
                <motion.button
                  key={kpi.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }}
                  onClick={() => setSelectedKpi(kpi)}
                  className="glass-card p-4 text-left hover:bg-dws-elevated transition-colors group"
                >
                  <div className="flex items-start justify-between mb-2">
                    <BarChart3 className="text-joe-blue" size={20} />
                    <ChevronRight className="text-gray-600 group-hover:text-joe-blue transition-colors" size={16} />
                  </div>
                  <h3 className="text-white font-medium text-sm">{kpi.name}</h3>
                  <p className="text-gray-500 text-xs mt-1 line-clamp-2">{kpi.description}</p>
                  <div className="mt-3 pt-2 border-t border-dws-border">
                    <span className="text-dws-green text-xs font-medium">Target: {kpi.target}</span>
                  </div>
                </motion.button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Agent Detail Modal */}
      <Modal
        isOpen={!!selectedAgent}
        onClose={() => setSelectedAgent(null)}
        title={selectedAgent?.name}
        subtitle={selectedAgent?.id}
        size="lg"
        headerIcon={selectedAgent && <Bot size={24} />}
        variant="info"
        footer={
          <div className="flex items-center justify-end">
            <button onClick={() => setSelectedAgent(null)} className="btn-primary">
              Close
            </button>
          </div>
        }
      >
        {selectedAgent && (
          <div className="space-y-6">
            <div>
              <h4 className="font-semibold text-white mb-2">Role</h4>
              <p className="text-gray-300">{selectedAgent.role}</p>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="font-semibold text-white mb-2">Inputs</h4>
                <ul className="space-y-1">
                  {selectedAgent.inputs.map(input => (
                    <li key={input} className="text-gray-400 text-sm flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-joe-blue" />
                      {input}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-white mb-2">Outputs</h4>
                <ul className="space-y-1">
                  {selectedAgent.outputs.map(output => (
                    <li key={output} className="text-gray-400 text-sm flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-dws-green" />
                      {output}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div>
              <h4 className="font-semibold text-white mb-2">Control Actions</h4>
              <div className="flex flex-wrap gap-2">
                {selectedAgent.controlActions.map(action => (
                  <span key={action} className="px-3 py-1 bg-alert-warning/10 text-alert-warning border border-alert-warning/30 rounded-full text-sm">
                    {action}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <h4 className="font-semibold text-white mb-2">KPI Influence</h4>
              <div className="flex flex-wrap gap-2">
                {selectedAgent.kpiInfluence.map(kpi => (
                  <span key={kpi} className="px-3 py-1 bg-joe-blue/10 text-joe-blue border border-joe-blue/30 rounded-full text-sm">
                    {kpi.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </Modal>

      {/* KPI Detail Modal */}
      <Modal
        isOpen={!!selectedKpi}
        onClose={() => setSelectedKpi(null)}
        title={selectedKpi?.name}
        subtitle={selectedKpi?.id}
        size="md"
        headerIcon={<BarChart3 size={24} />}
        variant="info"
        footer={
          <div className="flex items-center justify-end">
            <button onClick={() => setSelectedKpi(null)} className="btn-primary">
              Close
            </button>
          </div>
        }
      >
        {selectedKpi && (
          <div className="space-y-4">
            <div>
              <h4 className="font-semibold text-white mb-2">Description</h4>
              <p className="text-gray-300">{selectedKpi.description}</p>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-dws-dark rounded-lg">
                <p className="text-gray-500 text-sm">Unit</p>
                <p className="text-white font-medium">{selectedKpi.unit}</p>
              </div>
              <div className="p-4 bg-dws-dark rounded-lg">
                <p className="text-gray-500 text-sm">Frequency</p>
                <p className="text-white font-medium">{selectedKpi.frequency}</p>
              </div>
            </div>

            <div className="p-4 bg-dws-green/10 border border-dws-green/30 rounded-lg">
              <p className="text-dws-green text-sm font-medium">Target</p>
              <p className="text-white mt-1">{selectedKpi.target}</p>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
