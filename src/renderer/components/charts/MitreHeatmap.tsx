import { useState } from 'react';
import { motion } from 'framer-motion';
import Modal from '../common/Modal';
import { Shield, ExternalLink, AlertTriangle } from 'lucide-react';

/**
 * MITRE ATT&CK Heatmap Component
 *
 * Visualizes security coverage across MITRE ATT&CK framework tactics and techniques.
 * Based on MITRE ATT&CK Enterprise Matrix v14.1
 *
 * Reference: https://attack.mitre.org/matrices/enterprise/
 * Color coding follows industry standard security visualization practices
 */

interface TechniqueData {
  id: string;
  name: string;
  coverage: number; // 0-100
  detections: number;
  findings: number;
  description: string;
  mitigations: string[];
}

interface TacticData {
  id: string;
  name: string;
  techniques: TechniqueData[];
}

// MITRE ATT&CK Enterprise Matrix (Simplified for visualization)
const mitreData: TacticData[] = [
  {
    id: 'TA0001',
    name: 'Initial Access',
    techniques: [
      { id: 'T1566', name: 'Phishing', coverage: 85, detections: 12, findings: 2, description: 'Adversaries may send phishing messages to gain access to victim systems.', mitigations: ['User Training', 'Email Filtering', 'MFA'] },
      { id: 'T1190', name: 'Exploit Public-Facing Application', coverage: 70, detections: 8, findings: 3, description: 'Adversaries may attempt to exploit vulnerabilities in internet-facing applications.', mitigations: ['Patch Management', 'WAF', 'Network Segmentation'] },
      { id: 'T1133', name: 'External Remote Services', coverage: 60, detections: 5, findings: 1, description: 'Adversaries may leverage external-facing remote services to gain initial access.', mitigations: ['MFA', 'VPN', 'Access Control'] }
    ]
  },
  {
    id: 'TA0002',
    name: 'Execution',
    techniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter', coverage: 90, detections: 25, findings: 5, description: 'Adversaries may abuse command and script interpreters to execute commands.', mitigations: ['Script Blocking', 'Whitelisting', 'EDR'] },
      { id: 'T1204', name: 'User Execution', coverage: 75, detections: 18, findings: 4, description: 'Adversaries may rely upon specific actions by a user to gain execution.', mitigations: ['User Training', 'Sandboxing', 'AV'] },
      { id: 'T1047', name: 'WMI', coverage: 65, detections: 10, findings: 2, description: 'Adversaries may abuse WMI to execute malicious commands and payloads.', mitigations: ['WMI Logging', 'Disable WMI', 'EDR'] }
    ]
  },
  {
    id: 'TA0003',
    name: 'Persistence',
    techniques: [
      { id: 'T1547', name: 'Boot or Logon Autostart Execution', coverage: 80, detections: 15, findings: 3, description: 'Adversaries may configure system settings to automatically execute a program.', mitigations: ['Registry Monitoring', 'GPO', 'EDR'] },
      { id: 'T1136', name: 'Create Account', coverage: 95, detections: 30, findings: 1, description: 'Adversaries may create an account to maintain access to victim systems.', mitigations: ['Account Monitoring', 'Access Control', 'SIEM'] },
      { id: 'T1053', name: 'Scheduled Task/Job', coverage: 70, detections: 12, findings: 2, description: 'Adversaries may abuse task scheduling functionality.', mitigations: ['Task Monitoring', 'Least Privilege', 'EDR'] }
    ]
  },
  {
    id: 'TA0004',
    name: 'Privilege Escalation',
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control Mechanism', coverage: 75, detections: 8, findings: 4, description: 'Adversaries may circumvent mechanisms designed to control elevate privileges.', mitigations: ['UAC', 'Least Privilege', 'EDR'] },
      { id: 'T1134', name: 'Access Token Manipulation', coverage: 55, detections: 5, findings: 2, description: 'Adversaries may modify access tokens to operate under a different user.', mitigations: ['Token Monitoring', 'Least Privilege', 'EDR'] },
      { id: 'T1068', name: 'Exploitation for Privilege Escalation', coverage: 40, detections: 3, findings: 6, description: 'Adversaries may exploit software vulnerabilities to elevate privileges.', mitigations: ['Patch Management', 'EDR', 'Sandboxing'] }
    ]
  },
  {
    id: 'TA0005',
    name: 'Defense Evasion',
    techniques: [
      { id: 'T1562', name: 'Impair Defenses', coverage: 85, detections: 20, findings: 2, description: 'Adversaries may disable or modify system defenses.', mitigations: ['Tamper Protection', 'Monitoring', 'EDR'] },
      { id: 'T1070', name: 'Indicator Removal', coverage: 60, detections: 8, findings: 3, description: 'Adversaries may delete or modify artifacts generated within systems.', mitigations: ['Log Forwarding', 'Immutable Logs', 'SIEM'] },
      { id: 'T1027', name: 'Obfuscated Files or Information', coverage: 70, detections: 15, findings: 4, description: 'Adversaries may obfuscate files, scripts, and commands.', mitigations: ['Static Analysis', 'Sandboxing', 'ML Detection'] }
    ]
  },
  {
    id: 'TA0006',
    name: 'Credential Access',
    techniques: [
      { id: 'T1110', name: 'Brute Force', coverage: 95, detections: 50, findings: 1, description: 'Adversaries may use brute force techniques to gain access to accounts.', mitigations: ['Account Lockout', 'MFA', 'Password Policy'] },
      { id: 'T1555', name: 'Credentials from Password Stores', coverage: 65, detections: 10, findings: 3, description: 'Adversaries may search for credentials in password stores.', mitigations: ['Password Manager', 'Encryption', 'EDR'] },
      { id: 'T1003', name: 'OS Credential Dumping', coverage: 80, detections: 25, findings: 2, description: 'Adversaries may dump credentials from the operating system.', mitigations: ['Credential Guard', 'LAPS', 'EDR'] }
    ]
  }
];

interface MitreHeatmapProps {
  onTechniqueClick?: (technique: TechniqueData) => void;
}

export default function MitreHeatmap({ onTechniqueClick }: MitreHeatmapProps) {
  const [selectedTechnique, setSelectedTechnique] = useState<TechniqueData | null>(null);
  const [selectedTactic, setSelectedTactic] = useState<TacticData | null>(null);

  const getCoverageColor = (coverage: number) => {
    if (coverage >= 80) return 'bg-dws-green';
    if (coverage >= 60) return 'bg-joe-blue';
    if (coverage >= 40) return 'bg-alert-warning';
    return 'bg-alert-critical';
  };

  const getCoverageOpacity = (coverage: number) => {
    return 0.3 + (coverage / 100) * 0.7;
  };

  const handleTechniqueClick = (technique: TechniqueData, tactic: TacticData) => {
    setSelectedTechnique(technique);
    setSelectedTactic(tactic);
    onTechniqueClick?.(technique);
  };

  const totalCoverage = Math.round(
    mitreData.reduce((sum, tactic) =>
      sum + tactic.techniques.reduce((tSum, t) => tSum + t.coverage, 0), 0
    ) / mitreData.reduce((sum, tactic) => sum + tactic.techniques.length, 0)
  );

  return (
    <div className="space-y-4">
      {/* Header with overall coverage */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="text-joe-blue" size={20} />
          <span className="font-medium text-white">MITRE ATT&CK Coverage</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-2xl font-bold text-joe-blue">{totalCoverage}%</span>
          <span className="text-gray-500 text-sm">Overall</span>
        </div>
      </div>

      {/* Heatmap Grid */}
      <div className="space-y-2">
        {mitreData.map((tactic, tacticIndex) => (
          <motion.div
            key={tactic.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: tacticIndex * 0.1 }}
            className="flex items-stretch gap-2"
          >
            {/* Tactic Label */}
            <div className="w-32 flex-shrink-0 flex items-center">
              <span className="text-xs text-gray-400 truncate" title={tactic.name}>
                {tactic.name}
              </span>
            </div>

            {/* Techniques */}
            <div className="flex-1 flex gap-1">
              {tactic.techniques.map((technique) => (
                <motion.button
                  key={technique.id}
                  className={`
                    flex-1 h-10 rounded cursor-pointer
                    ${getCoverageColor(technique.coverage)}
                    border border-transparent hover:border-white/50
                    transition-all duration-200
                    relative overflow-hidden group
                  `}
                  style={{ opacity: getCoverageOpacity(technique.coverage) }}
                  onClick={() => handleTechniqueClick(technique, tactic)}
                  whileHover={{ scale: 1.05, zIndex: 10 }}
                  whileTap={{ scale: 0.98 }}
                  title={`${technique.name} - ${technique.coverage}% coverage`}
                >
                  {/* Hover tooltip */}
                  <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 bg-black/50 transition-opacity">
                    <span className="text-xs text-white font-medium">
                      {technique.coverage}%
                    </span>
                  </div>

                  {/* Finding indicator */}
                  {technique.findings > 0 && (
                    <div className="absolute top-0.5 right-0.5 w-2 h-2 bg-alert-critical rounded-full animate-pulse" />
                  )}
                </motion.button>
              ))}
            </div>
          </motion.div>
        ))}
      </div>

      {/* Legend */}
      <div className="flex items-center justify-center gap-6 pt-2 border-t border-dws-border">
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-dws-green" />
          <span className="text-xs text-gray-400">80-100%</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-joe-blue" />
          <span className="text-xs text-gray-400">60-79%</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-alert-warning" />
          <span className="text-xs text-gray-400">40-59%</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-alert-critical" />
          <span className="text-xs text-gray-400">0-39%</span>
        </div>
      </div>

      {/* Technique Detail Modal */}
      <Modal
        isOpen={!!selectedTechnique}
        onClose={() => setSelectedTechnique(null)}
        title={selectedTechnique?.name}
        subtitle={`${selectedTechnique?.id} | ${selectedTactic?.name}`}
        size="lg"
        headerIcon={<Shield size={24} />}
        variant={selectedTechnique && selectedTechnique.coverage < 50 ? 'critical' : 'info'}
        footer={
          <div className="flex items-center justify-between">
            <a
              href={`https://attack.mitre.org/techniques/${selectedTechnique?.id}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-joe-blue text-sm flex items-center gap-1 hover:underline"
            >
              View on MITRE ATT&CK <ExternalLink size={14} />
            </a>
            <button
              onClick={() => setSelectedTechnique(null)}
              className="btn-primary"
            >
              Close
            </button>
          </div>
        }
      >
        {selectedTechnique && (
          <div className="space-y-6">
            {/* Stats Grid */}
            <div className="grid grid-cols-3 gap-4">
              <div className="glass-card p-4 text-center">
                <p className="text-3xl font-bold text-joe-blue">{selectedTechnique.coverage}%</p>
                <p className="text-gray-400 text-sm">Coverage</p>
              </div>
              <div className="glass-card p-4 text-center">
                <p className="text-3xl font-bold text-dws-green">{selectedTechnique.detections}</p>
                <p className="text-gray-400 text-sm">Detections</p>
              </div>
              <div className="glass-card p-4 text-center">
                <p className={`text-3xl font-bold ${selectedTechnique.findings > 0 ? 'text-alert-critical' : 'text-gray-500'}`}>
                  {selectedTechnique.findings}
                </p>
                <p className="text-gray-400 text-sm">Active Findings</p>
              </div>
            </div>

            {/* Description */}
            <div>
              <h4 className="font-semibold text-white mb-2">Description</h4>
              <p className="text-gray-300">{selectedTechnique.description}</p>
            </div>

            {/* Mitigations */}
            <div>
              <h4 className="font-semibold text-white mb-2">Recommended Mitigations</h4>
              <div className="flex flex-wrap gap-2">
                {selectedTechnique.mitigations.map((mitigation) => (
                  <span
                    key={mitigation}
                    className="px-3 py-1 text-sm bg-dws-green/10 text-dws-green border border-dws-green/30 rounded-full"
                  >
                    {mitigation}
                  </span>
                ))}
              </div>
            </div>

            {/* Coverage Progress */}
            <div>
              <h4 className="font-semibold text-white mb-2">Coverage Progress</h4>
              <div className="h-3 bg-dws-dark rounded-full overflow-hidden">
                <motion.div
                  className={`h-full ${getCoverageColor(selectedTechnique.coverage)}`}
                  initial={{ width: 0 }}
                  animate={{ width: `${selectedTechnique.coverage}%` }}
                  transition={{ duration: 0.5, delay: 0.2 }}
                />
              </div>
              <div className="flex justify-between mt-1 text-xs text-gray-500">
                <span>0%</span>
                <span>100%</span>
              </div>
            </div>

            {/* Alert for low coverage */}
            {selectedTechnique.coverage < 50 && (
              <div className="flex items-start gap-3 p-4 rounded-lg bg-alert-critical/10 border border-alert-critical/30">
                <AlertTriangle className="text-alert-critical flex-shrink-0" size={20} />
                <div>
                  <p className="font-medium text-alert-critical">Low Coverage Alert</p>
                  <p className="text-gray-400 text-sm mt-1">
                    This technique has coverage below 50%. Consider implementing additional detection rules and mitigations.
                  </p>
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
