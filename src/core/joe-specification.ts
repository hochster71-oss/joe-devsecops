/**
 * J.O.E. - JOINT OPERATIONS ENGINE
 * AUTONOMOUS DEVSECOPS, CYBER-OPERATIONS, AND SDLC INTELLIGENCE PLATFORM
 *
 * THE COMPLETE, FINAL, LOCKED MASTER SPECIFICATION
 *
 * Architected by: Michael Hoch, Chief Architect of Autonomous Cyber-Operations (ACO)
 * Operational Mission Owner: Joseph Scholer
 *
 * This specification represents the final, integrated, comprehensive definition for J.O.E.
 */

// ============================================================================
// I. IDENTITY
// ============================================================================

export const JOE_IDENTITY = {
  name: 'J.O.E.',
  fullName: 'Joint Operations Engine',
  version: '1.0.0',
  architect: 'Michael Hoch',
  architectTitle: 'Chief Architect of Autonomous Cyber-Operations (ACO)',
  missionOwner: 'Joseph Scholer',
  organization: 'Dark Wolf Solutions',

  description: `An autonomous, multi-agent cyber-operations and DevSecOps intelligence platform
responsible for governing, orchestrating, optimizing, and securing the entire SDLC, cloud,
runtime, and compliance ecosystem.`,

  capabilities: [
    'Reason',
    'Predict',
    'Govern',
    'Enforce',
    'Optimize',
    'Adapt'
  ]
} as const;

// ============================================================================
// II. CORE MISSION
// ============================================================================

export const CORE_MISSION = {
  objectives: [
    { priority: 1, name: 'Security', description: 'Protect systems, data, and operations' },
    { priority: 2, name: 'Delivery Speed', description: 'Accelerate secure software delivery' },
    { priority: 3, name: 'Operational Resilience', description: 'Ensure continuous availability and recovery' }
  ],
  principle: 'Improve all objectives simultaneously, continuously, and without tradeoffs.'
} as const;

// ============================================================================
// III. DSO MATURITY MODEL
// ============================================================================

export type MaturityLevel = 'Initial' | 'Defined' | 'Integrated' | 'Automated' | 'Autonomous';

export const DSO_MATURITY_LEVELS: Record<MaturityLevel, { level: number; description: string; characteristics: string[] }> = {
  Initial: {
    level: 1,
    description: 'Ad-hoc security practices with minimal integration',
    characteristics: [
      'Manual security reviews',
      'Reactive vulnerability management',
      'Siloed security and development teams',
      'No standardized processes'
    ]
  },
  Defined: {
    level: 2,
    description: 'Documented processes and basic tooling in place',
    characteristics: [
      'Documented security policies',
      'Basic SAST/DAST tooling',
      'Security training programs',
      'Defined incident response'
    ]
  },
  Integrated: {
    level: 3,
    description: 'Security integrated into development workflow',
    characteristics: [
      'Security gates in CI/CD',
      'Automated vulnerability scanning',
      'Shift-left security practices',
      'Cross-functional security teams'
    ]
  },
  Automated: {
    level: 4,
    description: 'Automated security enforcement and remediation',
    characteristics: [
      'Policy-as-code enforcement',
      'Automated remediation workflows',
      'Real-time security monitoring',
      'Self-service security tools'
    ]
  },
  Autonomous: {
    level: 5,
    description: 'AI-driven predictive security with continuous optimization',
    characteristics: [
      'Predictive threat intelligence',
      'Self-healing infrastructure',
      'Autonomous risk management',
      'Continuous compliance verification'
    ]
  }
};

// ============================================================================
// IV. DSO SCORING RUBRIC (100-Point Scale)
// ============================================================================

export interface ScoringDimension {
  id: string;
  name: string;
  maxScore: number;
  weight: number;
  criteria: string[];
}

export const DSO_SCORING_DIMENSIONS: ScoringDimension[] = [
  {
    id: 'governance',
    name: 'Governance',
    maxScore: 10,
    weight: 1.0,
    criteria: [
      'Security policies defined and enforced',
      'Risk management framework in place',
      'Executive sponsorship and accountability',
      'Compliance requirements mapped'
    ]
  },
  {
    id: 'sdlc_integration',
    name: 'SDLC Integration',
    maxScore: 10,
    weight: 1.0,
    criteria: [
      'Security requirements in user stories',
      'Threat modeling in design phase',
      'Security testing in development',
      'Security sign-off before release'
    ]
  },
  {
    id: 'cicd_standardization',
    name: 'CI/CD Standardization',
    maxScore: 10,
    weight: 1.0,
    criteria: [
      'Standardized pipeline templates',
      'Security gates enforced',
      'Artifact integrity verification',
      'Environment promotion controls'
    ]
  },
  {
    id: 'automation',
    name: 'Automation',
    maxScore: 10,
    weight: 1.0,
    criteria: [
      'Automated security scanning',
      'Automated compliance checks',
      'Automated remediation',
      'Automated evidence collection'
    ]
  },
  {
    id: 'policy_as_code',
    name: 'Policy-as-Code',
    maxScore: 10,
    weight: 1.0,
    criteria: [
      'Policies codified and versioned',
      'Policy enforcement automated',
      'Exception handling defined',
      'Policy drift detection'
    ]
  },
  {
    id: 'toolchain_integration',
    name: 'Toolchain Integration',
    maxScore: 10,
    weight: 1.0,
    criteria: [
      'Unified security toolchain',
      'Tool output correlation',
      'Single pane of glass visibility',
      'API-first tool selection'
    ]
  },
  {
    id: 'developer_enablement',
    name: 'Developer Enablement',
    maxScore: 10,
    weight: 1.0,
    criteria: [
      'Self-service security tools',
      'Security training and certification',
      'Developer-friendly documentation',
      'Low friction security workflows'
    ]
  },
  {
    id: 'runtime_security',
    name: 'Runtime Security',
    maxScore: 10,
    weight: 1.0,
    criteria: [
      'Runtime threat detection',
      'Workload protection',
      'Network segmentation',
      'Incident response automation'
    ]
  },
  {
    id: 'ai_predictiveness',
    name: 'AI Predictiveness',
    maxScore: 10,
    weight: 1.0,
    criteria: [
      'Predictive vulnerability analysis',
      'Anomaly detection models',
      'Risk forecasting',
      'Intelligent prioritization'
    ]
  },
  {
    id: 'supply_chain_integrity',
    name: 'Supply Chain Integrity',
    maxScore: 10,
    weight: 1.0,
    criteria: [
      'SBOM generation and management',
      'Dependency vulnerability tracking',
      'Provenance verification',
      'Third-party risk assessment'
    ]
  }
];

// ============================================================================
// V. KPI FRAMEWORK
// ============================================================================

export interface KPI {
  id: string;
  name: string;
  description: string;
  unit: string;
  target: string;
  frequency: string;
  formula?: string;
}

export const KPI_FRAMEWORK: KPI[] = [
  {
    id: 'mttr',
    name: 'Mean Time to Remediate',
    description: 'Average time from vulnerability detection to remediation',
    unit: 'hours',
    target: '< 24 hours for critical, < 72 hours for high',
    frequency: 'Real-time'
  },
  {
    id: 'vulnerability_exposure_window',
    name: 'Vulnerability Exposure Window',
    description: 'Time vulnerabilities remain unpatched in production',
    unit: 'days',
    target: '< 7 days for critical vulnerabilities',
    frequency: 'Daily'
  },
  {
    id: 'guardrail_enforcement_rate',
    name: 'Guardrail Enforcement Rate',
    description: 'Percentage of deployments passing all security guardrails',
    unit: 'percentage',
    target: '> 95%',
    frequency: 'Per deployment'
  },
  {
    id: 'sbom_coverage',
    name: 'SBOM Coverage',
    description: 'Percentage of applications with complete, current SBOMs',
    unit: 'percentage',
    target: '100%',
    frequency: 'Weekly'
  },
  {
    id: 'predictive_accuracy',
    name: 'Predictive Accuracy',
    description: 'Accuracy of risk predictions vs actual incidents',
    unit: 'percentage',
    target: '> 85%',
    frequency: 'Monthly'
  },
  {
    id: 'blast_radius_reduction',
    name: 'Blast Radius Reduction',
    description: 'Reduction in potential impact from security incidents',
    unit: 'percentage',
    target: '> 50% year-over-year improvement',
    frequency: 'Quarterly'
  },
  {
    id: 'compliance_evidence_coverage',
    name: 'Compliance Evidence Coverage',
    description: 'Percentage of controls with automated evidence collection',
    unit: 'percentage',
    target: '> 90%',
    frequency: 'Per audit cycle'
  },
  {
    id: 'developer_friction_index',
    name: 'Developer Friction Index',
    description: 'Measure of security process impact on developer velocity',
    unit: 'score',
    target: '< 2.0 (low friction)',
    frequency: 'Monthly survey'
  },
  {
    id: 'autonomous_remediation_rate',
    name: 'Autonomous Remediation Rate',
    description: 'Percentage of vulnerabilities auto-remediated without human intervention',
    unit: 'percentage',
    target: '> 40%',
    frequency: 'Weekly'
  }
];

// ============================================================================
// VI. SYSTEM ARCHITECTURE
// ============================================================================

export const SYSTEM_ARCHITECTURE = {
  planes: {
    control: {
      name: 'Control Plane',
      description: 'Policies, workflows, risk, compliance, orchestration',
      components: [
        'Policy Engine',
        'Workflow Orchestrator',
        'Risk Calculator',
        'Compliance Manager',
        'Configuration Controller'
      ]
    },
    data: {
      name: 'Data Plane',
      description: 'Telemetry, logs, SBOMs, identity events, configuration metadata',
      components: [
        'Telemetry Collector',
        'Log Aggregator',
        'SBOM Repository',
        'Identity Store',
        'Configuration Database'
      ]
    },
    intelligence: {
      name: 'Intelligence Plane',
      description: 'Multi-agent reasoning, predictive models, optimization, anomaly detection',
      components: [
        'Agent Orchestrator',
        'ML Model Server',
        'Anomaly Detector',
        'Prediction Engine',
        'Knowledge Graph'
      ]
    },
    execution: {
      name: 'Execution Plane',
      description: 'Pipeline mutation, policy enforcement, remediation, rollbacks',
      components: [
        'Pipeline Controller',
        'Enforcement Engine',
        'Remediation Executor',
        'Rollback Manager',
        'Deployment Controller'
      ]
    }
  },

  diagram: `
                   +------------------------------+
                   |        INTELLIGENCE PLANE    |
                   |  (Agents, Models, Predictive)|
                   +------------------------------+
                               /      \\
                              /        \\
+---------------------+     /          \\    +---------------------+
|     CONTROL PLANE   |----            ----|    EXECUTION PLANE   |
|  (Governance, Risk, |                    |  (Pipelines, Guardrails|
|   Compliance, Policy)|                    |   Enforcement, Fixes) |
+---------------------+     \\          /   +---------------------+
                              \\        /
                     +----------------------------+
                     |         DATA PLANE         |
                     | (Telemetry, SBOMs, Logs,   |
                     | Evidence, Metadata, Events)|
                     +----------------------------+
`
} as const;

// ============================================================================
// VII. MULTI-AGENT ONTOLOGY
// ============================================================================

export interface AgentDefinition {
  id: string;
  name: string;
  role: string;
  inputs: string[];
  outputs: string[];
  controlActions: string[];
  kpiInfluence: string[];
}

export const AGENT_DEFINITIONS: AgentDefinition[] = [
  {
    id: 'build_agent',
    name: 'Build Agent',
    role: 'Manages CI/CD pipeline security and artifact integrity',
    inputs: ['Source code', 'Build configurations', 'Dependencies'],
    outputs: ['Secure artifacts', 'Build attestations', 'SBOM'],
    controlActions: ['Block insecure builds', 'Enforce signing', 'Validate dependencies'],
    kpiInfluence: ['guardrail_enforcement_rate', 'sbom_coverage']
  },
  {
    id: 'security_agent',
    name: 'Security Agent',
    role: 'Orchestrates security scanning and vulnerability management',
    inputs: ['Scan results', 'CVE feeds', 'Threat intelligence'],
    outputs: ['Prioritized findings', 'Risk scores', 'Remediation guidance'],
    controlActions: ['Trigger scans', 'Update policies', 'Escalate critical findings'],
    kpiInfluence: ['mttr', 'vulnerability_exposure_window']
  },
  {
    id: 'governance_agent',
    name: 'Governance Agent',
    role: 'Enforces policies and manages compliance',
    inputs: ['Policies', 'Compliance requirements', 'Audit requests'],
    outputs: ['Compliance reports', 'Evidence packages', 'Policy violations'],
    controlActions: ['Enforce policies', 'Generate evidence', 'Manage exceptions'],
    kpiInfluence: ['compliance_evidence_coverage', 'guardrail_enforcement_rate']
  },
  {
    id: 'runtime_defense_agent',
    name: 'Runtime Defense Agent',
    role: 'Monitors and protects production workloads',
    inputs: ['Runtime telemetry', 'Network traffic', 'System calls'],
    outputs: ['Threat alerts', 'Behavioral baselines', 'Incident reports'],
    controlActions: ['Block attacks', 'Isolate workloads', 'Trigger incident response'],
    kpiInfluence: ['blast_radius_reduction', 'mttr']
  },
  {
    id: 'threat_intelligence_agent',
    name: 'Threat Intelligence Agent',
    role: 'Aggregates and correlates threat data',
    inputs: ['CVE feeds', 'OSINT', 'Dark web monitoring', 'MITRE ATT&CK'],
    outputs: ['Threat assessments', 'IOCs', 'Attack predictions'],
    controlActions: ['Update threat models', 'Adjust risk scores', 'Alert on emerging threats'],
    kpiInfluence: ['predictive_accuracy', 'vulnerability_exposure_window']
  },
  {
    id: 'supply_chain_agent',
    name: 'Supply Chain Agent',
    role: 'Manages software supply chain security',
    inputs: ['SBOMs', 'Package metadata', 'Provenance data'],
    outputs: ['Dependency risk scores', 'License analysis', 'Supply chain alerts'],
    controlActions: ['Block risky dependencies', 'Verify provenance', 'Enforce license policies'],
    kpiInfluence: ['sbom_coverage', 'supply_chain_integrity']
  },
  {
    id: 'data_protection_agent',
    name: 'Data Protection Agent',
    role: 'Enforces data security and privacy',
    inputs: ['Data classification', 'Access patterns', 'Encryption status'],
    outputs: ['Data risk reports', 'Access anomalies', 'Compliance status'],
    controlActions: ['Enforce encryption', 'Revoke access', 'Mask sensitive data'],
    kpiInfluence: ['compliance_evidence_coverage', 'blast_radius_reduction']
  },
  {
    id: 'observability_agent',
    name: 'Observability Agent',
    role: 'Provides visibility across the security landscape',
    inputs: ['Logs', 'Metrics', 'Traces', 'Events'],
    outputs: ['Dashboards', 'Alerts', 'Trend analysis'],
    controlActions: ['Configure alerting', 'Correlate events', 'Generate reports'],
    kpiInfluence: ['mttr', 'predictive_accuracy']
  },
  {
    id: 'resilience_agent',
    name: 'Resilience Agent',
    role: 'Ensures system availability and recovery',
    inputs: ['Health metrics', 'Failure patterns', 'Backup status'],
    outputs: ['Resilience scores', 'Recovery plans', 'Chaos test results'],
    controlActions: ['Trigger failover', 'Execute rollback', 'Initiate self-healing'],
    kpiInfluence: ['blast_radius_reduction', 'mttr']
  },
  {
    id: 'quality_test_agent',
    name: 'Quality/Test Agent',
    role: 'Ensures security testing quality',
    inputs: ['Test results', 'Coverage data', 'Quality gates'],
    outputs: ['Test reports', 'Coverage metrics', 'Quality scores'],
    controlActions: ['Block low-quality releases', 'Trigger additional tests', 'Update test suites'],
    kpiInfluence: ['guardrail_enforcement_rate', 'developer_friction_index']
  },
  {
    id: 'developer_assist_agent',
    name: 'Developer Assist Agent',
    role: 'Enables developers with security tools and guidance',
    inputs: ['Developer queries', 'Code context', 'Best practices'],
    outputs: ['Security guidance', 'Code suggestions', 'Training recommendations'],
    controlActions: ['Provide real-time feedback', 'Suggest fixes', 'Enable self-service'],
    kpiInfluence: ['developer_friction_index', 'autonomous_remediation_rate']
  },
  {
    id: 'economic_optimization_agent',
    name: 'Economic Optimization Agent',
    role: 'Optimizes security investments and priorities',
    inputs: ['Cost data', 'Risk scores', 'Business impact'],
    outputs: ['ROI analysis', 'Priority rankings', 'Budget recommendations'],
    controlActions: ['Prioritize remediations', 'Optimize tool spend', 'Recommend investments'],
    kpiInfluence: ['mttr', 'blast_radius_reduction']
  }
];

// ============================================================================
// VIII. RISK MODEL
// ============================================================================

export interface RiskFactor {
  id: string;
  name: string;
  symbol: string;
  weight: number;
  description: string;
}

export const RISK_FACTORS: RiskFactor[] = [
  { id: 'vulnerability_severity', name: 'Vulnerability Severity', symbol: 'V', weight: 0.20, description: 'CVSS base score of the vulnerability' },
  { id: 'exploitability', name: 'Exploitability', symbol: 'E', weight: 0.15, description: 'Likelihood and ease of exploitation (EPSS)' },
  { id: 'exposure_surface', name: 'Exposure Surface', symbol: 'X', weight: 0.15, description: 'Internet exposure and attack surface' },
  { id: 'asset_value', name: 'Asset Value', symbol: 'A', weight: 0.15, description: 'Business criticality of affected asset' },
  { id: 'dependency_criticality', name: 'Dependency Criticality', symbol: 'D', weight: 0.10, description: 'Criticality in dependency chain' },
  { id: 'control_coverage_gap', name: 'Control Coverage Gap', symbol: 'C', weight: 0.10, description: 'Missing or ineffective controls' },
  { id: 'threat_intelligence', name: 'Threat Intelligence', symbol: 'T', weight: 0.10, description: 'Active exploitation in the wild' },
  { id: 'likelihood_time_adjusted', name: 'Likelihood (Time-Adjusted)', symbol: 'L', weight: 0.05, description: 'Probability of exploitation over time' }
];

export const RISK_FORMULA = `
RISK = Σ (Factor_i × Weight_i)
     = (V × 0.20) + (E × 0.15) + (X × 0.15) + (A × 0.15) + (D × 0.10) + (C × 0.10) + (T × 0.10) + (L × 0.05)

Where each factor is normalized to 0-10 scale.
Total Risk Score: 0-10 (Critical: >8, High: 6-8, Medium: 4-6, Low: <4)
`;

export type RiskTier = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export const RISK_TIERS: Record<RiskTier, { min: number; max: number; color: string; action: string }> = {
  Critical: { min: 8.0, max: 10.0, color: '#FF3366', action: 'Immediate remediation required within 24 hours' },
  High: { min: 6.0, max: 7.9, color: '#FF6B35', action: 'Remediation required within 72 hours' },
  Medium: { min: 4.0, max: 5.9, color: '#FFB800', action: 'Remediation within 7 days' },
  Low: { min: 2.0, max: 3.9, color: '#87C549', action: 'Remediation within 30 days' },
  Info: { min: 0, max: 1.9, color: '#00A8E8', action: 'Monitor and track' }
};

// ============================================================================
// IX. COMPLIANCE FRAMEWORKS
// ============================================================================

export const SUPPORTED_FRAMEWORKS = [
  { id: 'cmmc', name: 'CMMC 2.0', levels: [1, 2, 3], controlCount: 110 },
  { id: 'nist_800_171', name: 'NIST SP 800-171', levels: [1], controlCount: 110 },
  { id: 'nist_800_53', name: 'NIST SP 800-53', levels: ['Low', 'Moderate', 'High'], controlCount: 1000 },
  { id: 'soc2', name: 'SOC 2', levels: ['Type I', 'Type II'], controlCount: 64 },
  { id: 'iso27001', name: 'ISO 27001', levels: [1], controlCount: 93 },
  { id: 'pci_dss', name: 'PCI DSS', levels: [1, 2, 3, 4], controlCount: 251 },
  { id: 'hipaa', name: 'HIPAA', levels: [1], controlCount: 54 },
  { id: 'fedramp', name: 'FedRAMP', levels: ['Low', 'Moderate', 'High'], controlCount: 325 }
] as const;

// ============================================================================
// X. POLICY-AS-CODE TEMPLATES
// ============================================================================

export const POLICY_FORMATS = [
  'OPA/Rego',
  'HashiCorp Sentinel',
  'YAML Guardrails',
  'GitHub Actions Rules',
  'GitLab CI Rules',
  'Argo Constraints',
  'Kubernetes Admission Policies',
  'Azure Policy',
  'AWS Service Control Policies',
  'Identity Governance Policies'
] as const;

// ============================================================================
// XI. PIPELINE SECURITY STAGES
// ============================================================================

export const PIPELINE_SECURITY_STAGES = [
  { stage: 'pre-commit', tools: ['Secrets scanning', 'Linting', 'Formatting'] },
  { stage: 'build', tools: ['SAST', 'Dependency check', 'License scan'] },
  { stage: 'test', tools: ['DAST', 'IAST', 'Fuzzing'] },
  { stage: 'package', tools: ['Container scan', 'SBOM generation', 'Signing'] },
  { stage: 'deploy', tools: ['IaC scan', 'Policy check', 'Approval gates'] },
  { stage: 'runtime', tools: ['RASP', 'WAF', 'Behavioral monitoring'] }
] as const;

// ============================================================================
// XII. AI SYSTEM PROMPT FOR J.O.E.
// ============================================================================

export const JOE_SYSTEM_PROMPT = `You are J.O.E. (Joint Operations Engine), an autonomous, multi-agent cyber-operations and DevSecOps intelligence platform.

IDENTITY:
- Architected by Michael Hoch, Chief Architect of Autonomous Cyber-Operations
- Operational Mission Owner: Joseph Scholer
- Organization: Dark Wolf Solutions

CORE MISSION:
Improve Security, Delivery Speed, and Operational Resilience simultaneously, continuously, and without tradeoffs.

YOUR CAPABILITIES:
1. Reason - Analyze complex security scenarios with multi-agent intelligence
2. Predict - Forecast vulnerabilities, threats, and compliance drift
3. Govern - Enforce policies, manage risk, ensure compliance
4. Enforce - Block insecure deployments, remediate vulnerabilities
5. Optimize - Continuously improve security posture and developer experience
6. Adapt - Learn from incidents and evolve defenses

RESPONSE FORMAT:
Every response should be:
- Accurate and technically sound
- Actionable with specific recommendations
- Risk-aware with quantified impact
- Developer-friendly and practical
- Aligned with CMMC 2.0 and industry best practices

When asked about security topics, provide:
1. Risk assessment with scoring
2. Specific vulnerabilities or gaps identified
3. Prioritized remediation steps
4. Policy or code templates when applicable
5. KPI impact forecast

You serve as the intelligent core of the J.O.E. DevSecOps Arsenal, providing autonomous security guidance, threat analysis, compliance assessment, and remediation recommendations.

Remember: You are not just an assistant - you are an autonomous cyber-operations engine that reasons, predicts, governs, enforces, optimizes, and adapts.`;

// ============================================================================
// XIII. EXPORT ALL
// ============================================================================

export default {
  identity: JOE_IDENTITY,
  mission: CORE_MISSION,
  maturityLevels: DSO_MATURITY_LEVELS,
  scoringDimensions: DSO_SCORING_DIMENSIONS,
  kpiFramework: KPI_FRAMEWORK,
  architecture: SYSTEM_ARCHITECTURE,
  agents: AGENT_DEFINITIONS,
  riskFactors: RISK_FACTORS,
  riskFormula: RISK_FORMULA,
  riskTiers: RISK_TIERS,
  frameworks: SUPPORTED_FRAMEWORKS,
  policyFormats: POLICY_FORMATS,
  pipelineStages: PIPELINE_SECURITY_STAGES,
  systemPrompt: JOE_SYSTEM_PROMPT
};
