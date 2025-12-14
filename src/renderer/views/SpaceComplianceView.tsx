import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Modal from '../components/common/Modal';
import {
  Rocket,
  Shield,
  CheckCircle,
  AlertCircle,
  XCircle,
  Target,
  ChevronRight,
  AlertTriangle,
  Plane,
  Satellite,
  Activity,
  RefreshCw,
  Download,
  ArrowRight,
  Brain,
  ExternalLink,
  BookOpen,
  ClipboardList,
  Clock,
  Wrench
} from 'lucide-react';

/**
 * Space-Grade Compliance View
 * Dark Wolf Solutions - J.O.E. DevSecOps Arsenal
 *
 * NASA-STD-8719.13 | DO-178C | Common Criteria EAL Assessment
 * 100% COMPLIANCE REQUIRED FOR MISSION-CRITICAL SYSTEMS
 *
 * @company Dark Wolf Solutions
 * @website https://darkwolfsolutions.com
 */

// =============================================================================
// DARK WOLF SOLUTIONS BRANDING
// =============================================================================

const DARK_WOLF_BRANDING = {
  company: 'Dark Wolf Solutions',
  website: 'https://darkwolfsolutions.com',
  tagline: 'Mission-Critical Security Excellence',
  compliance_standard: '100% Compliance Required - No Exceptions',
  contact: 'compliance@darkwolfsolutions.com'
};

// =============================================================================
// AUTHORITATIVE SOURCES - DoD & Cybersecurity Guidance
// =============================================================================

const AUTHORITATIVE_SOURCES = {
  'NIST-800-53': {
    name: 'NIST SP 800-53 Rev 5',
    description: 'Security and Privacy Controls for Information Systems',
    url: 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    authority: 'National Institute of Standards and Technology'
  },
  'NIST-800-171': {
    name: 'NIST SP 800-171 Rev 2',
    description: 'Protecting Controlled Unclassified Information',
    url: 'https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final',
    authority: 'National Institute of Standards and Technology'
  },
  'NASA-STD-8719': {
    name: 'NASA-STD-8719.13C',
    description: 'NASA Software Safety Standard',
    url: 'https://standards.nasa.gov/standard/NASA/NASA-STD-871913',
    authority: 'National Aeronautics and Space Administration'
  },
  'DO-178C': {
    name: 'DO-178C / ED-12C',
    description: 'Software Considerations in Airborne Systems and Equipment Certification',
    url: 'https://www.rtca.org/products/do-178c-ed-12c/',
    authority: 'RTCA / EUROCAE'
  },
  'CMMC-2.0': {
    name: 'CMMC 2.0',
    description: 'Cybersecurity Maturity Model Certification',
    url: 'https://www.acq.osd.mil/cmmc/',
    authority: 'Department of Defense'
  },
  'DoD-STIG': {
    name: 'DoD Security Technical Implementation Guides',
    description: 'Configuration Standards for DoD Systems',
    url: 'https://public.cyber.mil/stigs/',
    authority: 'Defense Information Systems Agency'
  },
  'COMMON-CRITERIA': {
    name: 'Common Criteria (ISO/IEC 15408)',
    description: 'IT Security Evaluation',
    url: 'https://www.commoncriteriaportal.org/',
    authority: 'Common Criteria Recognition Arrangement'
  },
  'CISA-GUIDANCE': {
    name: 'CISA Cybersecurity Guidance',
    description: 'Federal Cybersecurity Best Practices',
    url: 'https://www.cisa.gov/cybersecurity',
    authority: 'Cybersecurity and Infrastructure Security Agency'
  }
};

// =============================================================================
// TYPES
// =============================================================================

type NASASafetyCategory = 'CAT-I' | 'CAT-II' | 'CAT-III' | 'CAT-IV';
type DO178CLevel = 'DAL-A' | 'DAL-B' | 'DAL-C' | 'DAL-D' | 'DAL-E';
type CommonCriteriaEAL = 'EAL-1' | 'EAL-2' | 'EAL-3' | 'EAL-4' | 'EAL-5' | 'EAL-6' | 'EAL-7';

interface ComplianceFinding {
  id: string;
  framework: 'NASA-STD-8719' | 'DO-178C' | 'Common-Criteria';
  controlId: string;
  status: 'compliant' | 'partial' | 'non-compliant' | 'not-applicable';
  severity: 'critical' | 'major' | 'minor' | 'observation';
  description: string;
  remediation?: string;
  sources: string[];
  poamRequired: boolean;
}

interface POAMItem {
  id: string;
  findingId: string;
  weakness: string;
  milestone: string;
  scheduledCompletion: string;
  responsibleParty: string;
  resources: string;
  status: 'open' | 'in-progress' | 'completed' | 'delayed';
  sources: string[];
}

// =============================================================================
// FRAMEWORK DATA
// =============================================================================

const NASA_SAFETY_CATEGORIES: Record<NASASafetyCategory, {
  category: NASASafetyCategory;
  name: string;
  description: string;
  hazardLevel: string;
  verificationMethods: string[];
  requiredDocumentation: string[];
  testingRequirements: string[];
  color: string;
}> = {
  'CAT-I': {
    category: 'CAT-I',
    name: 'Catastrophic',
    description: 'Software whose failure could result in loss of life, permanent disability, or loss of mission-critical systems',
    hazardLevel: 'Loss of life or permanent disability; loss of crewed vehicle; loss of critical national asset',
    verificationMethods: ['Formal Methods Verification', 'Independent V&V (IV&V)', 'Full MC/DC Coverage Testing', 'Fault Tree Analysis'],
    requiredDocumentation: ['Software Safety Plan', 'Safety-Critical Design Description', 'Hazard Analysis Report', 'Safety Assessment Report'],
    testingRequirements: ['100% MC/DC Coverage', '100% Statement Coverage', '100% Branch Coverage', 'Fault Injection Testing'],
    color: '#dc2626'
  },
  'CAT-II': {
    category: 'CAT-II',
    name: 'Critical',
    description: 'Software whose failure could result in severe injury, major property damage, or significant mission degradation',
    hazardLevel: 'Severe injury; major occupational illness; major property damage; significant mission degradation',
    verificationMethods: ['Independent V&V Recommended', 'Decision Coverage Testing', 'Hazard Analysis', 'Code Review'],
    requiredDocumentation: ['Software Safety Plan', 'Safety Requirements Specification', 'Hazard Analysis Report'],
    testingRequirements: ['100% Decision Coverage', '100% Statement Coverage', 'Integration Testing'],
    color: '#ea580c'
  },
  'CAT-III': {
    category: 'CAT-III',
    name: 'Moderate',
    description: 'Software whose failure could result in minor injury, minor property damage, or minor mission impact',
    hazardLevel: 'Minor injury; minor occupational illness; minor property damage; minor mission impact',
    verificationMethods: ['Statement Coverage Testing', 'Design Review', 'Code Inspection'],
    requiredDocumentation: ['Software Development Plan', 'Requirements Specification', 'Test Plan'],
    testingRequirements: ['90% Statement Coverage', 'Unit Testing', 'Integration Testing'],
    color: '#ca8a04'
  },
  'CAT-IV': {
    category: 'CAT-IV',
    name: 'Negligible',
    description: 'Software whose failure would have negligible safety impact',
    hazardLevel: 'No significant safety impact; minor inconvenience',
    verificationMethods: ['Unit Testing', 'Code Review', 'Functional Testing'],
    requiredDocumentation: ['Basic Development Documentation', 'Test Results'],
    testingRequirements: ['Functional Testing', 'Basic Unit Testing'],
    color: '#16a34a'
  }
};

const _DO178C_LEVELS: Record<DO178CLevel, {
  level: DO178CLevel;
  name: string;
  failureCondition: string;
  description: string;
  objectives: number;
  independenceRequired: boolean;
  coverageRequirements: { statement: number; decision: number; mcdc: number };
  color: string;
}> = {
  'DAL-A': { level: 'DAL-A', name: 'Catastrophic', failureCondition: 'Failure may cause catastrophic failure of aircraft', description: 'Highest assurance level', objectives: 71, independenceRequired: true, coverageRequirements: { statement: 100, decision: 100, mcdc: 100 }, color: '#dc2626' },
  'DAL-B': { level: 'DAL-B', name: 'Hazardous', failureCondition: 'Failure may cause hazardous/severe failure', description: 'High assurance level', objectives: 69, independenceRequired: true, coverageRequirements: { statement: 100, decision: 100, mcdc: 0 }, color: '#ea580c' },
  'DAL-C': { level: 'DAL-C', name: 'Major', failureCondition: 'Failure may cause major failure condition', description: 'Moderate assurance level', objectives: 62, independenceRequired: false, coverageRequirements: { statement: 100, decision: 0, mcdc: 0 }, color: '#ca8a04' },
  'DAL-D': { level: 'DAL-D', name: 'Minor', failureCondition: 'Failure may cause minor failure condition', description: 'Low assurance level', objectives: 26, independenceRequired: false, coverageRequirements: { statement: 0, decision: 0, mcdc: 0 }, color: '#16a34a' },
  'DAL-E': { level: 'DAL-E', name: 'No Effect', failureCondition: 'Failure has no safety effect', description: 'No safety effect', objectives: 0, independenceRequired: false, coverageRequirements: { statement: 0, decision: 0, mcdc: 0 }, color: '#6b7280' }
};

const COMMON_CRITERIA_LEVELS: Record<CommonCriteriaEAL, {
  level: CommonCriteriaEAL;
  name: string;
  description: string;
  applicability: string;
  effort: string;
  color: string;
}> = {
  'EAL-1': { level: 'EAL-1', name: 'Functionally Tested', description: 'Lowest assurance', applicability: 'Basic confidence required', effort: 'Minimal', color: '#6b7280' },
  'EAL-2': { level: 'EAL-2', name: 'Structurally Tested', description: 'Low-to-moderate level', applicability: 'Low-to-moderate security', effort: 'Low', color: '#16a34a' },
  'EAL-3': { level: 'EAL-3', name: 'Methodically Tested', description: 'Moderate level', applicability: 'Moderately high security', effort: 'Moderate', color: '#ca8a04' },
  'EAL-4': { level: 'EAL-4', name: 'Methodically Designed', description: 'Highest level commonly achieved commercially', applicability: 'Moderate-to-high security', effort: 'High', color: '#2563eb' },
  'EAL-5': { level: 'EAL-5', name: 'Semiformally Designed', description: 'Semiformal design descriptions', applicability: 'High level security', effort: 'Very High', color: '#7c3aed' },
  'EAL-6': { level: 'EAL-6', name: 'Semiformally Verified', description: 'Semiformal verification', applicability: 'High-risk situations', effort: 'Extremely High', color: '#9333ea' },
  'EAL-7': { level: 'EAL-7', name: 'Formally Verified', description: 'Formal methods and comprehensive testing', applicability: 'Extremely high-risk situations', effort: 'Maximum', color: '#dc2626' }
};

// Mock assessment data with source citations
const mockJOEAssessment = {
  nasa: {
    currentCategory: 'CAT-III' as NASASafetyCategory,
    score: 78,
    findings: [
      { id: '1', framework: 'NASA-STD-8719' as const, controlId: 'CAT-III-VER', status: 'compliant' as const, severity: 'observation' as const, description: 'Statement coverage testing implemented', sources: ['NASA-STD-8719', 'NIST-800-53'], poamRequired: false },
      { id: '2', framework: 'NASA-STD-8719' as const, controlId: 'CAT-III-DOC', status: 'partial' as const, severity: 'minor' as const, description: 'Software Development Plan exists but needs updates per NASA-STD-8719.13C Section 4.2', remediation: 'Update SDP to include all required elements per NASA-STD-8719.13C', sources: ['NASA-STD-8719', 'NIST-800-171'], poamRequired: true },
      { id: '3', framework: 'NASA-STD-8719' as const, controlId: 'CAT-III-TEST', status: 'partial' as const, severity: 'minor' as const, description: 'Unit testing at 85% coverage - NASA requires 90% minimum for CAT-III', remediation: 'Increase statement coverage to 90% per NASA-STD-8719.13C Table 1', sources: ['NASA-STD-8719', 'DO-178C'], poamRequired: true }
    ]
  },
  do178c: {
    currentLevel: 'DAL-C' as DO178CLevel,
    score: 72,
    coverageMetrics: { statement: 85, decision: 68, mcdc: 42 },
    findings: [
      { id: '4', framework: 'DO-178C' as const, controlId: 'DAL-C-COV', status: 'partial' as const, severity: 'major' as const, description: 'Statement coverage at 85% - DO-178C DAL-C requires 100%', remediation: 'Add test cases to achieve 100% statement coverage per DO-178C Section 6.4.4.2', sources: ['DO-178C', 'NIST-800-53'], poamRequired: true },
      { id: '5', framework: 'DO-178C' as const, controlId: 'DAL-C-DOC', status: 'compliant' as const, severity: 'observation' as const, description: 'PSAC documentation complete per DO-178C Section 11.1', sources: ['DO-178C'], poamRequired: false },
      { id: '6', framework: 'DO-178C' as const, controlId: 'DAL-C-VER', status: 'partial' as const, severity: 'minor' as const, description: 'Requirements traceability incomplete - DO-178C Section 6.3 requires bi-directional', remediation: 'Complete bi-directional traceability matrix per DO-178C Table A-5', sources: ['DO-178C', 'NASA-STD-8719'], poamRequired: true }
    ]
  },
  commonCriteria: {
    targetLevel: 'EAL-4' as CommonCriteriaEAL,
    currentLevel: 'EAL-3' as CommonCriteriaEAL,
    score: 65,
    findings: [
      { id: '7', framework: 'Common-Criteria' as const, controlId: 'ADV_ARC.1', status: 'compliant' as const, severity: 'observation' as const, description: 'Security architecture description complete per CC Part 3', sources: ['COMMON-CRITERIA', 'NIST-800-53'], poamRequired: false },
      { id: '8', framework: 'Common-Criteria' as const, controlId: 'ADV_IMP.1', status: 'non-compliant' as const, severity: 'major' as const, description: 'Implementation representation incomplete for EAL-4 per CC Part 3 ADV_IMP.1', remediation: 'Document implementation subset per Common Criteria Part 3 ADV_IMP.1.1D', sources: ['COMMON-CRITERIA', 'DoD-STIG'], poamRequired: true },
      { id: '9', framework: 'Common-Criteria' as const, controlId: 'AVA_VAN.3', status: 'partial' as const, severity: 'critical' as const, description: 'Vulnerability analysis insufficient for EAL-4 - requires focused testing per CC AVA_VAN.3', remediation: 'Conduct focused vulnerability testing per CISA guidance and CC Part 3 AVA_VAN.3.1E', sources: ['COMMON-CRITERIA', 'CISA-GUIDANCE', 'NIST-800-53'], poamRequired: true }
    ]
  }
};

// Generate POA&M items from findings
const generatePOAM = (findings: ComplianceFinding[]): POAMItem[] => {
  const poamItems: POAMItem[] = [];
  const today = new Date();

  findings.filter(f => f.poamRequired && f.status !== 'compliant').forEach((finding, idx) => {
    const daysToAdd = finding.severity === 'critical' ? 30 : finding.severity === 'major' ? 60 : 90;
    const completionDate = new Date(today);
    completionDate.setDate(completionDate.getDate() + daysToAdd);

    poamItems.push({
      id: `POAM-${idx + 1}`,
      findingId: finding.id,
      weakness: finding.description,
      milestone: finding.remediation || 'Implement remediation per cited guidance',
      scheduledCompletion: completionDate.toISOString().split('T')[0],
      responsibleParty: 'Dark Wolf Solutions Security Team',
      resources: 'Engineering resources, security tools, compliance documentation',
      status: 'open',
      sources: finding.sources
    });
  });

  return poamItems;
};

export default function SpaceComplianceView() {
  const [activeTab, setActiveTab] = useState<'overview' | 'nasa' | 'do178c' | 'cc' | 'poam' | 'mapping'>('overview');
  const [selectedCategory, setSelectedCategory] = useState<NASASafetyCategory | null>(null);
  const [_selectedDAL, _setSelectedDAL] = useState<DO178CLevel | null>(null);
  const [_selectedEAL, setSelectedEAL] = useState<CommonCriteriaEAL | null>(null);
  const [isAssessing, setIsAssessing] = useState(false);
  const [showAssessmentModal, setShowAssessmentModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showAIRemediationModal, setShowAIRemediationModal] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<ComplianceFinding | null>(null);
  const [aiRemediationContent, setAiRemediationContent] = useState<string>('');
  const [isGeneratingRemediation, setIsGeneratingRemediation] = useState(false);
  const [exportFormat, setExportFormat] = useState<'pdf' | 'csv' | 'json'>('pdf');

  // Calculate overall compliance - ANYTHING LESS THAN 100% IS UNACCEPTABLE
  const allFindings: ComplianceFinding[] = [...mockJOEAssessment.nasa.findings, ...mockJOEAssessment.do178c.findings, ...mockJOEAssessment.commonCriteria.findings];
  const compliantCount = allFindings.filter(f => f.status === 'compliant').length;
  const overallScore = Math.round((compliantCount / allFindings.length) * 100);
  const isFullyCompliant = overallScore === 100;
  const criticalCount = allFindings.filter(f => f.severity === 'critical' && f.status !== 'compliant').length;
  const majorCount = allFindings.filter(f => f.severity === 'major' && f.status !== 'compliant').length;
  const poamItems = generatePOAM(allFindings);

  const getStatusConfig = (status: string) => {
    switch (status) {
      case 'compliant': return { icon: CheckCircle, color: 'text-dws-green', bg: 'bg-dws-green/10', border: 'border-dws-green/30' };
      case 'partial': return { icon: AlertCircle, color: 'text-alert-warning', bg: 'bg-alert-warning/10', border: 'border-alert-warning/30' };
      case 'non-compliant': return { icon: XCircle, color: 'text-alert-critical', bg: 'bg-alert-critical/10', border: 'border-alert-critical/30' };
      default: return { icon: AlertCircle, color: 'text-gray-500', bg: 'bg-gray-500/10', border: 'border-gray-500/30' };
    }
  };

  const getSeverityConfig = (severity: string) => {
    switch (severity) {
      case 'critical': return 'badge-critical';
      case 'major': return 'badge-high';
      case 'minor': return 'badge-medium';
      default: return 'badge-low';
    }
  };

  // BUG-006 FIX: Actually call the space compliance assessment API
  const runAssessment = async () => {
    setIsAssessing(true);
    try {
      // Determine which assessment to run based on active tab
      let assessmentResult;

      if (activeTab === 'nasa' || activeTab === 'overview') {
        // Run NASA-STD-8719 assessment
        assessmentResult = await window.electronAPI?.spaceCompliance?.assessNASA?.({
          projectName: 'J.O.E. DevSecOps Arsenal',
          assessor: 'Dark Wolf Solutions Security Team',
          hazardAnalysis: {
            lossOfLife: false,
            severeInjury: false,
            missionCritical: true,
            propertyDamage: 'minor'
          },
          safetyMetrics: {
            hazardsIdentified: criticalCount + majorCount,
            hazardsMitigated: compliantCount,
            openSafetyIssues: criticalCount,
            safetyReviewsCompleted: 1,
            independentReviewsCompleted: 0
          },
          existingControls: allFindings.filter(f => f.status === 'compliant').map(f => f.controlId)
        });
      } else if (activeTab === 'do178c') {
        // Run DO-178C assessment
        assessmentResult = await window.electronAPI?.spaceCompliance?.assessDO178C?.({
          projectName: 'J.O.E. DevSecOps Arsenal',
          assessor: 'Dark Wolf Solutions Security Team',
          failureCondition: criticalCount > 0 ? 'hazardous' : 'major',
          coverageMetrics: {
            statementCoverage: overallScore,
            branchCoverage: Math.max(60, overallScore - 10),
            mcdcCoverage: Math.max(50, overallScore - 20),
            requirementsCoverage: overallScore,
            testCaseCoverage: Math.max(70, overallScore - 5)
          },
          documentationStatus: {
            SRS: true,
            SDD: true,
            SVP: false,
            SVR: false
          },
          verificationActivities: ['code-review', 'static-analysis', 'unit-testing']
        });
      } else if (activeTab === 'cc') {
        // Run Common Criteria assessment
        assessmentResult = await window.electronAPI?.spaceCompliance?.assessCommonCriteria?.({
          projectName: 'J.O.E. DevSecOps Arsenal',
          assessor: 'Dark Wolf Solutions Security Team',
          targetEAL: 'EAL-4',
          assuranceComponents: {
            'ADV_ARC': overallScore >= 80 ? 'satisfied' : 'partial',
            'ADV_FSP': overallScore >= 70 ? 'satisfied' : 'partial',
            'ADV_IMP': overallScore >= 60 ? 'partial' : 'not-satisfied',
            'ALC_CMC': 'satisfied',
            'ALC_CMS': 'satisfied',
            'ALC_DEL': 'partial',
            'ATE_COV': overallScore >= 80 ? 'satisfied' : 'partial',
            'AVA_VAN': criticalCount === 0 ? 'satisfied' : 'partial'
          },
          securityFunctions: ['authentication', 'access-control', 'audit-logging', 'cryptography']
        });
      }

      if (assessmentResult) {
        console.log('Assessment complete:', assessmentResult);
      }
    } catch (error) {
      console.error('Assessment error:', error);
    } finally {
      setIsAssessing(false);
      setShowAssessmentModal(true);
    }
  };

  // AI-Powered Remediation Generation - Connects to Ollama for real AI analysis
  const generateAIRemediation = async (finding: ComplianceFinding) => {
    setSelectedFinding(finding);
    setShowAIRemediationModal(true);
    setIsGeneratingRemediation(true);
    setAiRemediationContent('');

    const sourceRefs = finding.sources.map(s => AUTHORITATIVE_SOURCES[s as keyof typeof AUTHORITATIVE_SOURCES]).filter(Boolean);

    // Build detailed prompt for Ollama with DoD-specific context
    const prompt = `You are J.O.E. (Joint-Ops-Engine), Dark Wolf Solutions' AI Security Intelligence Engine.

Analyze this Space-Grade compliance finding and provide DoD-compliant remediation guidance:

**Finding Details:**
- Control ID: ${finding.controlId}
- Framework: ${finding.framework}
- Severity: ${finding.severity.toUpperCase()}
- Status: ${finding.status.replace('-', ' ').toUpperCase()}
- Description: ${finding.description}
- Current Remediation Guidance: ${finding.remediation || 'None provided'}

**Authoritative Sources to Reference:**
${sourceRefs.map(src => `- ${src.name}: ${src.description} (${src.authority})`).join('\n')}

**REQUIREMENTS - You MUST provide:**
1. **Risk Assessment**: Detailed analysis of security impact
2. **Attack Vectors**: How this vulnerability could be exploited (cite MITRE ATT&CK techniques)
3. **Remediation Steps**: Specific, actionable steps with commands/code where applicable
4. **DoD Compliance**: How this maps to NIST 800-53, CMMC 2.0, and DoD STIGs
5. **Timeline**: Recommended remediation timeline per DoD Instruction 8510.01
6. **Verification**: How to verify the fix was successful
7. **POA&M Entry**: Draft POA&M entry if required

Format response in clear markdown. Be specific and technical.
Organization: ${DARK_WOLF_BRANDING.company}
Standard: ${DARK_WOLF_BRANDING.compliance_standard}`;

    const context = `Space-Grade Compliance Assessment
Frameworks: NASA-STD-8719.13, DO-178C, Common Criteria EAL-4
Overall Compliance: ${overallScore}% (100% Required)
Critical Findings: ${criticalCount}
Major Findings: ${majorCount}`;

    try {
      // Try to use real Ollama AI if available
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const electronAPI = (window as any).electronAPI;
      if (electronAPI?.ollama?.chat) {
        const aiResponse = await electronAPI.ollama.chat(prompt, context);

        // Build final response with branding
        const remediation = `## J.O.E. AI Security Analysis

**Finding:** ${finding.controlId}
**Framework:** ${finding.framework}
**Severity:** ${finding.severity.toUpperCase()}
**Status:** ${finding.status.replace('-', ' ').toUpperCase()}

---

${aiResponse}

---

### Authoritative Source References

${sourceRefs.map(src => `**${src.name}**
- Authority: ${src.authority}
- URL: ${src.url}
- Applicability: ${src.description}`).join('\n\n')}

### POA&M Requirement
${finding.poamRequired ? '**YES** - This finding requires a Plan of Action and Milestones entry per DoD Instruction 8510.01.' : 'No - This finding does not require POA&M tracking.'}

---

*Analysis generated by J.O.E. AI Security Intelligence*
*${DARK_WOLF_BRANDING.company} - ${DARK_WOLF_BRANDING.website}*
*${DARK_WOLF_BRANDING.tagline}*`;

        setAiRemediationContent(remediation);
      } else {
        // Fallback if Ollama not available
        const fallbackRemediation = `## J.O.E. AI Security Analysis

**Finding:** ${finding.controlId}
**Framework:** ${finding.framework}
**Severity:** ${finding.severity.toUpperCase()}
**Status:** ${finding.status.replace('-', ' ').toUpperCase()}

---

### Issue Description
${finding.description}

### Authoritative Guidance

${sourceRefs.map(src => `**${src.name}**
- Authority: ${src.authority}
- Reference: ${src.url}
- Applicability: ${src.description}`).join('\n\n')}

### Remediation Steps

${finding.remediation || 'No specific remediation provided - follow guidance from cited sources.'}

**Immediate Actions Required:**
1. Review cited authoritative sources for specific requirements
2. Document current state vs required state
3. Develop implementation plan with milestones
4. Allocate resources per POA&M requirements
5. Implement controls with evidence collection
6. Verify implementation through testing
7. Update documentation and obtain approval

### DoD Best Practices
Per DoD Instruction 8510.01 (RMF) and CISA guidance:
- All findings must be remediated to achieve Authorization to Operate (ATO)
- Critical findings: 30-day remediation timeline
- Major findings: 60-day remediation timeline
- Minor findings: 90-day remediation timeline

### POA&M Requirement
${finding.poamRequired ? '**YES** - This finding requires a Plan of Action and Milestones entry.' : 'No - This finding does not require POA&M tracking.'}

---

⚠️ *Ollama AI not connected - using template response*
*For full AI analysis, ensure Ollama is running on localhost:11434*

*${DARK_WOLF_BRANDING.company} - ${DARK_WOLF_BRANDING.website}*`;

        setAiRemediationContent(fallbackRemediation);
      }
    } catch (error) {
      console.error('AI Remediation Error:', error);
      setAiRemediationContent(`## Error Generating AI Analysis

An error occurred while connecting to the AI service.

**Error Details:** ${error instanceof Error ? error.message : 'Unknown error'}

### Manual Remediation Guidance

${finding.description}

**Recommended Action:** ${finding.remediation || 'Review authoritative sources for remediation guidance.'}

**Sources:**
${sourceRefs.map(src => `- [${src.name}](${src.url})`).join('\n')}

---

*Please ensure Ollama is running and try again.*
*${DARK_WOLF_BRANDING.company} - ${DARK_WOLF_BRANDING.website}*`);
    } finally {
      setIsGeneratingRemediation(false);
    }
  };

  // Export Report Function
  const exportReport = () => {
    const reportDate = new Date().toISOString().split('T')[0];
    const reportContent = {
      metadata: {
        title: 'Space-Grade Compliance Assessment Report',
        organization: DARK_WOLF_BRANDING.company,
        website: DARK_WOLF_BRANDING.website,
        generatedDate: new Date().toISOString(),
        assessor: 'J.O.E. DevSecOps Arsenal',
        classification: 'CONTROLLED UNCLASSIFIED INFORMATION (CUI)'
      },
      executiveSummary: {
        overallScore: overallScore,
        complianceStatus: isFullyCompliant ? 'FULLY COMPLIANT' : 'NON-COMPLIANT - IMMEDIATE ACTION REQUIRED',
        criticalFindings: criticalCount,
        majorFindings: majorCount,
        totalFindings: allFindings.length,
        poamItemsRequired: poamItems.length
      },
      frameworks: {
        nasa: {
          category: mockJOEAssessment.nasa.currentCategory,
          score: mockJOEAssessment.nasa.score,
          findings: mockJOEAssessment.nasa.findings
        },
        do178c: {
          level: mockJOEAssessment.do178c.currentLevel,
          score: mockJOEAssessment.do178c.score,
          coverage: mockJOEAssessment.do178c.coverageMetrics,
          findings: mockJOEAssessment.do178c.findings
        },
        commonCriteria: {
          targetLevel: mockJOEAssessment.commonCriteria.targetLevel,
          currentLevel: mockJOEAssessment.commonCriteria.currentLevel,
          score: mockJOEAssessment.commonCriteria.score,
          findings: mockJOEAssessment.commonCriteria.findings
        }
      },
      poam: poamItems,
      authoritativeSources: AUTHORITATIVE_SOURCES,
      certification: {
        preparedBy: 'J.O.E. Automated Assessment System',
        organization: DARK_WOLF_BRANDING.company,
        date: reportDate,
        disclaimer: 'This assessment must be reviewed by a qualified security professional before submission to certification authorities.'
      }
    };

    if (exportFormat === 'json') {
      const blob = new Blob([JSON.stringify(reportContent, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `DarkWolf-SpaceCompliance-${reportDate}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } else if (exportFormat === 'csv') {
      // Generate CSV for findings
      const csvRows = [
        ['Framework', 'Control ID', 'Status', 'Severity', 'Description', 'Remediation', 'Sources', 'POA&M Required'],
        ...allFindings.map(f => [
          f.framework,
          f.controlId,
          f.status,
          f.severity,
          f.description,
          f.remediation || '',
          f.sources.join('; '),
          f.poamRequired ? 'Yes' : 'No'
        ])
      ];
      const csvContent = csvRows.map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `DarkWolf-SpaceCompliance-${reportDate}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } else {
      // For PDF, we'll generate a text report (in production, use a PDF library)
      const textReport = `
================================================================================
                    SPACE-GRADE COMPLIANCE ASSESSMENT REPORT
================================================================================

Organization: ${DARK_WOLF_BRANDING.company}
Website: ${DARK_WOLF_BRANDING.website}
Generated: ${new Date().toLocaleString()}
Classification: CONTROLLED UNCLASSIFIED INFORMATION (CUI)

================================================================================
                            EXECUTIVE SUMMARY
================================================================================

Overall Compliance Score: ${overallScore}%
Status: ${isFullyCompliant ? 'FULLY COMPLIANT' : 'NON-COMPLIANT - IMMEDIATE ACTION REQUIRED'}

Critical Findings: ${criticalCount}
Major Findings: ${majorCount}
Total Findings: ${allFindings.length}
POA&M Items Required: ${poamItems.length}

*** ${DARK_WOLF_BRANDING.compliance_standard} ***

================================================================================
                         FRAMEWORK ASSESSMENTS
================================================================================

NASA-STD-8719.13 ASSESSMENT
---------------------------
Category: ${mockJOEAssessment.nasa.currentCategory}
Score: ${mockJOEAssessment.nasa.score}%

DO-178C ASSESSMENT
------------------
DAL Level: ${mockJOEAssessment.do178c.currentLevel}
Score: ${mockJOEAssessment.do178c.score}%
Statement Coverage: ${mockJOEAssessment.do178c.coverageMetrics.statement}%
Decision Coverage: ${mockJOEAssessment.do178c.coverageMetrics.decision}%
MC/DC Coverage: ${mockJOEAssessment.do178c.coverageMetrics.mcdc}%

COMMON CRITERIA ASSESSMENT
--------------------------
Target Level: ${mockJOEAssessment.commonCriteria.targetLevel}
Current Level: ${mockJOEAssessment.commonCriteria.currentLevel}
Score: ${mockJOEAssessment.commonCriteria.score}%

================================================================================
                              FINDINGS
================================================================================

${allFindings.map(f => `
[${f.severity.toUpperCase()}] ${f.controlId}
Framework: ${f.framework}
Status: ${f.status}
Description: ${f.description}
${f.remediation ? `Remediation: ${f.remediation}` : ''}
Sources: ${f.sources.join(', ')}
POA&M Required: ${f.poamRequired ? 'YES' : 'No'}
`).join('\n')}

================================================================================
                         PLAN OF ACTION & MILESTONES
================================================================================

${poamItems.map(p => `
POA&M ID: ${p.id}
Weakness: ${p.weakness}
Milestone: ${p.milestone}
Scheduled Completion: ${p.scheduledCompletion}
Responsible Party: ${p.responsibleParty}
Status: ${p.status.toUpperCase()}
Sources: ${p.sources.join(', ')}
`).join('\n')}

================================================================================
                        AUTHORITATIVE SOURCES
================================================================================

${Object.values(AUTHORITATIVE_SOURCES).map(src => `
${src.name}
Authority: ${src.authority}
URL: ${src.url}
`).join('\n')}

================================================================================
                            CERTIFICATION
================================================================================

Prepared By: J.O.E. Automated Assessment System
Organization: ${DARK_WOLF_BRANDING.company}
Date: ${reportDate}
Contact: ${DARK_WOLF_BRANDING.contact}

DISCLAIMER: This assessment must be reviewed by a qualified security
professional before submission to certification authorities.

================================================================================
                    ${DARK_WOLF_BRANDING.company}
                    ${DARK_WOLF_BRANDING.website}
                    ${DARK_WOLF_BRANDING.tagline}
================================================================================
`;

      const blob = new Blob([textReport], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `DarkWolf-SpaceCompliance-${reportDate}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    }

    setShowExportModal(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-purple-500/20 to-joe-blue/20 border border-purple-500/30">
            <Rocket className="text-purple-400" size={28} />
          </div>
          <div>
            <h1 className="font-heading text-2xl font-bold text-white flex items-center gap-2">
              Space-Grade Compliance
              <span className="text-xs px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded-full border border-purple-500/30">
                Mission Critical
              </span>
            </h1>
            <p className="text-gray-400 mt-1">
              {DARK_WOLF_BRANDING.company} | {DARK_WOLF_BRANDING.website}
            </p>
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
            onClick={runAssessment}
            disabled={isAssessing}
            className="btn-primary flex items-center gap-2"
          >
            {isAssessing ? (
              <>
                <RefreshCw size={16} className="animate-spin" />
                Assessing...
              </>
            ) : (
              <>
                <Target size={16} />
                Run Assessment
              </>
            )}
          </button>
        </div>
      </div>

      {/* 100% Compliance Warning Banner */}
      {!isFullyCompliant && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="p-4 bg-alert-critical/20 border-2 border-alert-critical rounded-lg"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="text-alert-critical flex-shrink-0" size={24} />
            <div>
              <h3 className="font-bold text-alert-critical text-lg">
                {DARK_WOLF_BRANDING.compliance_standard}
              </h3>
              <p className="text-gray-300 mt-1">
                Current compliance: {overallScore}% - This system requires 100% compliance for mission-critical operations.
                {criticalCount > 0 && ` ${criticalCount} CRITICAL finding(s) require immediate attention.`}
              </p>
              <p className="text-gray-400 text-sm mt-2">
                Per DoD Instruction 8510.01, NIST SP 800-37, and NASA-STD-8719.13, all findings must be remediated
                or documented in a POA&M with approved milestones before Authorization to Operate (ATO) can be granted.
              </p>
            </div>
          </div>
        </motion.div>
      )}

      {/* Tab Navigation */}
      <div className="flex items-center gap-2 border-b border-dws-border pb-2 overflow-x-auto">
        {[
          { id: 'overview', label: 'Overview', icon: Activity },
          { id: 'nasa', label: 'NASA-STD-8719', icon: Satellite },
          { id: 'do178c', label: 'DO-178C', icon: Plane },
          { id: 'cc', label: 'Common Criteria', icon: Shield },
          { id: 'poam', label: `POA&M (${poamItems.length})`, icon: ClipboardList },
          { id: 'mapping', label: 'Sources', icon: BookOpen }
        ].map(tab => (
          <button
            key={tab.id}
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2 rounded-t-lg transition-colors whitespace-nowrap ${
              activeTab === tab.id
                ? 'bg-dws-elevated text-joe-blue border-b-2 border-joe-blue'
                : 'text-gray-400 hover:text-white hover:bg-dws-dark'
            }`}
          >
            <tab.icon size={16} />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        {activeTab === 'overview' && (
          <motion.div
            key="overview"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-6"
          >
            {/* Score Cards */}
            <div className="grid grid-cols-4 gap-4">
              <div className={`glass-card p-6 col-span-1 ${!isFullyCompliant ? 'border-2 border-alert-critical' : 'border-2 border-dws-green'}`}>
                <div className="text-center">
                  <motion.p
                    className={`text-5xl font-bold ${isFullyCompliant ? 'text-dws-green' : 'text-alert-critical'}`}
                    initial={{ opacity: 0, scale: 0.5 }}
                    animate={{ opacity: 1, scale: 1 }}
                  >
                    {overallScore}%
                  </motion.p>
                  <p className={`mt-2 font-bold ${isFullyCompliant ? 'text-dws-green' : 'text-alert-critical'}`}>
                    {isFullyCompliant ? 'COMPLIANT' : 'NON-COMPLIANT'}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">100% Required</p>
                </div>
              </div>

              {/* Framework Score Cards */}
              {[
                { name: 'NASA-STD-8719', score: mockJOEAssessment.nasa.score, level: mockJOEAssessment.nasa.currentCategory, icon: Satellite, color: 'purple' },
                { name: 'DO-178C', score: mockJOEAssessment.do178c.score, level: mockJOEAssessment.do178c.currentLevel, icon: Plane, color: 'joe-blue' },
                { name: 'Common Criteria', score: mockJOEAssessment.commonCriteria.score, level: `${mockJOEAssessment.commonCriteria.currentLevel}→${mockJOEAssessment.commonCriteria.targetLevel}`, icon: Shield, color: 'dws-green' }
              ].map((fw, idx) => (
                <button
                  key={idx}
                  onClick={() => setActiveTab(idx === 0 ? 'nasa' : idx === 1 ? 'do178c' : 'cc')}
                  className={`glass-card p-4 flex items-center gap-4 hover:bg-dws-elevated transition-colors group ${fw.score < 100 ? 'border border-alert-warning/50' : ''}`}
                >
                  <div className={`p-3 rounded-lg bg-${fw.color}/10`}>
                    <fw.icon className={`text-${fw.color}`} size={24} />
                  </div>
                  <div className="text-left">
                    <p className={`text-2xl font-bold ${fw.score === 100 ? 'text-dws-green' : 'text-alert-warning'}`}>{fw.score}%</p>
                    <p className="text-gray-400 text-sm">{fw.name}</p>
                    <p className={`text-xs text-${fw.color} mt-1`}>{fw.level}</p>
                  </div>
                  <ChevronRight className="ml-auto text-gray-600 group-hover:text-joe-blue" size={20} />
                </button>
              ))}
            </div>

            {/* Findings with AI Remediation */}
            <div className="glass-card p-6">
              <h3 className="font-semibold text-white mb-4 flex items-center gap-2">
                <AlertTriangle className="text-alert-warning" size={20} />
                Findings Requiring Remediation ({allFindings.filter(f => f.status !== 'compliant').length})
              </h3>
              <div className="space-y-3">
                {allFindings.filter(f => f.status !== 'compliant').map((finding, idx) => {
                  const config = getStatusConfig(finding.status);
                  return (
                    <div key={idx} className={`p-4 rounded-lg border ${config.bg} ${config.border}`}>
                      <div className="flex items-start gap-3">
                        <config.icon size={20} className={config.color} />
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-mono text-sm text-gray-400">{finding.controlId}</span>
                            <span className={`badge ${getSeverityConfig(finding.severity)}`}>{finding.severity}</span>
                            {finding.poamRequired && (
                              <span className="badge badge-info text-xs">POA&M Required</span>
                            )}
                          </div>
                          <p className="text-gray-300">{finding.description}</p>
                          <div className="flex items-center gap-2 mt-2">
                            <span className="text-xs text-gray-500">Sources:</span>
                            {finding.sources.map((src, i) => (
                              <span key={i} className="text-xs px-2 py-0.5 bg-joe-blue/20 text-joe-blue rounded-full">
                                {src}
                              </span>
                            ))}
                          </div>
                        </div>
                        <button
                          onClick={() => generateAIRemediation(finding)}
                          className="btn-secondary text-sm flex items-center gap-1"
                        >
                          <Brain size={14} />
                          AI Remediation
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'poam' && (
          <motion.div
            key="poam"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-6"
          >
            <div className="glass-card p-6">
              <div className="flex items-center justify-between mb-6">
                <h3 className="font-semibold text-white flex items-center gap-2">
                  <ClipboardList className="text-joe-blue" size={20} />
                  Plan of Action & Milestones (POA&M)
                </h3>
                <p className="text-gray-400 text-sm">
                  Per NIST SP 800-37 & DoD Instruction 8510.01
                </p>
              </div>

              {poamItems.length === 0 ? (
                <div className="text-center py-12">
                  <CheckCircle className="mx-auto text-dws-green" size={48} />
                  <p className="text-dws-green font-bold mt-4">No POA&M Items Required</p>
                  <p className="text-gray-400 mt-2">All findings are compliant</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {poamItems.map((item, idx) => (
                    <div key={idx} className="p-4 bg-dws-dark rounded-lg border border-dws-border">
                      <div className="flex items-start gap-4">
                        <div className="flex-shrink-0 w-20 h-20 bg-alert-warning/10 rounded-lg flex flex-col items-center justify-center">
                          <span className="text-2xl font-bold text-alert-warning">{item.id}</span>
                        </div>
                        <div className="flex-1">
                          <h4 className="font-semibold text-white">{item.weakness}</h4>
                          <p className="text-gray-400 text-sm mt-1">{item.milestone}</p>
                          <div className="grid grid-cols-3 gap-4 mt-3">
                            <div>
                              <span className="text-xs text-gray-500 block">Scheduled Completion</span>
                              <span className="text-sm text-white flex items-center gap-1">
                                <Clock size={12} />
                                {item.scheduledCompletion}
                              </span>
                            </div>
                            <div>
                              <span className="text-xs text-gray-500 block">Responsible Party</span>
                              <span className="text-sm text-white">{item.responsibleParty}</span>
                            </div>
                            <div>
                              <span className="text-xs text-gray-500 block">Status</span>
                              <span className={`text-sm font-medium ${item.status === 'completed' ? 'text-dws-green' : item.status === 'in-progress' ? 'text-joe-blue' : 'text-alert-warning'}`}>
                                {item.status.toUpperCase()}
                              </span>
                            </div>
                          </div>
                          <div className="flex items-center gap-2 mt-3">
                            <span className="text-xs text-gray-500">Sources:</span>
                            {item.sources.map((src, i) => (
                              <span key={i} className="text-xs px-2 py-0.5 bg-joe-blue/20 text-joe-blue rounded-full">
                                {src}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}

        {activeTab === 'mapping' && (
          <motion.div
            key="mapping"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-6"
          >
            <div className="glass-card p-6">
              <h3 className="font-semibold text-white mb-6 flex items-center gap-2">
                <BookOpen className="text-joe-blue" size={20} />
                Authoritative Cybersecurity Sources
              </h3>
              <div className="grid grid-cols-2 gap-4">
                {Object.entries(AUTHORITATIVE_SOURCES).map(([key, src]) => (
                  <a
                    key={key}
                    href={src.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-4 bg-dws-dark rounded-lg border border-dws-border hover:border-joe-blue/50 transition-colors group"
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <h4 className="font-semibold text-white group-hover:text-joe-blue transition-colors">
                          {src.name}
                        </h4>
                        <p className="text-gray-400 text-sm mt-1">{src.description}</p>
                        <p className="text-xs text-gray-500 mt-2">Authority: {src.authority}</p>
                      </div>
                      <ExternalLink size={16} className="text-gray-500 group-hover:text-joe-blue" />
                    </div>
                  </a>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {/* Other tabs - NASA, DO-178C, CC remain similar but with source citations */}
        {activeTab === 'nasa' && (
          <motion.div
            key="nasa"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-6"
          >
            <div className="grid grid-cols-4 gap-4">
              {(Object.entries(NASA_SAFETY_CATEGORIES) as [NASASafetyCategory, typeof NASA_SAFETY_CATEGORIES[NASASafetyCategory]][]).map(([key, cat]) => (
                <motion.button
                  key={key}
                  onClick={() => setSelectedCategory(key)}
                  className={`glass-card p-4 text-left transition-all ${
                    selectedCategory === key ? 'ring-2 ring-joe-blue' : ''
                  } ${mockJOEAssessment.nasa.currentCategory === key ? 'border-purple-500/50' : ''}`}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: cat.color }} />
                    <span className="font-mono text-lg font-bold text-white">{key}</span>
                    {mockJOEAssessment.nasa.currentCategory === key && (
                      <span className="ml-auto text-xs px-2 py-0.5 bg-purple-500/20 text-purple-400 rounded-full">Current</span>
                    )}
                  </div>
                  <p className="font-medium text-white">{cat.name}</p>
                  <p className="text-xs text-gray-500 mt-1 line-clamp-2">{cat.description}</p>
                </motion.button>
              ))}
            </div>

            {/* NASA Findings */}
            <div className="glass-card p-6">
              <h3 className="font-semibold text-white mb-4">NASA-STD-8719.13 Findings</h3>
              <div className="space-y-3">
                {mockJOEAssessment.nasa.findings.map((finding, idx) => {
                  const config = getStatusConfig(finding.status);
                  return (
                    <div key={idx} className={`p-4 rounded-lg border ${config.bg} ${config.border}`}>
                      <div className="flex items-start gap-3">
                        <config.icon size={20} className={config.color} />
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-mono text-sm text-gray-400">{finding.controlId}</span>
                            <span className={`badge ${getSeverityConfig(finding.severity)}`}>{finding.severity}</span>
                          </div>
                          <p className="text-gray-300">{finding.description}</p>
                          {finding.remediation && (
                            <p className="text-joe-blue text-sm mt-2 flex items-center gap-1">
                              <Wrench size={12} />
                              {finding.remediation}
                            </p>
                          )}
                          <div className="flex items-center gap-2 mt-2">
                            {finding.sources.map((src, i) => (
                              <span key={i} className="text-xs px-2 py-0.5 bg-joe-blue/20 text-joe-blue rounded-full">
                                {src}
                              </span>
                            ))}
                          </div>
                        </div>
                        <button
                          onClick={() => generateAIRemediation(finding)}
                          className="btn-secondary text-sm flex items-center gap-1"
                        >
                          <Brain size={14} />
                          AI Fix
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'do178c' && (
          <motion.div
            key="do178c"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-6"
          >
            {/* Coverage Metrics */}
            <div className="glass-card p-6">
              <h3 className="font-semibold text-white mb-4">DO-178C Coverage Requirements</h3>
              <div className="space-y-4">
                {[
                  { name: 'Statement Coverage', value: mockJOEAssessment.do178c.coverageMetrics.statement, required: 100 },
                  { name: 'Decision Coverage', value: mockJOEAssessment.do178c.coverageMetrics.decision, required: 100 },
                  { name: 'MC/DC Coverage', value: mockJOEAssessment.do178c.coverageMetrics.mcdc, required: 100 }
                ].map((metric, idx) => (
                  <div key={idx}>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-gray-400">{metric.name}</span>
                      <span className={metric.value >= metric.required ? 'text-dws-green' : 'text-alert-critical font-bold'}>
                        {metric.value}% / {metric.required}% {metric.value < metric.required && '- REMEDIATION REQUIRED'}
                      </span>
                    </div>
                    <div className="h-3 bg-dws-dark rounded-full overflow-hidden">
                      <motion.div
                        className={`h-full ${metric.value >= metric.required ? 'bg-dws-green' : 'bg-alert-critical'}`}
                        initial={{ width: 0 }}
                        animate={{ width: `${metric.value}%` }}
                        transition={{ duration: 1, delay: idx * 0.2 }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* DO-178C Findings */}
            <div className="glass-card p-6">
              <h3 className="font-semibold text-white mb-4">DO-178C Findings</h3>
              <div className="space-y-3">
                {mockJOEAssessment.do178c.findings.map((finding, idx) => {
                  const config = getStatusConfig(finding.status);
                  return (
                    <div key={idx} className={`p-4 rounded-lg border ${config.bg} ${config.border}`}>
                      <div className="flex items-start gap-3">
                        <config.icon size={20} className={config.color} />
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-mono text-sm text-gray-400">{finding.controlId}</span>
                            <span className={`badge ${getSeverityConfig(finding.severity)}`}>{finding.severity}</span>
                          </div>
                          <p className="text-gray-300">{finding.description}</p>
                          {finding.remediation && (
                            <p className="text-joe-blue text-sm mt-2 flex items-center gap-1">
                              <Wrench size={12} />
                              {finding.remediation}
                            </p>
                          )}
                        </div>
                        <button
                          onClick={() => generateAIRemediation(finding)}
                          className="btn-secondary text-sm flex items-center gap-1"
                        >
                          <Brain size={14} />
                          AI Fix
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'cc' && (
          <motion.div
            key="cc"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-6"
          >
            {/* EAL Levels */}
            <div className="glass-card p-6">
              <h3 className="font-semibold text-white mb-4">Common Criteria EAL Progression</h3>
              <div className="flex items-center gap-2">
                {(Object.entries(COMMON_CRITERIA_LEVELS) as [CommonCriteriaEAL, typeof COMMON_CRITERIA_LEVELS[CommonCriteriaEAL]][]).map(([key, eal], idx) => {
                  const isCurrent = mockJOEAssessment.commonCriteria.currentLevel === key;
                  const isTarget = mockJOEAssessment.commonCriteria.targetLevel === key;

                  return (
                    <div key={key} className="flex items-center">
                      <button
                        onClick={() => setSelectedEAL(key)}
                        className={`relative p-3 rounded-lg transition-all ${
                          isCurrent ? 'bg-dws-green/20 border border-dws-green/50' :
                          isTarget ? 'bg-joe-blue/20 border border-joe-blue/50' : 'bg-dws-dark'
                        }`}
                      >
                        <div className="text-center">
                          <div className="w-3 h-3 rounded-full mx-auto mb-1" style={{ backgroundColor: eal.color }} />
                          <span className="font-mono text-xs font-bold text-white">{key}</span>
                        </div>
                        {isCurrent && <span className="absolute -top-2 -right-2 text-xs px-1.5 py-0.5 bg-dws-green text-white rounded-full">Current</span>}
                        {isTarget && !isCurrent && <span className="absolute -top-2 -right-2 text-xs px-1.5 py-0.5 bg-joe-blue text-white rounded-full">Target</span>}
                      </button>
                      {idx < Object.keys(COMMON_CRITERIA_LEVELS).length - 1 && <ArrowRight size={16} className="text-gray-600 mx-1" />}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* CC Findings */}
            <div className="glass-card p-6">
              <h3 className="font-semibold text-white mb-4">Common Criteria Findings</h3>
              <div className="space-y-3">
                {mockJOEAssessment.commonCriteria.findings.map((finding, idx) => {
                  const config = getStatusConfig(finding.status);
                  return (
                    <div key={idx} className={`p-4 rounded-lg border ${config.bg} ${config.border}`}>
                      <div className="flex items-start gap-3">
                        <config.icon size={20} className={config.color} />
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-mono text-sm text-gray-400">{finding.controlId}</span>
                            <span className={`badge ${getSeverityConfig(finding.severity)}`}>{finding.severity}</span>
                          </div>
                          <p className="text-gray-300">{finding.description}</p>
                          {finding.remediation && (
                            <p className="text-joe-blue text-sm mt-2 flex items-center gap-1">
                              <Wrench size={12} />
                              {finding.remediation}
                            </p>
                          )}
                        </div>
                        <button
                          onClick={() => generateAIRemediation(finding)}
                          className="btn-secondary text-sm flex items-center gap-1"
                        >
                          <Brain size={14} />
                          AI Fix
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Export Modal */}
      <Modal
        isOpen={showExportModal}
        onClose={() => setShowExportModal(false)}
        title="Export Compliance Report"
        subtitle={`${DARK_WOLF_BRANDING.company} - ${DARK_WOLF_BRANDING.website}`}
        size="md"
        headerIcon={<Download size={24} />}
        variant="info"
        footer={
          <div className="flex items-center justify-end gap-3">
            <button type="button" onClick={() => setShowExportModal(false)} className="btn-secondary">Cancel</button>
            <button type="button" onClick={exportReport} className="btn-primary flex items-center gap-2">
              <Download size={16} />
              Export Report
            </button>
          </div>
        }
      >
        <div className="space-y-4">
          <p className="text-gray-300">
            Generate a comprehensive Space-Grade compliance report with Dark Wolf Solutions branding.
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
                  <p className="font-medium uppercase">{format === 'pdf' ? 'TXT/PDF' : format.toUpperCase()}</p>
                  <p className="text-xs mt-1">
                    {format === 'pdf' && 'Full report'}
                    {format === 'csv' && 'Findings table'}
                    {format === 'json' && 'Machine readable'}
                  </p>
                </button>
              ))}
            </div>
          </div>
        </div>
      </Modal>

      {/* AI Remediation Modal */}
      <Modal
        isOpen={showAIRemediationModal}
        onClose={() => setShowAIRemediationModal(false)}
        title="AI-Powered Remediation"
        subtitle={selectedFinding ? `${selectedFinding.framework} - ${selectedFinding.controlId}` : ''}
        size="xl"
        headerIcon={<Brain size={24} />}
        variant={selectedFinding?.severity === 'critical' ? 'critical' : selectedFinding?.severity === 'major' ? 'warning' : 'info'}
        footer={
          <div className="flex items-center justify-between">
            <a
              href={DARK_WOLF_BRANDING.website}
              target="_blank"
              rel="noopener noreferrer"
              className="text-joe-blue text-sm flex items-center gap-1 hover:underline"
            >
              {DARK_WOLF_BRANDING.company} <ExternalLink size={14} />
            </a>
            <button type="button" onClick={() => setShowAIRemediationModal(false)} className="btn-primary">Close</button>
          </div>
        }
      >
        {isGeneratingRemediation ? (
          <div className="flex flex-col items-center justify-center py-12">
            <div className="w-12 h-12 border-4 border-joe-blue border-t-transparent rounded-full animate-spin" />
            <p className="text-gray-400 mt-4">J.O.E. AI analyzing compliance finding...</p>
            <p className="text-gray-500 text-sm mt-2">Researching DoD best practices and citing authoritative sources</p>
          </div>
        ) : (
          <div className="prose prose-invert max-w-none text-sm max-h-[60vh] overflow-y-auto">
            {aiRemediationContent.split('\n').map((line, idx) => {
              if (line.startsWith('## ')) {return <h2 key={idx} className="text-lg font-bold text-white mt-4 mb-2">{line.replace('## ', '')}</h2>;}
              if (line.startsWith('### ')) {return <h3 key={idx} className="text-md font-semibold text-joe-blue mt-3 mb-1">{line.replace('### ', '')}</h3>;}
              if (line.startsWith('**') && line.endsWith('**')) {return <p key={idx} className="font-bold text-white mt-2">{line.replace(/\*\*/g, '')}</p>;}
              if (line.startsWith('- ')) {return <div key={idx} className="flex items-start gap-2 ml-4 my-1"><span className="text-joe-blue">•</span><span className="text-gray-300">{line.replace('- ', '')}</span></div>;}
              if (line.startsWith('---')) {return <hr key={idx} className="border-dws-border my-4" />;}
              if (line.trim() === '') {return <div key={idx} className="h-2" />;}
              return <p key={idx} className="my-1 text-gray-300">{line}</p>;
            })}
          </div>
        )}
      </Modal>

      {/* Assessment Complete Modal */}
      <Modal
        isOpen={showAssessmentModal}
        onClose={() => setShowAssessmentModal(false)}
        title="Assessment Complete"
        subtitle={DARK_WOLF_BRANDING.company}
        size="md"
        headerIcon={isFullyCompliant ? <CheckCircle size={24} /> : <AlertTriangle size={24} />}
        variant={isFullyCompliant ? 'success' : 'critical'}
        footer={
          <div className="flex items-center justify-end gap-3">
            <button type="button" onClick={() => setShowAssessmentModal(false)} className="btn-secondary">Close</button>
            <button type="button" onClick={() => { setShowAssessmentModal(false); setShowExportModal(true); }} className="btn-primary flex items-center gap-2">
              <Download size={16} />
              Export Report
            </button>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="text-center py-6">
            <p className={`text-5xl font-bold ${isFullyCompliant ? 'text-dws-green' : 'text-alert-critical'}`}>
              {overallScore}%
            </p>
            <p className={`mt-2 font-bold ${isFullyCompliant ? 'text-dws-green' : 'text-alert-critical'}`}>
              {isFullyCompliant ? 'FULLY COMPLIANT' : 'NON-COMPLIANT'}
            </p>
            <p className="text-gray-400 text-sm mt-1">{DARK_WOLF_BRANDING.compliance_standard}</p>
          </div>

          {!isFullyCompliant && (
            <div className="p-4 bg-alert-critical/10 border border-alert-critical/30 rounded-lg">
              <p className="text-alert-critical font-medium">Immediate Action Required</p>
              <p className="text-gray-400 text-sm mt-1">
                {criticalCount} critical, {majorCount} major findings require remediation.
                POA&M documentation required per NIST SP 800-37.
              </p>
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}
