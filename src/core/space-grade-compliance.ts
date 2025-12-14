/**
 * J.O.E. DevSecOps Arsenal - Space-Grade Compliance System
 * NASA-STD-8719.13 | DO-178C | Common Criteria EAL-4+
 *
 * @module core/space-grade-compliance
 * @version 1.0.0
 *
 * Space-Grade Security Standards for Mission-Critical Software:
 * - NASA Software Safety Standard (NPR 7150.2, NASA-STD-8719.13)
 * - DO-178C Software Considerations in Airborne Systems
 * - Common Criteria for IT Security Evaluation (ISO/IEC 15408)
 * - NIST Cybersecurity Framework 2.0
 * - CMMC 2.0 for Defense Contractors
 */

// =============================================================================
// NASA SOFTWARE SAFETY STANDARD (NASA-STD-8719.13)
// =============================================================================

export type NASASafetyCategory = 'CAT-I' | 'CAT-II' | 'CAT-III' | 'CAT-IV';

export interface NASASafetyLevel {
  category: NASASafetyCategory;
  name: string;
  description: string;
  hazardLevel: string;
  verificationMethods: string[];
  requiredDocumentation: string[];
  testingRequirements: string[];
  reviewRequirements: string[];
  color: string;
}

export const NASA_SAFETY_CATEGORIES: Record<NASASafetyCategory, NASASafetyLevel> = {
  'CAT-I': {
    category: 'CAT-I',
    name: 'Catastrophic',
    description: 'Software whose failure could result in loss of life, permanent disability, or loss of mission-critical systems',
    hazardLevel: 'Loss of life or permanent disability; loss of crewed vehicle; loss of critical national asset',
    verificationMethods: [
      'Formal Methods Verification',
      'Independent V&V (IV&V)',
      'Full MC/DC Coverage Testing',
      'Fault Tree Analysis',
      'Failure Mode Effects and Criticality Analysis (FMECA)',
      'Probabilistic Risk Assessment'
    ],
    requiredDocumentation: [
      'Software Safety Plan',
      'Software Safety Requirements',
      'Safety-Critical Design Description',
      'Hazard Analysis Report',
      'Safety Assessment Report',
      'Independent Safety Audit Report'
    ],
    testingRequirements: [
      '100% MC/DC (Modified Condition/Decision Coverage)',
      '100% Statement Coverage',
      '100% Branch Coverage',
      'Robustness Testing',
      'Stress Testing',
      'Boundary Value Analysis',
      'Fault Injection Testing'
    ],
    reviewRequirements: [
      'Phase 0/I Safety Review',
      'Phase II Safety Review',
      'Phase III Safety Review',
      'Mission Readiness Review',
      'Independent Safety Review Board'
    ],
    color: '#dc2626' // red-600
  },
  'CAT-II': {
    category: 'CAT-II',
    name: 'Critical',
    description: 'Software whose failure could result in severe injury, major property damage, or significant mission degradation',
    hazardLevel: 'Severe injury; major occupational illness; major property damage; significant mission degradation',
    verificationMethods: [
      'Independent V&V Recommended',
      'Decision Coverage Testing',
      'Hazard Analysis',
      'Failure Mode Effects Analysis (FMEA)',
      'Code Review'
    ],
    requiredDocumentation: [
      'Software Safety Plan',
      'Safety Requirements Specification',
      'Hazard Analysis Report',
      'Test Reports'
    ],
    testingRequirements: [
      '100% Decision Coverage',
      '100% Statement Coverage',
      'Integration Testing',
      'System Testing',
      'Regression Testing'
    ],
    reviewRequirements: [
      'Safety Review at Major Milestones',
      'Design Review',
      'Code Review',
      'Test Readiness Review'
    ],
    color: '#ea580c' // orange-600
  },
  'CAT-III': {
    category: 'CAT-III',
    name: 'Moderate',
    description: 'Software whose failure could result in minor injury, minor property damage, or minor mission impact',
    hazardLevel: 'Minor injury; minor occupational illness; minor property damage; minor mission impact',
    verificationMethods: [
      'Statement Coverage Testing',
      'Design Review',
      'Code Inspection',
      'Unit Testing'
    ],
    requiredDocumentation: [
      'Software Development Plan',
      'Requirements Specification',
      'Design Description',
      'Test Plan and Results'
    ],
    testingRequirements: [
      '90% Statement Coverage',
      'Unit Testing',
      'Integration Testing',
      'Functional Testing'
    ],
    reviewRequirements: [
      'Peer Review',
      'Design Review',
      'Test Review'
    ],
    color: '#ca8a04' // yellow-600
  },
  'CAT-IV': {
    category: 'CAT-IV',
    name: 'Negligible',
    description: 'Software whose failure would have negligible safety impact',
    hazardLevel: 'No significant safety impact; minor inconvenience',
    verificationMethods: [
      'Unit Testing',
      'Code Review',
      'Functional Testing'
    ],
    requiredDocumentation: [
      'Basic Development Documentation',
      'Test Results'
    ],
    testingRequirements: [
      'Functional Testing',
      'Basic Unit Testing'
    ],
    reviewRequirements: [
      'Self-Review',
      'Peer Review Optional'
    ],
    color: '#16a34a' // green-600
  }
};

// =============================================================================
// DO-178C DESIGN ASSURANCE LEVELS
// =============================================================================

export type DO178CLevel = 'DAL-A' | 'DAL-B' | 'DAL-C' | 'DAL-D' | 'DAL-E';

export interface DO178CAssuranceLevel {
  level: DO178CLevel;
  name: string;
  failureCondition: string;
  description: string;
  objectives: number;
  independenceRequired: boolean;
  coverageRequirements: {
    statement: number;
    decision: number;
    mcdc: number;
  };
  documentationRequirements: string[];
  verificationActivities: string[];
  color: string;
}

export const DO178C_LEVELS: Record<DO178CLevel, DO178CAssuranceLevel> = {
  'DAL-A': {
    level: 'DAL-A',
    name: 'Catastrophic',
    failureCondition: 'Failure may cause or contribute to a catastrophic failure of the aircraft',
    description: 'Highest assurance level - prevents all failures that could contribute to catastrophic aircraft failures',
    objectives: 71,
    independenceRequired: true,
    coverageRequirements: {
      statement: 100,
      decision: 100,
      mcdc: 100
    },
    documentationRequirements: [
      'Plan for Software Aspects of Certification (PSAC)',
      'Software Development Plan (SDP)',
      'Software Verification Plan (SVP)',
      'Software Configuration Management Plan (SCMP)',
      'Software Quality Assurance Plan (SQAP)',
      'Software Requirements Data (SRD)',
      'Software Design Description (SDD)',
      'Source Code',
      'Software Verification Cases and Procedures (SVCP)',
      'Software Verification Results (SVR)',
      'Software Configuration Index (SCI)',
      'Software Accomplishment Summary (SAS)'
    ],
    verificationActivities: [
      'Requirements-Based Testing',
      'Structural Coverage Analysis (MC/DC)',
      'Requirements Traceability',
      'Code Review',
      'Independence of Verification'
    ],
    color: '#dc2626'
  },
  'DAL-B': {
    level: 'DAL-B',
    name: 'Hazardous',
    failureCondition: 'Failure may cause or contribute to a hazardous/severe failure condition',
    description: 'High assurance level - prevents failures leading to serious injury or large reduction in safety margins',
    objectives: 69,
    independenceRequired: true,
    coverageRequirements: {
      statement: 100,
      decision: 100,
      mcdc: 0
    },
    documentationRequirements: [
      'PSAC', 'SDP', 'SVP', 'SCMP', 'SQAP',
      'SRD', 'SDD', 'Source Code',
      'SVCP', 'SVR', 'SCI', 'SAS'
    ],
    verificationActivities: [
      'Requirements-Based Testing',
      'Decision Coverage Analysis',
      'Requirements Traceability',
      'Code Review'
    ],
    color: '#ea580c'
  },
  'DAL-C': {
    level: 'DAL-C',
    name: 'Major',
    failureCondition: 'Failure may cause or contribute to a major failure condition',
    description: 'Moderate assurance level - prevents failures leading to passenger discomfort or increased crew workload',
    objectives: 62,
    independenceRequired: false,
    coverageRequirements: {
      statement: 100,
      decision: 0,
      mcdc: 0
    },
    documentationRequirements: [
      'PSAC', 'SDP', 'SVP', 'SCMP',
      'SRD', 'SDD', 'Source Code',
      'SVCP', 'SVR', 'SCI', 'SAS'
    ],
    verificationActivities: [
      'Requirements-Based Testing',
      'Statement Coverage Analysis',
      'Requirements Traceability'
    ],
    color: '#ca8a04'
  },
  'DAL-D': {
    level: 'DAL-D',
    name: 'Minor',
    failureCondition: 'Failure may cause or contribute to a minor failure condition',
    description: 'Low assurance level - prevents failures causing minor inconvenience',
    objectives: 26,
    independenceRequired: false,
    coverageRequirements: {
      statement: 0,
      decision: 0,
      mcdc: 0
    },
    documentationRequirements: [
      'PSAC', 'SDP', 'SCMP',
      'SRD', 'Source Code', 'SCI', 'SAS'
    ],
    verificationActivities: [
      'Requirements-Based Testing',
      'Basic Functional Testing'
    ],
    color: '#16a34a'
  },
  'DAL-E': {
    level: 'DAL-E',
    name: 'No Effect',
    failureCondition: 'Failure has no effect on aircraft operational capability or pilot workload',
    description: 'No safety effect - software does not contribute to aircraft safety',
    objectives: 0,
    independenceRequired: false,
    coverageRequirements: {
      statement: 0,
      decision: 0,
      mcdc: 0
    },
    documentationRequirements: [
      'Basic Documentation'
    ],
    verificationActivities: [
      'Basic Testing'
    ],
    color: '#6b7280'
  }
};

// =============================================================================
// COMMON CRITERIA EAL LEVELS (ISO/IEC 15408)
// =============================================================================

export type CommonCriteriaEAL = 'EAL-1' | 'EAL-2' | 'EAL-3' | 'EAL-4' | 'EAL-5' | 'EAL-6' | 'EAL-7';

export interface CommonCriteriaLevel {
  level: CommonCriteriaEAL;
  name: string;
  description: string;
  assuranceComponents: string[];
  applicability: string;
  effort: string;
  color: string;
}

export const COMMON_CRITERIA_LEVELS: Record<CommonCriteriaEAL, CommonCriteriaLevel> = {
  'EAL-1': {
    level: 'EAL-1',
    name: 'Functionally Tested',
    description: 'Lowest level of assurance. Product is functionally tested.',
    assuranceComponents: ['ADV_FSP.1', 'AGD_OPE.1', 'AGD_PRE.1', 'ALC_CMC.1', 'ALC_CMS.1', 'ATE_IND.1', 'AVA_VAN.1'],
    applicability: 'When confidence in correct operation is required, but threats are not viewed as serious',
    effort: 'Minimal',
    color: '#6b7280'
  },
  'EAL-2': {
    level: 'EAL-2',
    name: 'Structurally Tested',
    description: 'Low-to-moderate level requiring developer testing and analysis.',
    assuranceComponents: ['ADV_ARC.1', 'ADV_FSP.2', 'ADV_TDS.1', 'AGD_OPE.1', 'AGD_PRE.1', 'ALC_CMC.2', 'ALC_CMS.2', 'ALC_DEL.1', 'ATE_COV.1', 'ATE_FUN.1', 'ATE_IND.2', 'AVA_VAN.2'],
    applicability: 'When developers or users require low-to-moderate independently assured security',
    effort: 'Low',
    color: '#16a34a'
  },
  'EAL-3': {
    level: 'EAL-3',
    name: 'Methodically Tested and Checked',
    description: 'Moderate level requiring more thorough testing and checking.',
    assuranceComponents: ['ADV_ARC.1', 'ADV_FSP.3', 'ADV_TDS.2', 'AGD_OPE.1', 'AGD_PRE.1', 'ALC_CMC.3', 'ALC_CMS.3', 'ALC_DEL.1', 'ALC_DVS.1', 'ALC_LCD.1', 'ATE_COV.2', 'ATE_DPT.1', 'ATE_FUN.1', 'ATE_IND.2', 'AVA_VAN.2'],
    applicability: 'When moderately high level of independently assured security is required',
    effort: 'Moderate',
    color: '#ca8a04'
  },
  'EAL-4': {
    level: 'EAL-4',
    name: 'Methodically Designed, Tested, and Reviewed',
    description: 'Highest level commonly achieved commercially. Requires methodical design and review.',
    assuranceComponents: ['ADV_ARC.1', 'ADV_FSP.4', 'ADV_IMP.1', 'ADV_TDS.3', 'AGD_OPE.1', 'AGD_PRE.1', 'ALC_CMC.4', 'ALC_CMS.4', 'ALC_DEL.1', 'ALC_DVS.1', 'ALC_LCD.1', 'ALC_TAT.1', 'ATE_COV.2', 'ATE_DPT.1', 'ATE_FUN.1', 'ATE_IND.2', 'AVA_VAN.3'],
    applicability: 'When developers or users require moderate-to-high independently assured security in conventional commodity TOEs',
    effort: 'High',
    color: '#2563eb'
  },
  'EAL-5': {
    level: 'EAL-5',
    name: 'Semiformally Designed and Tested',
    description: 'Requires semiformal design descriptions and comprehensive testing.',
    assuranceComponents: ['ADV_ARC.1', 'ADV_FSP.5', 'ADV_IMP.1', 'ADV_INT.2', 'ADV_TDS.4', 'AGD_OPE.1', 'AGD_PRE.1', 'ALC_CMC.4', 'ALC_CMS.5', 'ALC_DEL.1', 'ALC_DVS.1', 'ALC_LCD.1', 'ALC_TAT.2', 'ATE_COV.2', 'ATE_DPT.3', 'ATE_FUN.1', 'ATE_IND.2', 'AVA_VAN.4'],
    applicability: 'When developers or users require high level of independently assured security',
    effort: 'Very High',
    color: '#7c3aed'
  },
  'EAL-6': {
    level: 'EAL-6',
    name: 'Semiformally Verified Design and Tested',
    description: 'Requires semiformal verification and more comprehensive analysis.',
    assuranceComponents: ['ADV_ARC.1', 'ADV_FSP.5', 'ADV_IMP.2', 'ADV_INT.3', 'ADV_SPM.1', 'ADV_TDS.5', 'AGD_OPE.1', 'AGD_PRE.1', 'ALC_CMC.5', 'ALC_CMS.5', 'ALC_DEL.1', 'ALC_DVS.2', 'ALC_LCD.1', 'ALC_TAT.3', 'ATE_COV.3', 'ATE_DPT.3', 'ATE_FUN.2', 'ATE_IND.2', 'AVA_VAN.5'],
    applicability: 'When developers or users require high level of independently assured security for high-risk situations',
    effort: 'Extremely High',
    color: '#9333ea'
  },
  'EAL-7': {
    level: 'EAL-7',
    name: 'Formally Verified Design and Tested',
    description: 'Highest assurance level requiring formal methods and comprehensive independent testing.',
    assuranceComponents: ['ADV_ARC.1', 'ADV_FSP.6', 'ADV_IMP.2', 'ADV_INT.3', 'ADV_SPM.1', 'ADV_TDS.6', 'AGD_OPE.1', 'AGD_PRE.1', 'ALC_CMC.5', 'ALC_CMS.5', 'ALC_DEL.1', 'ALC_DVS.2', 'ALC_LCD.2', 'ALC_TAT.3', 'ATE_COV.3', 'ATE_DPT.4', 'ATE_FUN.2', 'ATE_IND.3', 'AVA_VAN.5'],
    applicability: 'When developing security TOEs for application in extremely high-risk situations',
    effort: 'Maximum',
    color: '#dc2626'
  }
};

// =============================================================================
// CROSS-FRAMEWORK MAPPING
// =============================================================================

export interface FrameworkMapping {
  from: string;
  to: string;
  mappings: Array<{
    sourceId: string;
    targetId: string;
    relationship: 'equivalent' | 'partial' | 'related';
    notes?: string;
  }>;
}

export const FRAMEWORK_MAPPINGS: FrameworkMapping[] = [
  {
    from: 'NASA-STD-8719',
    to: 'DO-178C',
    mappings: [
      { sourceId: 'CAT-I', targetId: 'DAL-A', relationship: 'equivalent', notes: 'Both require highest rigor for catastrophic failures' },
      { sourceId: 'CAT-II', targetId: 'DAL-B', relationship: 'equivalent', notes: 'Critical/Hazardous failure conditions' },
      { sourceId: 'CAT-III', targetId: 'DAL-C', relationship: 'partial', notes: 'Moderate impact levels' },
      { sourceId: 'CAT-IV', targetId: 'DAL-D', relationship: 'partial', notes: 'Minor/Negligible impact' }
    ]
  },
  {
    from: 'NASA-STD-8719',
    to: 'Common-Criteria',
    mappings: [
      { sourceId: 'CAT-I', targetId: 'EAL-6', relationship: 'partial', notes: 'High assurance requirements' },
      { sourceId: 'CAT-I', targetId: 'EAL-7', relationship: 'partial', notes: 'Formal methods recommended' },
      { sourceId: 'CAT-II', targetId: 'EAL-4', relationship: 'partial', notes: 'Methodical design and review' },
      { sourceId: 'CAT-II', targetId: 'EAL-5', relationship: 'partial', notes: 'Semiformal design' },
      { sourceId: 'CAT-III', targetId: 'EAL-3', relationship: 'partial', notes: 'Methodical testing' },
      { sourceId: 'CAT-IV', targetId: 'EAL-2', relationship: 'partial', notes: 'Structural testing' }
    ]
  },
  {
    from: 'NASA-STD-8719',
    to: 'NIST-800-53',
    mappings: [
      { sourceId: 'CAT-I', targetId: 'HIGH', relationship: 'related', notes: 'High impact baseline' },
      { sourceId: 'CAT-II', targetId: 'HIGH', relationship: 'related', notes: 'High impact baseline' },
      { sourceId: 'CAT-III', targetId: 'MODERATE', relationship: 'related', notes: 'Moderate impact baseline' },
      { sourceId: 'CAT-IV', targetId: 'LOW', relationship: 'related', notes: 'Low impact baseline' }
    ]
  },
  {
    from: 'DO-178C',
    to: 'Common-Criteria',
    mappings: [
      { sourceId: 'DAL-A', targetId: 'EAL-6', relationship: 'partial', notes: 'Both require semiformal/formal verification' },
      { sourceId: 'DAL-A', targetId: 'EAL-7', relationship: 'partial', notes: 'Formal verification alignment' },
      { sourceId: 'DAL-B', targetId: 'EAL-4', relationship: 'partial', notes: 'Methodical design requirements' },
      { sourceId: 'DAL-B', targetId: 'EAL-5', relationship: 'partial', notes: 'Semiformal design' },
      { sourceId: 'DAL-C', targetId: 'EAL-3', relationship: 'partial', notes: 'Testing coverage' },
      { sourceId: 'DAL-D', targetId: 'EAL-2', relationship: 'partial', notes: 'Basic assurance' }
    ]
  }
];

// =============================================================================
// COMPLIANCE ASSESSMENT TYPES
// =============================================================================

export interface ComplianceAssessment {
  id: string;
  projectName: string;
  assessmentDate: string;
  assessor: string;
  nasaCategory?: NASASafetyCategory;
  do178cLevel?: DO178CLevel;
  commonCriteriaLevel?: CommonCriteriaEAL;
  overallScore: number;
  findings: ComplianceFinding[];
  recommendations: string[];
  certificationReady: boolean;
}

export interface ComplianceFinding {
  id: string;
  framework: 'NASA-STD-8719' | 'DO-178C' | 'Common-Criteria';
  controlId: string;
  status: 'compliant' | 'partial' | 'non-compliant' | 'not-applicable';
  severity: 'critical' | 'major' | 'minor' | 'observation';
  description: string;
  evidence?: string;
  remediation?: string;
  dueDate?: string;
}

export interface CoverageMetrics {
  statementCoverage: number;
  branchCoverage: number;
  mcdcCoverage: number;
  requirementsCoverage: number;
  testCaseCoverage: number;
}

export interface SafetyMetrics {
  hazardsIdentified: number;
  hazardsMitigated: number;
  openSafetyIssues: number;
  safetyReviewsCompleted: number;
  independentReviewsCompleted: number;
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Determine NASA safety category based on impact analysis
 */
export const determineNASACategory = (
  lossOfLife: boolean,
  severeInjury: boolean,
  missionCritical: boolean,
  propertyDamage: 'none' | 'minor' | 'major' | 'critical'
): NASASafetyCategory => {
  if (lossOfLife || propertyDamage === 'critical') return 'CAT-I';
  if (severeInjury || missionCritical || propertyDamage === 'major') return 'CAT-II';
  if (propertyDamage === 'minor') return 'CAT-III';
  return 'CAT-IV';
};

/**
 * Determine DO-178C DAL based on failure condition severity
 */
export const determineDO178CLevel = (
  failureEffect: 'catastrophic' | 'hazardous' | 'major' | 'minor' | 'no-effect'
): DO178CLevel => {
  const mapping: Record<string, DO178CLevel> = {
    'catastrophic': 'DAL-A',
    'hazardous': 'DAL-B',
    'major': 'DAL-C',
    'minor': 'DAL-D',
    'no-effect': 'DAL-E'
  };
  return mapping[failureEffect];
};

/**
 * Check if coverage metrics meet DAL requirements
 */
export const checkDALCompliance = (
  level: DO178CLevel,
  coverage: CoverageMetrics
): { compliant: boolean; gaps: string[] } => {
  const requirements = DO178C_LEVELS[level].coverageRequirements;
  const gaps: string[] = [];

  if (requirements.statement > 0 && coverage.statementCoverage < requirements.statement) {
    gaps.push(`Statement coverage: ${coverage.statementCoverage}% < ${requirements.statement}% required`);
  }
  if (requirements.decision > 0 && coverage.branchCoverage < requirements.decision) {
    gaps.push(`Decision coverage: ${coverage.branchCoverage}% < ${requirements.decision}% required`);
  }
  if (requirements.mcdc > 0 && coverage.mcdcCoverage < requirements.mcdc) {
    gaps.push(`MC/DC coverage: ${coverage.mcdcCoverage}% < ${requirements.mcdc}% required`);
  }

  return {
    compliant: gaps.length === 0,
    gaps
  };
};

/**
 * Get mapped controls across frameworks
 */
export const getMappedControls = (
  framework: string,
  controlId: string
): Array<{ framework: string; controlId: string; relationship: string }> => {
  const results: Array<{ framework: string; controlId: string; relationship: string }> = [];

  for (const mapping of FRAMEWORK_MAPPINGS) {
    if (mapping.from === framework) {
      const match = mapping.mappings.find(m => m.sourceId === controlId);
      if (match) {
        results.push({
          framework: mapping.to,
          controlId: match.targetId,
          relationship: match.relationship
        });
      }
    }
    if (mapping.to === framework) {
      const match = mapping.mappings.find(m => m.targetId === controlId);
      if (match) {
        results.push({
          framework: mapping.from,
          controlId: match.sourceId,
          relationship: match.relationship
        });
      }
    }
  }

  return results;
};

/**
 * Calculate overall compliance score
 */
export const calculateComplianceScore = (findings: ComplianceFinding[]): number => {
  if (findings.length === 0) return 100;

  const weights = {
    compliant: 100,
    partial: 60,
    'non-compliant': 0,
    'not-applicable': 100
  };

  const severityMultipliers = {
    critical: 2.0,
    major: 1.5,
    minor: 1.0,
    observation: 0.5
  };

  let totalWeight = 0;
  let weightedScore = 0;

  for (const finding of findings) {
    const multiplier = severityMultipliers[finding.severity];
    totalWeight += multiplier;
    weightedScore += weights[finding.status] * multiplier;
  }

  return Math.round(weightedScore / totalWeight);
};

/**
 * Get certification readiness status
 */
export const getCertificationReadiness = (
  assessment: ComplianceAssessment
): { ready: boolean; blockers: string[] } => {
  const blockers: string[] = [];

  // Check for critical non-compliant findings
  const criticalNC = assessment.findings.filter(
    f => f.status === 'non-compliant' && f.severity === 'critical'
  );
  if (criticalNC.length > 0) {
    blockers.push(`${criticalNC.length} critical non-compliant finding(s)`);
  }

  // Check for major non-compliant findings
  const majorNC = assessment.findings.filter(
    f => f.status === 'non-compliant' && f.severity === 'major'
  );
  if (majorNC.length > 0) {
    blockers.push(`${majorNC.length} major non-compliant finding(s)`);
  }

  // Check overall score
  if (assessment.overallScore < 80) {
    blockers.push(`Overall score ${assessment.overallScore}% below 80% threshold`);
  }

  return {
    ready: blockers.length === 0,
    blockers
  };
};

export default {
  NASA_SAFETY_CATEGORIES,
  DO178C_LEVELS,
  COMMON_CRITERIA_LEVELS,
  FRAMEWORK_MAPPINGS,
  determineNASACategory,
  determineDO178CLevel,
  checkDALCompliance,
  getMappedControls,
  calculateComplianceScore,
  getCertificationReadiness
};
