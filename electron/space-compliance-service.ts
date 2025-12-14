/**
 * J.O.E. DevSecOps Arsenal - Space Compliance Service
 * NASA-STD-8719.13 | DO-178C | Common Criteria Assessment Engine
 *
 * @module electron/space-compliance-service
 * @version 1.0.0
 */

import {
  NASASafetyCategory,
  DO178CLevel,
  CommonCriteriaEAL,
  NASA_SAFETY_CATEGORIES,
  DO178C_LEVELS,
  COMMON_CRITERIA_LEVELS,
  ComplianceAssessment,
  ComplianceFinding,
  CoverageMetrics,
  SafetyMetrics,
  determineNASACategory,
  determineDO178CLevel,
  checkDALCompliance,
  getMappedControls,
  calculateComplianceScore,
  getCertificationReadiness
} from '../src/core/space-grade-compliance';
import crypto from 'crypto';

// =============================================================================
// TYPES
// =============================================================================

export interface ProjectConfig {
  name: string;
  type: 'spacecraft' | 'avionics' | 'ground-system' | 'mission-control' | 'general';
  primaryFramework: 'NASA-STD-8719' | 'DO-178C' | 'Common-Criteria';
  targetLevel: string;
  description?: string;
}

export interface AssessmentResult {
  assessment: ComplianceAssessment;
  summary: {
    totalControls: number;
    compliant: number;
    partial: number;
    nonCompliant: number;
    notApplicable: number;
  };
  certificationStatus: {
    ready: boolean;
    blockers: string[];
  };
  nextSteps: string[];
}

export interface ComplianceReport {
  id: string;
  generatedAt: string;
  project: ProjectConfig;
  assessment: ComplianceAssessment;
  executiveSummary: string;
  detailedFindings: ComplianceFinding[];
  recommendations: string[];
  signatureBlock: {
    preparedBy: string;
    reviewedBy?: string;
    approvedBy?: string;
  };
}

// =============================================================================
// SPACE COMPLIANCE SERVICE
// =============================================================================

class SpaceComplianceService {
  private assessments: Map<string, ComplianceAssessment> = new Map();
  private projects: Map<string, ProjectConfig> = new Map();

  // ===========================================================================
  // PROJECT MANAGEMENT
  // ===========================================================================

  /**
   * Register a project for compliance assessment
   */
  registerProject(config: ProjectConfig): string {
    const projectId = crypto.randomUUID();
    this.projects.set(projectId, config);
    console.log('[Space Compliance] Project registered:', config.name);
    return projectId;
  }

  /**
   * Get project configuration
   */
  getProject(projectId: string): ProjectConfig | null {
    return this.projects.get(projectId) || null;
  }

  /**
   * List all registered projects
   */
  listProjects(): Array<{ id: string; config: ProjectConfig }> {
    return Array.from(this.projects.entries()).map(([id, config]) => ({ id, config }));
  }

  // ===========================================================================
  // NASA SAFETY ASSESSMENT
  // ===========================================================================

  /**
   * Assess NASA software safety category
   */
  assessNASASafety(params: {
    projectName: string;
    assessor: string;
    hazardAnalysis: {
      lossOfLife: boolean;
      severeInjury: boolean;
      missionCritical: boolean;
      propertyDamage: 'none' | 'minor' | 'major' | 'critical';
    };
    safetyMetrics: SafetyMetrics;
    existingControls: string[];
  }): AssessmentResult {
    const category = determineNASACategory(
      params.hazardAnalysis.lossOfLife,
      params.hazardAnalysis.severeInjury,
      params.hazardAnalysis.missionCritical,
      params.hazardAnalysis.propertyDamage
    );

    const _categoryInfo = NASA_SAFETY_CATEGORIES[category];
    const findings = this.evaluateNASACompliance(category, params.safetyMetrics, params.existingControls);

    const assessment: ComplianceAssessment = {
      id: crypto.randomUUID(),
      projectName: params.projectName,
      assessmentDate: new Date().toISOString(),
      assessor: params.assessor,
      nasaCategory: category,
      overallScore: calculateComplianceScore(findings),
      findings,
      recommendations: this.generateNASARecommendations(category, findings),
      certificationReady: false
    };

    const certStatus = getCertificationReadiness(assessment);
    assessment.certificationReady = certStatus.ready;

    this.assessments.set(assessment.id, assessment);

    return {
      assessment,
      summary: this.summarizeFindings(findings),
      certificationStatus: certStatus,
      nextSteps: this.generateNextSteps('NASA-STD-8719', category, findings)
    };
  }

  private evaluateNASACompliance(
    category: NASASafetyCategory,
    metrics: SafetyMetrics,
    existingControls: string[]
  ): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];
    const requirements = NASA_SAFETY_CATEGORIES[category];

    // Verification Methods
    for (const method of requirements.verificationMethods) {
      const hasControl = existingControls.some(c => c.toLowerCase().includes(method.toLowerCase().split(' ')[0]));
      findings.push({
        id: crypto.randomUUID(),
        framework: 'NASA-STD-8719',
        controlId: `${category}-VER`,
        status: hasControl ? 'compliant' : 'non-compliant',
        severity: category === 'CAT-I' ? 'critical' : category === 'CAT-II' ? 'major' : 'minor',
        description: `Verification method: ${method}`,
        remediation: hasControl ? undefined : `Implement ${method} verification`
      });
    }

    // Documentation Requirements
    for (const doc of requirements.requiredDocumentation) {
      const hasDoc = existingControls.some(c => c.toLowerCase().includes(doc.toLowerCase().split(' ')[0]));
      findings.push({
        id: crypto.randomUUID(),
        framework: 'NASA-STD-8719',
        controlId: `${category}-DOC`,
        status: hasDoc ? 'compliant' : 'partial',
        severity: 'major',
        description: `Documentation: ${doc}`,
        remediation: hasDoc ? undefined : `Create ${doc}`
      });
    }

    // Safety Metrics Evaluation
    if (metrics.openSafetyIssues > 0 && (category === 'CAT-I' || category === 'CAT-II')) {
      findings.push({
        id: crypto.randomUUID(),
        framework: 'NASA-STD-8719',
        controlId: `${category}-HAZARD`,
        status: 'non-compliant',
        severity: 'critical',
        description: `${metrics.openSafetyIssues} open safety issues must be resolved`,
        remediation: 'Close all open safety issues before certification'
      });
    }

    // Hazard Mitigation Rate
    const mitigationRate = metrics.hazardsIdentified > 0
      ? (metrics.hazardsMitigated / metrics.hazardsIdentified) * 100
      : 100;

    if (mitigationRate < 100 && category === 'CAT-I') {
      findings.push({
        id: crypto.randomUUID(),
        framework: 'NASA-STD-8719',
        controlId: `${category}-MIT`,
        status: 'non-compliant',
        severity: 'critical',
        description: `Hazard mitigation rate: ${mitigationRate.toFixed(1)}% (100% required for ${category})`,
        remediation: 'Mitigate all identified hazards'
      });
    }

    return findings;
  }

  private generateNASARecommendations(category: NASASafetyCategory, findings: ComplianceFinding[]): string[] {
    const recommendations: string[] = [];
    const nonCompliant = findings.filter(f => f.status === 'non-compliant');

    if (nonCompliant.length > 0) {
      recommendations.push(`Address ${nonCompliant.length} non-compliant finding(s) immediately`);
    }

    if (category === 'CAT-I') {
      recommendations.push('Engage Independent V&V team for all safety-critical functions');
      recommendations.push('Conduct formal methods verification for highest-risk components');
      recommendations.push('Schedule Independent Safety Review Board');
    }

    if (category === 'CAT-II') {
      recommendations.push('Complete hazard analysis for all failure modes');
      recommendations.push('Ensure decision coverage testing is complete');
    }

    recommendations.push(`Review NASA-STD-8719.13 requirements for ${NASA_SAFETY_CATEGORIES[category].name} category`);

    return recommendations;
  }

  // ===========================================================================
  // DO-178C ASSESSMENT
  // ===========================================================================

  /**
   * Assess DO-178C Design Assurance Level compliance
   */
  assessDO178C(params: {
    projectName: string;
    assessor: string;
    failureCondition: 'catastrophic' | 'hazardous' | 'major' | 'minor' | 'no-effect';
    coverageMetrics: CoverageMetrics;
    documentationStatus: Record<string, boolean>;
    verificationActivities: string[];
  }): AssessmentResult {
    const level = determineDO178CLevel(params.failureCondition);
    const _levelInfo = DO178C_LEVELS[level];
    const findings = this.evaluateDO178CCompliance(level, params.coverageMetrics, params.documentationStatus, params.verificationActivities);

    const assessment: ComplianceAssessment = {
      id: crypto.randomUUID(),
      projectName: params.projectName,
      assessmentDate: new Date().toISOString(),
      assessor: params.assessor,
      do178cLevel: level,
      overallScore: calculateComplianceScore(findings),
      findings,
      recommendations: this.generateDO178CRecommendations(level, findings, params.coverageMetrics),
      certificationReady: false
    };

    const certStatus = getCertificationReadiness(assessment);
    assessment.certificationReady = certStatus.ready;

    this.assessments.set(assessment.id, assessment);

    return {
      assessment,
      summary: this.summarizeFindings(findings),
      certificationStatus: certStatus,
      nextSteps: this.generateNextSteps('DO-178C', level, findings)
    };
  }

  private evaluateDO178CCompliance(
    level: DO178CLevel,
    coverage: CoverageMetrics,
    docs: Record<string, boolean>,
    activities: string[]
  ): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];
    const requirements = DO178C_LEVELS[level];

    // Coverage Requirements
    const coverageCheck = checkDALCompliance(level, coverage);
    if (!coverageCheck.compliant) {
      for (const gap of coverageCheck.gaps) {
        findings.push({
          id: crypto.randomUUID(),
          framework: 'DO-178C',
          controlId: `${level}-COV`,
          status: 'non-compliant',
          severity: level === 'DAL-A' || level === 'DAL-B' ? 'critical' : 'major',
          description: gap,
          remediation: 'Increase test coverage to meet DAL requirements'
        });
      }
    } else {
      findings.push({
        id: crypto.randomUUID(),
        framework: 'DO-178C',
        controlId: `${level}-COV`,
        status: 'compliant',
        severity: 'observation',
        description: 'Structural coverage requirements met'
      });
    }

    // Documentation Requirements
    for (const doc of requirements.documentationRequirements) {
      const shortDoc = doc.match(/\(([^)]+)\)/)?.[1] || doc;
      const hasDoc = docs[shortDoc] || docs[doc] || false;

      findings.push({
        id: crypto.randomUUID(),
        framework: 'DO-178C',
        controlId: `${level}-DOC`,
        status: hasDoc ? 'compliant' : 'non-compliant',
        severity: level === 'DAL-A' || level === 'DAL-B' ? 'major' : 'minor',
        description: `Documentation: ${doc}`,
        remediation: hasDoc ? undefined : `Create ${doc}`
      });
    }

    // Verification Activities
    for (const activity of requirements.verificationActivities) {
      const hasActivity = activities.some(a => a.toLowerCase().includes(activity.toLowerCase().split(' ')[0]));

      findings.push({
        id: crypto.randomUUID(),
        framework: 'DO-178C',
        controlId: `${level}-VER`,
        status: hasActivity ? 'compliant' : 'partial',
        severity: 'major',
        description: `Verification activity: ${activity}`,
        remediation: hasActivity ? undefined : `Implement ${activity}`
      });
    }

    // Independence Check for DAL-A/B
    if (requirements.independenceRequired) {
      const hasIndependence = activities.some(a => a.toLowerCase().includes('independent'));
      findings.push({
        id: crypto.randomUUID(),
        framework: 'DO-178C',
        controlId: `${level}-IND`,
        status: hasIndependence ? 'compliant' : 'non-compliant',
        severity: 'critical',
        description: 'Independence of verification required',
        remediation: hasIndependence ? undefined : 'Establish independent verification team'
      });
    }

    return findings;
  }

  private generateDO178CRecommendations(
    level: DO178CLevel,
    findings: ComplianceFinding[],
    coverage: CoverageMetrics
  ): string[] {
    const recommendations: string[] = [];
    const requirements = DO178C_LEVELS[level];

    // Coverage recommendations
    if (requirements.coverageRequirements.mcdc > 0 && coverage.mcdcCoverage < 100) {
      recommendations.push(`Increase MC/DC coverage from ${coverage.mcdcCoverage}% to 100%`);
    }
    if (requirements.coverageRequirements.decision > 0 && coverage.branchCoverage < 100) {
      recommendations.push(`Increase decision coverage from ${coverage.branchCoverage}% to 100%`);
    }
    if (requirements.coverageRequirements.statement > 0 && coverage.statementCoverage < 100) {
      recommendations.push(`Increase statement coverage from ${coverage.statementCoverage}% to 100%`);
    }

    // Documentation recommendations
    const docFindings = findings.filter(f => f.controlId.includes('DOC') && f.status !== 'compliant');
    if (docFindings.length > 0) {
      recommendations.push(`Complete ${docFindings.length} missing documentation item(s)`);
    }

    // Level-specific recommendations
    if (level === 'DAL-A') {
      recommendations.push('Ensure all objectives (71) are satisfied with evidence');
      recommendations.push('Prepare for DER (Designated Engineering Representative) review');
    }

    recommendations.push(`Review DO-178C Section 6 for ${level} objective requirements`);

    return recommendations;
  }

  // ===========================================================================
  // COMMON CRITERIA ASSESSMENT
  // ===========================================================================

  /**
   * Assess Common Criteria EAL compliance
   */
  assessCommonCriteria(params: {
    projectName: string;
    assessor: string;
    targetEAL: CommonCriteriaEAL;
    assuranceComponents: Record<string, 'satisfied' | 'partial' | 'not-satisfied'>;
    securityFunctions: string[];
  }): AssessmentResult {
    const _levelInfo = COMMON_CRITERIA_LEVELS[params.targetEAL];
    const findings = this.evaluateCCCompliance(params.targetEAL, params.assuranceComponents);

    const assessment: ComplianceAssessment = {
      id: crypto.randomUUID(),
      projectName: params.projectName,
      assessmentDate: new Date().toISOString(),
      assessor: params.assessor,
      commonCriteriaLevel: params.targetEAL,
      overallScore: calculateComplianceScore(findings),
      findings,
      recommendations: this.generateCCRecommendations(params.targetEAL, findings),
      certificationReady: false
    };

    const certStatus = getCertificationReadiness(assessment);
    assessment.certificationReady = certStatus.ready;

    this.assessments.set(assessment.id, assessment);

    return {
      assessment,
      summary: this.summarizeFindings(findings),
      certificationStatus: certStatus,
      nextSteps: this.generateNextSteps('Common-Criteria', params.targetEAL, findings)
    };
  }

  private evaluateCCCompliance(
    level: CommonCriteriaEAL,
    components: Record<string, 'satisfied' | 'partial' | 'not-satisfied'>
  ): ComplianceFinding[] {
    const findings: ComplianceFinding[] = [];
    const required = COMMON_CRITERIA_LEVELS[level].assuranceComponents;

    for (const component of required) {
      const status = components[component];
      const statusMapping = {
        'satisfied': 'compliant' as const,
        'partial': 'partial' as const,
        'not-satisfied': 'non-compliant' as const
      };

      findings.push({
        id: crypto.randomUUID(),
        framework: 'Common-Criteria',
        controlId: component,
        status: status ? statusMapping[status] : 'non-compliant',
        severity: component.startsWith('AVA') ? 'critical' : component.startsWith('ATE') ? 'major' : 'minor',
        description: `Assurance component: ${component}`,
        remediation: status === 'satisfied' ? undefined : `Complete ${component} evaluation`
      });
    }

    return findings;
  }

  private generateCCRecommendations(level: CommonCriteriaEAL, findings: ComplianceFinding[]): string[] {
    const recommendations: string[] = [];
    const nonCompliant = findings.filter(f => f.status !== 'compliant');

    if (nonCompliant.length > 0) {
      recommendations.push(`Address ${nonCompliant.length} incomplete assurance component(s)`);
    }

    // Family-specific recommendations
    const families = {
      ADV: 'Development',
      AGD: 'Guidance',
      ALC: 'Life-cycle support',
      ATE: 'Tests',
      AVA: 'Vulnerability assessment'
    };

    for (const [prefix, name] of Object.entries(families)) {
      const familyGaps = findings.filter(f => f.controlId.startsWith(prefix) && f.status !== 'compliant');
      if (familyGaps.length > 0) {
        recommendations.push(`Focus on ${name} (${prefix}_*) assurance family - ${familyGaps.length} gap(s)`);
      }
    }

    recommendations.push(`Prepare Security Target (ST) document for ${level} evaluation`);
    recommendations.push('Engage Common Criteria Test Laboratory (CCTL) for formal evaluation');

    return recommendations;
  }

  // ===========================================================================
  // CROSS-FRAMEWORK ANALYSIS
  // ===========================================================================

  /**
   * Get mapped controls across frameworks
   */
  getCrossFrameworkMappings(framework: string, controlId: string) {
    return getMappedControls(framework, controlId);
  }

  /**
   * Generate unified compliance report across all frameworks
   */
  generateUnifiedReport(assessmentIds: string[]): {
    nasaFindings: ComplianceFinding[];
    do178cFindings: ComplianceFinding[];
    ccFindings: ComplianceFinding[];
    overallScore: number;
    recommendations: string[];
  } {
    const allFindings: ComplianceFinding[] = [];
    const allRecommendations: string[] = [];

    for (const id of assessmentIds) {
      const assessment = this.assessments.get(id);
      if (assessment) {
        allFindings.push(...assessment.findings);
        allRecommendations.push(...assessment.recommendations);
      }
    }

    return {
      nasaFindings: allFindings.filter(f => f.framework === 'NASA-STD-8719'),
      do178cFindings: allFindings.filter(f => f.framework === 'DO-178C'),
      ccFindings: allFindings.filter(f => f.framework === 'Common-Criteria'),
      overallScore: calculateComplianceScore(allFindings),
      recommendations: [...new Set(allRecommendations)]
    };
  }

  // ===========================================================================
  // UTILITY METHODS
  // ===========================================================================

  private summarizeFindings(findings: ComplianceFinding[]) {
    return {
      totalControls: findings.length,
      compliant: findings.filter(f => f.status === 'compliant').length,
      partial: findings.filter(f => f.status === 'partial').length,
      nonCompliant: findings.filter(f => f.status === 'non-compliant').length,
      notApplicable: findings.filter(f => f.status === 'not-applicable').length
    };
  }

  private generateNextSteps(framework: string, level: string, findings: ComplianceFinding[]): string[] {
    const steps: string[] = [];
    const criticalFindings = findings.filter(f => f.severity === 'critical' && f.status === 'non-compliant');
    const majorFindings = findings.filter(f => f.severity === 'major' && f.status !== 'compliant');

    if (criticalFindings.length > 0) {
      steps.push('1. IMMEDIATE: Address all critical non-compliant findings');
      for (const f of criticalFindings.slice(0, 3)) {
        steps.push(`   - ${f.description}`);
      }
    }

    if (majorFindings.length > 0) {
      steps.push(`2. HIGH PRIORITY: Resolve ${majorFindings.length} major finding(s)`);
    }

    steps.push(`3. Review ${framework} ${level} requirements documentation`);
    steps.push('4. Schedule compliance review meeting with stakeholders');
    steps.push('5. Prepare evidence package for certification authority');

    return steps;
  }

  /**
   * Get assessment by ID
   */
  getAssessment(id: string): ComplianceAssessment | null {
    return this.assessments.get(id) || null;
  }

  /**
   * List all assessments
   */
  listAssessments(): Array<{ id: string; assessment: ComplianceAssessment }> {
    return Array.from(this.assessments.entries()).map(([id, assessment]) => ({ id, assessment }));
  }

  /**
   * Get framework information
   */
  getFrameworkInfo(framework: 'NASA-STD-8719' | 'DO-178C' | 'Common-Criteria') {
    switch (framework) {
      case 'NASA-STD-8719':
        return { levels: NASA_SAFETY_CATEGORIES, description: 'NASA Software Safety Standard' };
      case 'DO-178C':
        return { levels: DO178C_LEVELS, description: 'Software Considerations in Airborne Systems' };
      case 'Common-Criteria':
        return { levels: COMMON_CRITERIA_LEVELS, description: 'Common Criteria for IT Security Evaluation' };
    }
  }
}

// Export singleton instance
export const spaceComplianceService = new SpaceComplianceService();
export default spaceComplianceService;
