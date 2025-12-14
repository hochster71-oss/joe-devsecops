/**
 * J.O.E. DevSecOps Arsenal - Security Frameworks Definitions
 * Comprehensive security framework data for AI-powered source citations
 *
 * @module core/security-frameworks
 * @version 1.0.0
 * @license MIT
 */

import type { Framework, Citation, CitationRelevance } from '../types/ai-touchpoint';

// =============================================================================
// FRAMEWORK METADATA
// =============================================================================

export interface FrameworkMetadata {
  readonly id: Framework;
  readonly name: string;
  readonly fullName: string;
  readonly version: string;
  readonly organization: string;
  readonly description: string;
  readonly baseUrl: string;
  readonly iconColor: string;
  readonly category: 'governance' | 'technical' | 'compliance' | 'threat' | 'space-grade';
}

export const FRAMEWORK_METADATA: ReadonlyMap<Framework, FrameworkMetadata> = new Map([
  ['NIST-CSF-2.0', {
    id: 'NIST-CSF-2.0',
    name: 'NIST CSF',
    fullName: 'NIST Cybersecurity Framework 2.0',
    version: '2.0',
    organization: 'National Institute of Standards and Technology',
    description: 'Framework for improving critical infrastructure cybersecurity',
    baseUrl: 'https://www.nist.gov/cyberframework',
    iconColor: '#0066cc',
    category: 'governance'
  }],
  ['NIST-800-53', {
    id: 'NIST-800-53',
    name: 'NIST 800-53',
    fullName: 'NIST Special Publication 800-53 Rev. 5',
    version: 'Rev. 5',
    organization: 'National Institute of Standards and Technology',
    description: 'Security and Privacy Controls for Information Systems',
    baseUrl: 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
    iconColor: '#0066cc',
    category: 'technical'
  }],
  ['NIST-800-171', {
    id: 'NIST-800-171',
    name: 'NIST 800-171',
    fullName: 'NIST Special Publication 800-171 Rev. 2',
    version: 'Rev. 2',
    organization: 'National Institute of Standards and Technology',
    description: 'Protecting Controlled Unclassified Information',
    baseUrl: 'https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final',
    iconColor: '#0066cc',
    category: 'compliance'
  }],
  ['MITRE-ATTACK', {
    id: 'MITRE-ATTACK',
    name: 'MITRE ATT&CK',
    fullName: 'MITRE ATT&CK Framework',
    version: '14.1',
    organization: 'MITRE Corporation',
    description: 'Knowledge base of adversary tactics and techniques',
    baseUrl: 'https://attack.mitre.org',
    iconColor: '#e53935',
    category: 'threat'
  }],
  ['MITRE-DEFEND', {
    id: 'MITRE-DEFEND',
    name: 'MITRE D3FEND',
    fullName: 'MITRE D3FEND Framework',
    version: '1.0',
    organization: 'MITRE Corporation',
    description: 'Knowledge base of defensive countermeasures',
    baseUrl: 'https://d3fend.mitre.org',
    iconColor: '#4caf50',
    category: 'threat'
  }],
  ['CIS-CONTROLS', {
    id: 'CIS-CONTROLS',
    name: 'CIS Controls',
    fullName: 'CIS Critical Security Controls v8',
    version: '8',
    organization: 'Center for Internet Security',
    description: 'Prioritized set of actions to protect organizations',
    baseUrl: 'https://www.cisecurity.org/controls',
    iconColor: '#2e7d32',
    category: 'technical'
  }],
  ['OWASP-TOP-10', {
    id: 'OWASP-TOP-10',
    name: 'OWASP Top 10',
    fullName: 'OWASP Top 10 Web Application Security Risks',
    version: '2021',
    organization: 'Open Web Application Security Project',
    description: 'Top 10 web application security risks',
    baseUrl: 'https://owasp.org/Top10',
    iconColor: '#ff6f00',
    category: 'technical'
  }],
  ['OWASP-ASVS', {
    id: 'OWASP-ASVS',
    name: 'OWASP ASVS',
    fullName: 'OWASP Application Security Verification Standard',
    version: '4.0.3',
    organization: 'Open Web Application Security Project',
    description: 'Framework for testing web application security',
    baseUrl: 'https://owasp.org/www-project-application-security-verification-standard',
    iconColor: '#ff6f00',
    category: 'technical'
  }],
  ['OWASP-SAMM', {
    id: 'OWASP-SAMM',
    name: 'OWASP SAMM',
    fullName: 'OWASP Software Assurance Maturity Model',
    version: '2.0',
    organization: 'Open Web Application Security Project',
    description: 'Framework for software security assurance',
    baseUrl: 'https://owaspsamm.org',
    iconColor: '#ff6f00',
    category: 'governance'
  }],
  ['NASA-STD-8719', {
    id: 'NASA-STD-8719',
    name: 'NASA-STD-8719',
    fullName: 'NASA Software Safety Standard',
    version: '8719.13C',
    organization: 'National Aeronautics and Space Administration',
    description: 'Software safety requirements for NASA missions',
    baseUrl: 'https://standards.nasa.gov/standard/NASA/NASA-STD-871913',
    iconColor: '#7b1fa2',
    category: 'space-grade'
  }],
  ['DO-178C', {
    id: 'DO-178C',
    name: 'DO-178C',
    fullName: 'Software Considerations in Airborne Systems',
    version: 'DO-178C',
    organization: 'RTCA / EUROCAE',
    description: 'Software certification standard for airborne systems',
    baseUrl: 'https://www.rtca.org/content/do-178c',
    iconColor: '#7b1fa2',
    category: 'space-grade'
  }],
  ['CMMC-2.0', {
    id: 'CMMC-2.0',
    name: 'CMMC 2.0',
    fullName: 'Cybersecurity Maturity Model Certification 2.0',
    version: '2.0',
    organization: 'U.S. Department of Defense',
    description: 'DoD contractor cybersecurity requirements',
    baseUrl: 'https://dodcio.defense.gov/CMMC',
    iconColor: '#1565c0',
    category: 'compliance'
  }],
  ['COMMON-CRITERIA', {
    id: 'COMMON-CRITERIA',
    name: 'Common Criteria',
    fullName: 'Common Criteria for IT Security Evaluation',
    version: 'ISO/IEC 15408:2022',
    organization: 'ISO/IEC',
    description: 'International standard for computer security certification',
    baseUrl: 'https://www.commoncriteriaportal.org',
    iconColor: '#6a1b9a',
    category: 'compliance'
  }],
  ['ISO-27001', {
    id: 'ISO-27001',
    name: 'ISO 27001',
    fullName: 'ISO/IEC 27001:2022',
    version: '2022',
    organization: 'International Organization for Standardization',
    description: 'Information security management systems',
    baseUrl: 'https://www.iso.org/standard/27001',
    iconColor: '#00838f',
    category: 'compliance'
  }],
  ['SOC-2', {
    id: 'SOC-2',
    name: 'SOC 2',
    fullName: 'SOC 2 Type II',
    version: '2017',
    organization: 'American Institute of CPAs',
    description: 'Service organization control reporting',
    baseUrl: 'https://www.aicpa.org/soc2',
    iconColor: '#00838f',
    category: 'compliance'
  }],
  ['SLSA', {
    id: 'SLSA',
    name: 'SLSA',
    fullName: 'Supply Chain Levels for Software Artifacts',
    version: '1.0',
    organization: 'OpenSSF',
    description: 'Security framework for software supply chain',
    baseUrl: 'https://slsa.dev',
    iconColor: '#4caf50',
    category: 'technical'
  }]
]);

// =============================================================================
// NIST CSF 2.0
// =============================================================================

export interface NISTCSFFunction {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly categories: readonly NISTCSFCategory[];
}

export interface NISTCSFCategory {
  readonly id: string;
  readonly name: string;
  readonly description: string;
}

export const NIST_CSF_2_FUNCTIONS: readonly NISTCSFFunction[] = [
  {
    id: 'GV',
    name: 'GOVERN',
    description: 'Establish and monitor organizational cybersecurity risk management strategy, expectations, and policy',
    categories: [
      { id: 'GV.OC', name: 'Organizational Context', description: 'Understanding of organizational mission, stakeholder expectations, and legal requirements' },
      { id: 'GV.RM', name: 'Risk Management Strategy', description: 'Organizational priorities, constraints, risk tolerance, and assumptions' },
      { id: 'GV.RR', name: 'Roles & Responsibilities', description: 'Cybersecurity roles, responsibilities, and authorities' },
      { id: 'GV.PO', name: 'Policy', description: 'Organizational cybersecurity policy' },
      { id: 'GV.OV', name: 'Oversight', description: 'Results of risk management activities inform leadership decisions' },
      { id: 'GV.SC', name: 'Cybersecurity Supply Chain Risk Management', description: 'Cyber supply chain risk management processes' }
    ]
  },
  {
    id: 'ID',
    name: 'IDENTIFY',
    description: 'Understand organizational context to manage cybersecurity risk to systems, assets, data, and capabilities',
    categories: [
      { id: 'ID.AM', name: 'Asset Management', description: 'Assets that enable the organization to achieve business purposes' },
      { id: 'ID.RA', name: 'Risk Assessment', description: 'Understanding cybersecurity risk to organizational operations' },
      { id: 'ID.IM', name: 'Improvement', description: 'Improvements to organizational cybersecurity risk management' }
    ]
  },
  {
    id: 'PR',
    name: 'PROTECT',
    description: 'Implement appropriate safeguards to ensure delivery of critical services',
    categories: [
      { id: 'PR.AA', name: 'Identity Management & Access Control', description: 'Access to physical and logical assets is limited' },
      { id: 'PR.AT', name: 'Awareness & Training', description: 'Personnel are provided cybersecurity awareness and training' },
      { id: 'PR.DS', name: 'Data Security', description: 'Information and records are managed consistent with risk strategy' },
      { id: 'PR.PS', name: 'Platform Security', description: 'Hardware, software, and services are managed consistent with risk strategy' },
      { id: 'PR.IR', name: 'Technology Infrastructure Resilience', description: 'Security architectures managed to protect assets' }
    ]
  },
  {
    id: 'DE',
    name: 'DETECT',
    description: 'Implement appropriate activities to identify the occurrence of a cybersecurity event',
    categories: [
      { id: 'DE.CM', name: 'Continuous Monitoring', description: 'Assets are monitored to find anomalies and potential events' },
      { id: 'DE.AE', name: 'Adverse Event Analysis', description: 'Anomalies and potential events are analyzed to characterize and detect cybersecurity events' }
    ]
  },
  {
    id: 'RS',
    name: 'RESPOND',
    description: 'Implement appropriate activities to take action regarding a detected cybersecurity incident',
    categories: [
      { id: 'RS.MA', name: 'Incident Management', description: 'Responses to detected cybersecurity incidents are managed' },
      { id: 'RS.AN', name: 'Incident Analysis', description: 'Investigations conducted to ensure effective response' },
      { id: 'RS.CO', name: 'Incident Response Reporting & Communication', description: 'Coordination with stakeholders occurs' },
      { id: 'RS.MI', name: 'Incident Mitigation', description: 'Activities performed to prevent expansion and mitigate effects' }
    ]
  },
  {
    id: 'RC',
    name: 'RECOVER',
    description: 'Implement appropriate activities to maintain plans for resilience and restore capabilities',
    categories: [
      { id: 'RC.RP', name: 'Incident Recovery Plan Execution', description: 'Restoration activities performed to ensure availability' },
      { id: 'RC.CO', name: 'Incident Recovery Communication', description: 'Restoration activities coordinated with internal and external parties' }
    ]
  }
];

// =============================================================================
// MITRE ATT&CK TACTICS
// =============================================================================

export interface MITRETactic {
  readonly id: string;
  readonly name: string;
  readonly shortName: string;
  readonly description: string;
  readonly url: string;
}

export const MITRE_ATTACK_TACTICS: readonly MITRETactic[] = [
  { id: 'TA0043', name: 'Reconnaissance', shortName: 'recon', description: 'Gathering information to plan future operations', url: 'https://attack.mitre.org/tactics/TA0043' },
  { id: 'TA0042', name: 'Resource Development', shortName: 'resource-dev', description: 'Establishing resources to support operations', url: 'https://attack.mitre.org/tactics/TA0042' },
  { id: 'TA0001', name: 'Initial Access', shortName: 'initial-access', description: 'Trying to get into your network', url: 'https://attack.mitre.org/tactics/TA0001' },
  { id: 'TA0002', name: 'Execution', shortName: 'execution', description: 'Trying to run malicious code', url: 'https://attack.mitre.org/tactics/TA0002' },
  { id: 'TA0003', name: 'Persistence', shortName: 'persistence', description: 'Trying to maintain foothold', url: 'https://attack.mitre.org/tactics/TA0003' },
  { id: 'TA0004', name: 'Privilege Escalation', shortName: 'priv-esc', description: 'Trying to gain higher-level permissions', url: 'https://attack.mitre.org/tactics/TA0004' },
  { id: 'TA0005', name: 'Defense Evasion', shortName: 'defense-evasion', description: 'Trying to avoid being detected', url: 'https://attack.mitre.org/tactics/TA0005' },
  { id: 'TA0006', name: 'Credential Access', shortName: 'cred-access', description: 'Trying to steal account credentials', url: 'https://attack.mitre.org/tactics/TA0006' },
  { id: 'TA0007', name: 'Discovery', shortName: 'discovery', description: 'Trying to figure out your environment', url: 'https://attack.mitre.org/tactics/TA0007' },
  { id: 'TA0008', name: 'Lateral Movement', shortName: 'lateral-movement', description: 'Trying to move through your environment', url: 'https://attack.mitre.org/tactics/TA0008' },
  { id: 'TA0009', name: 'Collection', shortName: 'collection', description: 'Trying to gather data of interest', url: 'https://attack.mitre.org/tactics/TA0009' },
  { id: 'TA0011', name: 'Command and Control', shortName: 'c2', description: 'Trying to communicate with compromised systems', url: 'https://attack.mitre.org/tactics/TA0011' },
  { id: 'TA0010', name: 'Exfiltration', shortName: 'exfiltration', description: 'Trying to steal data', url: 'https://attack.mitre.org/tactics/TA0010' },
  { id: 'TA0040', name: 'Impact', shortName: 'impact', description: 'Trying to manipulate, interrupt, or destroy systems', url: 'https://attack.mitre.org/tactics/TA0040' }
];

// =============================================================================
// CIS CONTROLS v8
// =============================================================================

export interface CISControl {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly ig1: boolean; // Implementation Group 1
  readonly ig2: boolean;
  readonly ig3: boolean;
  readonly safeguardCount: number;
}

export const CIS_CONTROLS_V8: readonly CISControl[] = [
  { id: 'CIS-1', name: 'Inventory and Control of Enterprise Assets', description: 'Actively manage all enterprise assets connected to infrastructure', ig1: true, ig2: true, ig3: true, safeguardCount: 5 },
  { id: 'CIS-2', name: 'Inventory and Control of Software Assets', description: 'Actively manage all software on the network', ig1: true, ig2: true, ig3: true, safeguardCount: 7 },
  { id: 'CIS-3', name: 'Data Protection', description: 'Develop processes and technical controls to identify, classify, and protect data', ig1: true, ig2: true, ig3: true, safeguardCount: 14 },
  { id: 'CIS-4', name: 'Secure Configuration of Enterprise Assets and Software', description: 'Establish and maintain secure configurations', ig1: true, ig2: true, ig3: true, safeguardCount: 12 },
  { id: 'CIS-5', name: 'Account Management', description: 'Use processes and tools to assign and manage authorization to credentials', ig1: true, ig2: true, ig3: true, safeguardCount: 6 },
  { id: 'CIS-6', name: 'Access Control Management', description: 'Use processes and tools to create, assign, manage, and revoke access credentials', ig1: true, ig2: true, ig3: true, safeguardCount: 8 },
  { id: 'CIS-7', name: 'Continuous Vulnerability Management', description: 'Continuously acquire, assess, and address new vulnerabilities', ig1: true, ig2: true, ig3: true, safeguardCount: 7 },
  { id: 'CIS-8', name: 'Audit Log Management', description: 'Collect, alert, review, and retain audit logs of events', ig1: true, ig2: true, ig3: true, safeguardCount: 12 },
  { id: 'CIS-9', name: 'Email and Web Browser Protections', description: 'Improve protections and detections of threats from email and web vectors', ig1: true, ig2: true, ig3: true, safeguardCount: 7 },
  { id: 'CIS-10', name: 'Malware Defenses', description: 'Prevent or control the installation and execution of malicious applications', ig1: true, ig2: true, ig3: true, safeguardCount: 7 },
  { id: 'CIS-11', name: 'Data Recovery', description: 'Establish and maintain data recovery practices', ig1: true, ig2: true, ig3: true, safeguardCount: 5 },
  { id: 'CIS-12', name: 'Network Infrastructure Management', description: 'Establish and maintain network device configurations', ig1: false, ig2: true, ig3: true, safeguardCount: 8 },
  { id: 'CIS-13', name: 'Network Monitoring and Defense', description: 'Operate processes and tooling to monitor and defend against network-based threats', ig1: false, ig2: true, ig3: true, safeguardCount: 11 },
  { id: 'CIS-14', name: 'Security Awareness and Skills Training', description: 'Establish and maintain a security awareness program', ig1: true, ig2: true, ig3: true, safeguardCount: 9 },
  { id: 'CIS-15', name: 'Service Provider Management', description: 'Develop a process to evaluate service providers', ig1: false, ig2: true, ig3: true, safeguardCount: 7 },
  { id: 'CIS-16', name: 'Application Software Security', description: 'Manage the security life cycle of in-house and acquired software', ig1: false, ig2: true, ig3: true, safeguardCount: 14 },
  { id: 'CIS-17', name: 'Incident Response Management', description: 'Establish a program to develop and maintain incident response capability', ig1: true, ig2: true, ig3: true, safeguardCount: 9 },
  { id: 'CIS-18', name: 'Penetration Testing', description: 'Test the effectiveness of security defenses through penetration testing', ig1: false, ig2: false, ig3: true, safeguardCount: 5 }
];

// =============================================================================
// OWASP TOP 10 (2021)
// =============================================================================

export interface OWASPCategory {
  readonly id: string;
  readonly rank: number;
  readonly name: string;
  readonly description: string;
  readonly cwe: readonly string[];
  readonly url: string;
}

export const OWASP_TOP_10_2021: readonly OWASPCategory[] = [
  { id: 'A01', rank: 1, name: 'Broken Access Control', description: 'Restrictions on authenticated users are not properly enforced', cwe: ['CWE-200', 'CWE-201', 'CWE-352'], url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control' },
  { id: 'A02', rank: 2, name: 'Cryptographic Failures', description: 'Failures related to cryptography which often lead to sensitive data exposure', cwe: ['CWE-259', 'CWE-327', 'CWE-331'], url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures' },
  { id: 'A03', rank: 3, name: 'Injection', description: 'User-supplied data is not validated, filtered, or sanitized by the application', cwe: ['CWE-79', 'CWE-89', 'CWE-73'], url: 'https://owasp.org/Top10/A03_2021-Injection' },
  { id: 'A04', rank: 4, name: 'Insecure Design', description: 'Risks related to design and architectural flaws', cwe: ['CWE-209', 'CWE-256', 'CWE-501'], url: 'https://owasp.org/Top10/A04_2021-Insecure_Design' },
  { id: 'A05', rank: 5, name: 'Security Misconfiguration', description: 'Missing appropriate security hardening or improperly configured permissions', cwe: ['CWE-16', 'CWE-611'], url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration' },
  { id: 'A06', rank: 6, name: 'Vulnerable and Outdated Components', description: 'Using components with known vulnerabilities', cwe: ['CWE-1104'], url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components' },
  { id: 'A07', rank: 7, name: 'Identification and Authentication Failures', description: 'Confirmation of user identity, authentication, and session management weaknesses', cwe: ['CWE-287', 'CWE-297', 'CWE-384'], url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures' },
  { id: 'A08', rank: 8, name: 'Software and Data Integrity Failures', description: 'Code and infrastructure that does not protect against integrity violations', cwe: ['CWE-829', 'CWE-494', 'CWE-502'], url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures' },
  { id: 'A09', rank: 9, name: 'Security Logging and Monitoring Failures', description: 'Without logging and monitoring, breaches cannot be detected', cwe: ['CWE-778', 'CWE-117', 'CWE-223'], url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures' },
  { id: 'A10', rank: 10, name: 'Server-Side Request Forgery (SSRF)', description: 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL', cwe: ['CWE-918'], url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29' }
];

// =============================================================================
// NASA-STD-8719.13 SAFETY CLASSIFICATIONS
// =============================================================================

export interface NASASafetyCategory {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly consequences: string;
  readonly verificationMethods: readonly string[];
  readonly requiredControls: readonly string[];
}

export const NASA_SAFETY_CATEGORIES: readonly NASASafetyCategory[] = [
  {
    id: 'CAT-I',
    name: 'Catastrophic',
    description: 'Loss of life or permanently disabling injury, loss of mission-critical systems',
    consequences: 'Death, permanently disabling injury, loss of major facility, or loss of mission',
    verificationMethods: ['Formal Analysis', 'Formal Inspection', 'Formal Test', 'Formal Demonstration'],
    requiredControls: ['Fault tolerance', 'Redundancy', 'Fail-safe design', 'Hardware/software diversity', 'Independent verification']
  },
  {
    id: 'CAT-II',
    name: 'Critical',
    description: 'Severe injury or illness, major property damage, or significant reduction in mission success',
    consequences: 'Severe injury or occupational illness, major damage to facilities or equipment',
    verificationMethods: ['Formal Analysis', 'Formal Inspection', 'Formal Test'],
    requiredControls: ['Fault detection', 'Safe mode transitions', 'Watchdog timers', 'Range safety']
  },
  {
    id: 'CAT-III',
    name: 'Moderate',
    description: 'Minor injury, minor property damage, or minor degradation in mission objectives',
    consequences: 'Minor injury or illness, minor damage requiring repair',
    verificationMethods: ['Analysis', 'Inspection', 'Test'],
    requiredControls: ['Input validation', 'Error handling', 'Logging', 'Recovery procedures']
  },
  {
    id: 'CAT-IV',
    name: 'Negligible',
    description: 'No injury or illness, minimal property damage, negligible impact on mission',
    consequences: 'Less than minor injury, negligible damage',
    verificationMethods: ['Analysis', 'Review'],
    requiredControls: ['Standard development practices', 'Code review']
  }
];

// =============================================================================
// DO-178C DESIGN ASSURANCE LEVELS
// =============================================================================

export interface DO178CLevel {
  readonly id: string;
  readonly name: string;
  readonly failureCondition: string;
  readonly description: string;
  readonly objectiveCount: number;
  readonly independence: 'Full' | 'Substantial' | 'Partial' | 'None';
  readonly coverage: {
    readonly statement?: number;
    readonly decision?: number;
    readonly mcdc?: number;
  };
}

export const DO178C_LEVELS: readonly DO178CLevel[] = [
  {
    id: 'DAL-A',
    name: 'Level A',
    failureCondition: 'Catastrophic',
    description: 'Failure may cause or contribute to a failure of system function resulting in catastrophic failure condition',
    objectiveCount: 71,
    independence: 'Full',
    coverage: { statement: 100, decision: 100, mcdc: 100 }
  },
  {
    id: 'DAL-B',
    name: 'Level B',
    failureCondition: 'Hazardous/Severe-Major',
    description: 'Failure may cause or contribute to a failure resulting in hazardous or severe-major failure condition',
    objectiveCount: 69,
    independence: 'Substantial',
    coverage: { statement: 100, decision: 100 }
  },
  {
    id: 'DAL-C',
    name: 'Level C',
    failureCondition: 'Major',
    description: 'Failure may cause or contribute to a failure resulting in major failure condition',
    objectiveCount: 62,
    independence: 'Partial',
    coverage: { statement: 100 }
  },
  {
    id: 'DAL-D',
    name: 'Level D',
    failureCondition: 'Minor',
    description: 'Failure may cause or contribute to a failure resulting in minor failure condition',
    objectiveCount: 28,
    independence: 'None',
    coverage: {}
  },
  {
    id: 'DAL-E',
    name: 'Level E',
    failureCondition: 'No Effect',
    description: 'Failure has no effect on the operational capability of the system',
    objectiveCount: 0,
    independence: 'None',
    coverage: {}
  }
];

// =============================================================================
// COMMON CRITERIA EAL LEVELS
// =============================================================================

export interface CommonCriteriaEAL {
  readonly id: string;
  readonly level: number;
  readonly name: string;
  readonly description: string;
  readonly developmentEnvironment: string;
  readonly testingDepth: string;
}

export const COMMON_CRITERIA_EAL_LEVELS: readonly CommonCriteriaEAL[] = [
  { id: 'EAL1', level: 1, name: 'Functionally Tested', description: 'Applicable when basic security assurance is required', developmentEnvironment: 'None', testingDepth: 'Basic' },
  { id: 'EAL2', level: 2, name: 'Structurally Tested', description: 'Requires developer cooperation with minimal cost', developmentEnvironment: 'Limited', testingDepth: 'Structural' },
  { id: 'EAL3', level: 3, name: 'Methodically Tested and Checked', description: 'Permits conscientious developer to gain security assurance', developmentEnvironment: 'Methodical', testingDepth: 'Moderate' },
  { id: 'EAL4', level: 4, name: 'Methodically Designed, Tested, and Reviewed', description: 'Maximum assurance from engineering practices', developmentEnvironment: 'Rigorous', testingDepth: 'High' },
  { id: 'EAL5', level: 5, name: 'Semi-formally Designed and Tested', description: 'Rigorous development practices and specialist security engineering', developmentEnvironment: 'Semi-formal', testingDepth: 'Very High' },
  { id: 'EAL6', level: 6, name: 'Semi-formally Verified Design and Tested', description: 'High value assets in significant risk situations', developmentEnvironment: 'Formal Methods', testingDepth: 'Comprehensive' },
  { id: 'EAL7', level: 7, name: 'Formally Verified Design and Tested', description: 'Extremely high risk situations and/or high value assets', developmentEnvironment: 'Formal Proofs', testingDepth: 'Mathematical' }
];

// =============================================================================
// CITATION BUILDER UTILITIES
// =============================================================================

/**
 * Build a citation for a specific framework control
 */
export const buildCitation = (
  framework: Framework,
  controlId: string,
  title: string,
  description: string,
  relevance: CitationRelevance = 'direct'
): Citation => {
  const metadata = FRAMEWORK_METADATA.get(framework);
  const baseUrl = metadata?.baseUrl ?? '';

  const urlMap: Record<Framework, (id: string) => string> = {
    'NIST-CSF-2.0': (id) => `https://www.nist.gov/cyberframework/csf-20/csf-core/${id.toLowerCase()}`,
    'NIST-800-53': (id) => `https://csrc.nist.gov/Projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=${id}`,
    'NIST-800-171': (id) => `https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final#${id}`,
    'MITRE-ATTACK': (id) => `https://attack.mitre.org/techniques/${id}`,
    'MITRE-DEFEND': (id) => `https://d3fend.mitre.org/technique/${id}`,
    'CIS-CONTROLS': (id) => `https://www.cisecurity.org/controls/v8#${id}`,
    'OWASP-TOP-10': (id) => `https://owasp.org/Top10/${id}`,
    'OWASP-ASVS': (id) => `https://github.com/OWASP/ASVS/blob/master/5.0/en/0x${id}.md`,
    'OWASP-SAMM': (id) => `https://owaspsamm.org/model/${id}`,
    'NASA-STD-8719': (id) => `https://standards.nasa.gov/standard/NASA/NASA-STD-871913#${id}`,
    'DO-178C': (id) => `https://www.rtca.org/content/do-178c#${id}`,
    'CMMC-2.0': (id) => `https://dodcio.defense.gov/CMMC/Model/#${id}`,
    'COMMON-CRITERIA': (id) => `https://www.commoncriteriaportal.org/cc/#${id}`,
    'ISO-27001': (id) => `https://www.iso.org/standard/27001#${id}`,
    'SOC-2': (id) => `https://www.aicpa.org/soc2#${id}`,
    'SLSA': (id) => `https://slsa.dev/spec/v1.0/levels#${id}`
  };

  const urlBuilder = urlMap[framework] ?? (() => baseUrl);

  return {
    framework,
    controlId,
    title,
    description,
    url: urlBuilder(controlId),
    relevance
  };
};

/**
 * Get framework display color
 */
export const getFrameworkColor = (framework: Framework): string =>
  FRAMEWORK_METADATA.get(framework)?.iconColor ?? '#666666';

/**
 * Get framework short name
 */
export const getFrameworkShortName = (framework: Framework): string =>
  FRAMEWORK_METADATA.get(framework)?.name ?? framework;

/**
 * Map vulnerability to relevant frameworks
 */
export const mapVulnerabilityToFrameworks = (
  vulnType: string,
  severity: 'low' | 'medium' | 'high' | 'critical'
): readonly Framework[] => {
  const frameworkMap: Record<string, readonly Framework[]> = {
    'injection': ['OWASP-TOP-10', 'NIST-800-53', 'CIS-CONTROLS', 'MITRE-ATTACK'],
    'authentication': ['OWASP-TOP-10', 'NIST-800-53', 'CIS-CONTROLS', 'CMMC-2.0'],
    'access-control': ['OWASP-TOP-10', 'NIST-800-53', 'CIS-CONTROLS', 'ISO-27001'],
    'cryptography': ['OWASP-TOP-10', 'NIST-800-53', 'COMMON-CRITERIA'],
    'supply-chain': ['SLSA', 'NIST-CSF-2.0', 'CIS-CONTROLS'],
    'configuration': ['CIS-CONTROLS', 'NIST-800-53', 'OWASP-TOP-10'],
    'default': ['NIST-CSF-2.0', 'OWASP-TOP-10', 'CIS-CONTROLS']
  };

  const baseFrameworks = frameworkMap[vulnType.toLowerCase()] ?? frameworkMap['default'];

  // Add space-grade frameworks for critical severity
  if (severity === 'critical') {
    return [...baseFrameworks, 'NASA-STD-8719', 'DO-178C'];
  }

  return baseFrameworks;
};

/**
 * Get MITRE ATT&CK tactic by technique ID
 */
export const getTacticForTechnique = (techniqueId: string): MITRETactic | undefined => {
  // Simplified mapping - in production, this would use a complete technique-to-tactic mapping
  const tacticPrefixMap: Record<string, string> = {
    'T1595': 'TA0043', // Active Scanning -> Reconnaissance
    'T1190': 'TA0001', // Exploit Public-Facing Application -> Initial Access
    'T1059': 'TA0002', // Command and Scripting Interpreter -> Execution
    'T1078': 'TA0003', // Valid Accounts -> Persistence
    'T1068': 'TA0004', // Exploitation for Privilege Escalation -> Privilege Escalation
    'T1562': 'TA0005', // Impair Defenses -> Defense Evasion
    'T1003': 'TA0006', // OS Credential Dumping -> Credential Access
    'T1082': 'TA0007', // System Information Discovery -> Discovery
    'T1021': 'TA0008', // Remote Services -> Lateral Movement
    'T1005': 'TA0009', // Data from Local System -> Collection
    'T1041': 'TA0010', // Exfiltration Over C2 Channel -> Exfiltration
    'T1071': 'TA0011', // Application Layer Protocol -> Command and Control
    'T1486': 'TA0040'  // Data Encrypted for Impact -> Impact
  };

  const tacticId = tacticPrefixMap[techniqueId.split('.')[0]];
  return MITRE_ATTACK_TACTICS.find(t => t.id === tacticId);
};

// =============================================================================
// SOC 2 TYPE II - TRUST SERVICE CRITERIA
// =============================================================================

export interface SOC2TrustServiceCriteria {
  readonly id: string;
  readonly category: 'security' | 'availability' | 'processing-integrity' | 'confidentiality' | 'privacy';
  readonly name: string;
  readonly description: string;
  readonly pointsOfFocus: readonly string[];
}

export const SOC2_TRUST_SERVICE_CRITERIA: readonly SOC2TrustServiceCriteria[] = [
  // Security (Common Criteria)
  { id: 'CC1.1', category: 'security', name: 'COSO Principle 1', description: 'The entity demonstrates commitment to integrity and ethical values', pointsOfFocus: ['Tone at the top', 'Standards of conduct', 'Deviations addressed'] },
  { id: 'CC1.2', category: 'security', name: 'COSO Principle 2', description: 'The board exercises oversight responsibility', pointsOfFocus: ['Board independence', 'Board expertise', 'Oversight of internal control'] },
  { id: 'CC1.3', category: 'security', name: 'COSO Principle 3', description: 'Management establishes structures, reporting lines, and authorities', pointsOfFocus: ['Organizational structure', 'Reporting lines', 'Authorities and responsibilities'] },
  { id: 'CC1.4', category: 'security', name: 'COSO Principle 4', description: 'The entity demonstrates commitment to attract and retain competent individuals', pointsOfFocus: ['HR policies', 'Competency requirements', 'Training programs'] },
  { id: 'CC1.5', category: 'security', name: 'COSO Principle 5', description: 'The entity holds individuals accountable for internal control responsibilities', pointsOfFocus: ['Performance measures', 'Incentives', 'Accountability enforcement'] },
  { id: 'CC2.1', category: 'security', name: 'Information Communication', description: 'The entity obtains or generates relevant, quality information', pointsOfFocus: ['Information requirements', 'Data sources', 'Processing integrity'] },
  { id: 'CC2.2', category: 'security', name: 'Internal Communication', description: 'The entity internally communicates information necessary to support objectives', pointsOfFocus: ['Communication policies', 'Communication methods', 'Separate lines of communication'] },
  { id: 'CC2.3', category: 'security', name: 'External Communication', description: 'The entity communicates with external parties', pointsOfFocus: ['External communication channels', 'Whistleblower mechanisms', 'External auditor communication'] },
  { id: 'CC3.1', category: 'security', name: 'Risk Objectives', description: 'The entity specifies objectives with sufficient clarity', pointsOfFocus: ['Operations objectives', 'External reporting', 'Compliance objectives'] },
  { id: 'CC3.2', category: 'security', name: 'Risk Identification', description: 'The entity identifies and analyzes risks', pointsOfFocus: ['Entity and subsidiary risks', 'External factors', 'Change management'] },
  { id: 'CC3.3', category: 'security', name: 'Fraud Risk', description: 'The entity considers the potential for fraud in assessing risks', pointsOfFocus: ['Incentives and pressures', 'Opportunities', 'Attitudes and rationalizations'] },
  { id: 'CC3.4', category: 'security', name: 'Change Analysis', description: 'The entity identifies and assesses changes that could significantly impact internal control', pointsOfFocus: ['External environment changes', 'Business model changes', 'Leadership changes'] },
  { id: 'CC4.1', category: 'security', name: 'Monitoring Activities', description: 'The entity selects, develops, and performs ongoing evaluations', pointsOfFocus: ['Automated monitoring', 'Baseline understanding', 'Periodic assessments'] },
  { id: 'CC4.2', category: 'security', name: 'Deficiency Communication', description: 'The entity evaluates and communicates internal control deficiencies', pointsOfFocus: ['Assessment of results', 'Corrective action', 'Management reporting'] },
  { id: 'CC5.1', category: 'security', name: 'Control Selection', description: 'The entity selects and develops control activities', pointsOfFocus: ['Integration with risk assessment', 'Control variety', 'Segregation of duties'] },
  { id: 'CC5.2', category: 'security', name: 'Technology Controls', description: 'The entity selects and develops general controls over technology', pointsOfFocus: ['IT infrastructure', 'Security management', 'Technology acquisition'] },
  { id: 'CC5.3', category: 'security', name: 'Policy Deployment', description: 'The entity deploys control activities through policies and procedures', pointsOfFocus: ['Policies and procedures', 'Responsibility and accountability', 'Timely action'] },
  { id: 'CC6.1', category: 'security', name: 'Logical Access', description: 'The entity implements logical access security software', pointsOfFocus: ['Access control', 'Authentication', 'Authorization'] },
  { id: 'CC6.2', category: 'security', name: 'Access Authorization', description: 'Prior to issuing system credentials, the entity registers and authorizes new users', pointsOfFocus: ['User registration', 'Authorization process', 'Credential management'] },
  { id: 'CC6.3', category: 'security', name: 'Access Removal', description: 'The entity removes access to protected information assets when appropriate', pointsOfFocus: ['Timely removal', 'Access reviews', 'Transfer handling'] },
  { id: 'CC6.4', category: 'security', name: 'Access Review', description: 'The entity restricts and reviews physical access', pointsOfFocus: ['Physical security', 'Access logs', 'Visitor management'] },
  { id: 'CC6.5', category: 'security', name: 'Asset Disposal', description: 'The entity discontinues logical and physical protections over assets only after transfer', pointsOfFocus: ['Data sanitization', 'Asset disposal', 'Transfer verification'] },
  { id: 'CC6.6', category: 'security', name: 'External Threats', description: 'The entity implements controls to prevent or detect and correct unauthorized access', pointsOfFocus: ['Boundary protection', 'Threat detection', 'Incident response'] },
  { id: 'CC6.7', category: 'security', name: 'Data Transmission', description: 'The entity restricts transmission, movement, and removal of information', pointsOfFocus: ['Encryption', 'Data loss prevention', 'Secure transmission'] },
  { id: 'CC6.8', category: 'security', name: 'Malware Prevention', description: 'The entity implements controls to prevent or detect malicious software', pointsOfFocus: ['Anti-malware', 'Software integrity', 'Security monitoring'] },
  { id: 'CC7.1', category: 'security', name: 'Configuration Management', description: 'To meet its objectives, the entity uses detection and monitoring procedures', pointsOfFocus: ['Configuration baselines', 'Change detection', 'Vulnerability monitoring'] },
  { id: 'CC7.2', category: 'security', name: 'Security Monitoring', description: 'The entity monitors system components and operation', pointsOfFocus: ['Security event monitoring', 'Anomaly detection', 'Log analysis'] },
  { id: 'CC7.3', category: 'security', name: 'Incident Analysis', description: 'The entity evaluates security events to determine whether they could or have resulted in incidents', pointsOfFocus: ['Event evaluation', 'Incident classification', 'Root cause analysis'] },
  { id: 'CC7.4', category: 'security', name: 'Incident Response', description: 'The entity responds to identified security incidents', pointsOfFocus: ['Incident response plan', 'Communication protocols', 'Containment procedures'] },
  { id: 'CC7.5', category: 'security', name: 'Incident Recovery', description: 'The entity identifies, develops, and implements activities to recover from incidents', pointsOfFocus: ['Recovery procedures', 'Business continuity', 'Lessons learned'] },
  { id: 'CC8.1', category: 'security', name: 'Change Management', description: 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes', pointsOfFocus: ['Change authorization', 'Testing procedures', 'Documentation'] },
  { id: 'CC9.1', category: 'security', name: 'Risk Mitigation', description: 'The entity identifies, selects, and develops risk mitigation activities', pointsOfFocus: ['Control identification', 'Mitigation strategies', 'Residual risk acceptance'] },
  { id: 'CC9.2', category: 'security', name: 'Vendor Management', description: 'The entity assesses and manages risks associated with vendors', pointsOfFocus: ['Vendor assessment', 'Contract requirements', 'Ongoing monitoring'] },

  // Availability
  { id: 'A1.1', category: 'availability', name: 'Capacity Management', description: 'The entity maintains, monitors, and evaluates current capacity', pointsOfFocus: ['Capacity planning', 'Performance monitoring', 'Scalability'] },
  { id: 'A1.2', category: 'availability', name: 'Environmental Protection', description: 'The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections', pointsOfFocus: ['Environmental controls', 'Backup power', 'Fire suppression'] },
  { id: 'A1.3', category: 'availability', name: 'Recovery Testing', description: 'The entity tests recovery plan procedures supporting system recovery', pointsOfFocus: ['Backup testing', 'Recovery testing', 'Disaster recovery'] },

  // Processing Integrity
  { id: 'PI1.1', category: 'processing-integrity', name: 'Data Quality', description: 'The entity obtains or generates, uses, and communicates relevant, quality information', pointsOfFocus: ['Input validation', 'Processing accuracy', 'Output verification'] },
  { id: 'PI1.2', category: 'processing-integrity', name: 'System Processing', description: 'The entity implements policies and procedures over system processing', pointsOfFocus: ['Processing controls', 'Error handling', 'Transaction integrity'] },
  { id: 'PI1.3', category: 'processing-integrity', name: 'Processing Accuracy', description: 'The entity implements policies and procedures to ensure completeness and accuracy', pointsOfFocus: ['Completeness checks', 'Accuracy verification', 'Reconciliation'] },
  { id: 'PI1.4', category: 'processing-integrity', name: 'Output Delivery', description: 'The entity implements policies to ensure outputs are complete and accurate', pointsOfFocus: ['Output validation', 'Delivery confirmation', 'Error correction'] },
  { id: 'PI1.5', category: 'processing-integrity', name: 'Input/Output Storage', description: 'The entity implements policies to store inputs and outputs completely and accurately', pointsOfFocus: ['Data retention', 'Archive integrity', 'Storage security'] },

  // Confidentiality
  { id: 'C1.1', category: 'confidentiality', name: 'Confidential Information', description: 'The entity identifies and maintains confidential information', pointsOfFocus: ['Data classification', 'Confidentiality policies', 'Information handling'] },
  { id: 'C1.2', category: 'confidentiality', name: 'Confidentiality Disposal', description: 'The entity disposes of confidential information', pointsOfFocus: ['Secure disposal', 'Destruction verification', 'Retention policies'] },

  // Privacy
  { id: 'P1.1', category: 'privacy', name: 'Privacy Notice', description: 'The entity provides notice about privacy policies and procedures', pointsOfFocus: ['Privacy notice content', 'Notice delivery', 'Notice updates'] },
  { id: 'P2.1', category: 'privacy', name: 'Privacy Consent', description: 'The entity communicates choices available regarding collection, use, and disclosure', pointsOfFocus: ['Consent mechanisms', 'Opt-out options', 'Consent records'] },
  { id: 'P3.1', category: 'privacy', name: 'Privacy Collection', description: 'Personal information is collected consistent with privacy notice', pointsOfFocus: ['Collection limitation', 'Purpose specification', 'Data minimization'] },
  { id: 'P3.2', category: 'privacy', name: 'Collection Sources', description: 'The entity collects personal information from reliable sources', pointsOfFocus: ['Source verification', 'Third-party collection', 'Implicit collection'] },
  { id: 'P4.1', category: 'privacy', name: 'Privacy Use', description: 'The entity limits the use of personal information', pointsOfFocus: ['Use limitation', 'Purpose compatibility', 'Secondary use consent'] },
  { id: 'P4.2', category: 'privacy', name: 'Data Retention', description: 'The entity retains personal information consistent with objectives', pointsOfFocus: ['Retention schedules', 'Disposal procedures', 'Retention justification'] },
  { id: 'P4.3', category: 'privacy', name: 'Data Disposal', description: 'The entity securely disposes of personal information', pointsOfFocus: ['Secure erasure', 'Disposal verification', 'Third-party disposal'] },
  { id: 'P5.1', category: 'privacy', name: 'Data Access', description: 'The entity grants identified and authenticated data subjects the ability to access their stored personal information', pointsOfFocus: ['Access request process', 'Identity verification', 'Access delivery'] },
  { id: 'P5.2', category: 'privacy', name: 'Data Correction', description: 'The entity corrects, amends, or appends personal information', pointsOfFocus: ['Correction process', 'Update verification', 'Third-party notification'] },
  { id: 'P6.1', category: 'privacy', name: 'Privacy Disclosure', description: 'The entity discloses personal information to third parties with appropriate consent', pointsOfFocus: ['Disclosure consent', 'Third-party agreements', 'Disclosure records'] },
  { id: 'P6.2', category: 'privacy', name: 'Disclosure Records', description: 'The entity creates and retains a complete, accurate, and timely record of disclosures', pointsOfFocus: ['Disclosure logging', 'Record accuracy', 'Record retention'] },
  { id: 'P6.3', category: 'privacy', name: 'Third-Party Accountability', description: 'The entity obtains privacy commitments from third parties', pointsOfFocus: ['Contractual requirements', 'Privacy assessments', 'Compliance monitoring'] },
  { id: 'P6.4', category: 'privacy', name: 'Data Subject Notification', description: 'The entity provides notification of third-party disclosures and new uses', pointsOfFocus: ['Change notification', 'Consent renewal', 'Opt-out opportunity'] },
  { id: 'P6.5', category: 'privacy', name: 'Third-Party Verification', description: 'The entity obtains assurances that personal information is protected by third parties', pointsOfFocus: ['Third-party audits', 'Compliance certifications', 'Security assessments'] },
  { id: 'P6.6', category: 'privacy', name: 'Unauthorized Disclosure', description: 'The entity provides notification of breaches and incidents', pointsOfFocus: ['Breach notification', 'Incident communication', 'Regulatory reporting'] },
  { id: 'P6.7', category: 'privacy', name: 'Privacy Inquiry', description: 'The entity provides data subjects with an efficient means to address inquiries', pointsOfFocus: ['Inquiry process', 'Response timeliness', 'Complaint handling'] },
  { id: 'P7.1', category: 'privacy', name: 'Data Quality', description: 'The entity collects and maintains accurate, up-to-date, complete, and relevant personal information', pointsOfFocus: ['Accuracy verification', 'Update procedures', 'Completeness checks'] },
  { id: 'P8.1', category: 'privacy', name: 'Privacy Governance', description: 'The entity implements a privacy governance program', pointsOfFocus: ['Privacy officer', 'Governance structure', 'Policy management'] }
];

// =============================================================================
// HIPAA SECURITY RULE
// =============================================================================

export interface HIPAASafeguard {
  readonly id: string;
  readonly category: 'administrative' | 'physical' | 'technical' | 'organizational';
  readonly name: string;
  readonly description: string;
  readonly required: boolean;
  readonly specification: 'required' | 'addressable';
  readonly section: string;
}

export const HIPAA_SAFEGUARDS: readonly HIPAASafeguard[] = [
  // Administrative Safeguards (164.308)
  { id: '164.308(a)(1)(i)', category: 'administrative', name: 'Security Management Process', description: 'Implement policies and procedures to prevent, detect, contain, and correct security violations', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(1)(ii)(A)', category: 'administrative', name: 'Risk Analysis', description: 'Conduct an accurate and thorough assessment of potential risks and vulnerabilities', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(1)(ii)(B)', category: 'administrative', name: 'Risk Management', description: 'Implement security measures to reduce risks and vulnerabilities', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(1)(ii)(C)', category: 'administrative', name: 'Sanction Policy', description: 'Apply appropriate sanctions against workforce members who fail to comply', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(1)(ii)(D)', category: 'administrative', name: 'Information System Activity Review', description: 'Implement procedures to regularly review records of information system activity', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(2)', category: 'administrative', name: 'Assigned Security Responsibility', description: 'Identify the security official responsible for developing and implementing policies', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(3)(i)', category: 'administrative', name: 'Workforce Security', description: 'Implement policies to ensure appropriate access to ePHI', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(3)(ii)(A)', category: 'administrative', name: 'Authorization and Supervision', description: 'Implement procedures for authorizing access to ePHI', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(3)(ii)(B)', category: 'administrative', name: 'Workforce Clearance', description: 'Implement procedures to determine appropriate ePHI access', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(3)(ii)(C)', category: 'administrative', name: 'Termination Procedures', description: 'Implement procedures for terminating access when employment ends', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(4)(i)', category: 'administrative', name: 'Information Access Management', description: 'Implement policies for authorizing access to ePHI', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(4)(ii)(A)', category: 'administrative', name: 'Isolating Healthcare Clearinghouse', description: 'Implement policies to protect clearinghouse functions', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(4)(ii)(B)', category: 'administrative', name: 'Access Authorization', description: 'Implement policies for granting access to ePHI', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(4)(ii)(C)', category: 'administrative', name: 'Access Establishment and Modification', description: 'Implement policies for establishing, documenting, reviewing, and modifying user access', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(5)(i)', category: 'administrative', name: 'Security Awareness Training', description: 'Implement a security awareness and training program', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(5)(ii)(A)', category: 'administrative', name: 'Security Reminders', description: 'Periodic security updates', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(5)(ii)(B)', category: 'administrative', name: 'Protection from Malicious Software', description: 'Procedures for guarding against, detecting, and reporting malware', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(5)(ii)(C)', category: 'administrative', name: 'Log-in Monitoring', description: 'Procedures for monitoring log-in attempts and reporting discrepancies', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(5)(ii)(D)', category: 'administrative', name: 'Password Management', description: 'Procedures for creating, changing, and safeguarding passwords', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(6)(i)', category: 'administrative', name: 'Security Incident Procedures', description: 'Implement policies to address security incidents', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(6)(ii)', category: 'administrative', name: 'Response and Reporting', description: 'Identify and respond to suspected or known security incidents', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(7)(i)', category: 'administrative', name: 'Contingency Plan', description: 'Establish policies for responding to emergencies', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(7)(ii)(A)', category: 'administrative', name: 'Data Backup Plan', description: 'Establish procedures to create retrievable exact copies of ePHI', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(7)(ii)(B)', category: 'administrative', name: 'Disaster Recovery Plan', description: 'Establish procedures to restore any loss of data', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(7)(ii)(C)', category: 'administrative', name: 'Emergency Mode Operation Plan', description: 'Establish procedures to enable continuation of critical processes', required: true, specification: 'required', section: '164.308' },
  { id: '164.308(a)(7)(ii)(D)', category: 'administrative', name: 'Testing and Revision', description: 'Procedures for periodic testing and revision of contingency plans', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(7)(ii)(E)', category: 'administrative', name: 'Applications and Data Criticality Analysis', description: 'Assess relative criticality of applications and data', required: false, specification: 'addressable', section: '164.308' },
  { id: '164.308(a)(8)', category: 'administrative', name: 'Evaluation', description: 'Perform periodic technical and nontechnical evaluation', required: true, specification: 'required', section: '164.308' },

  // Physical Safeguards (164.310)
  { id: '164.310(a)(1)', category: 'physical', name: 'Facility Access Controls', description: 'Implement policies to limit physical access to systems', required: true, specification: 'required', section: '164.310' },
  { id: '164.310(a)(2)(i)', category: 'physical', name: 'Contingency Operations', description: 'Establish procedures for facility access during emergencies', required: false, specification: 'addressable', section: '164.310' },
  { id: '164.310(a)(2)(ii)', category: 'physical', name: 'Facility Security Plan', description: 'Implement policies to safeguard the facility and equipment', required: false, specification: 'addressable', section: '164.310' },
  { id: '164.310(a)(2)(iii)', category: 'physical', name: 'Access Control and Validation', description: 'Implement procedures to control and validate facility access', required: false, specification: 'addressable', section: '164.310' },
  { id: '164.310(a)(2)(iv)', category: 'physical', name: 'Maintenance Records', description: 'Implement policies for documenting repairs and modifications', required: false, specification: 'addressable', section: '164.310' },
  { id: '164.310(b)', category: 'physical', name: 'Workstation Use', description: 'Implement policies for proper workstation use', required: true, specification: 'required', section: '164.310' },
  { id: '164.310(c)', category: 'physical', name: 'Workstation Security', description: 'Implement physical safeguards for workstations', required: true, specification: 'required', section: '164.310' },
  { id: '164.310(d)(1)', category: 'physical', name: 'Device and Media Controls', description: 'Implement policies for receipt and removal of hardware and media', required: true, specification: 'required', section: '164.310' },
  { id: '164.310(d)(2)(i)', category: 'physical', name: 'Disposal', description: 'Implement policies for final disposal of ePHI and media', required: true, specification: 'required', section: '164.310' },
  { id: '164.310(d)(2)(ii)', category: 'physical', name: 'Media Re-use', description: 'Implement procedures for removal of ePHI before media reuse', required: true, specification: 'required', section: '164.310' },
  { id: '164.310(d)(2)(iii)', category: 'physical', name: 'Accountability', description: 'Maintain records of hardware and media movements', required: false, specification: 'addressable', section: '164.310' },
  { id: '164.310(d)(2)(iv)', category: 'physical', name: 'Data Backup and Storage', description: 'Create retrievable exact copy of ePHI before equipment movement', required: false, specification: 'addressable', section: '164.310' },

  // Technical Safeguards (164.312)
  { id: '164.312(a)(1)', category: 'technical', name: 'Access Control', description: 'Implement technical policies to allow only authorized access', required: true, specification: 'required', section: '164.312' },
  { id: '164.312(a)(2)(i)', category: 'technical', name: 'Unique User Identification', description: 'Assign unique name/number for identifying and tracking user identity', required: true, specification: 'required', section: '164.312' },
  { id: '164.312(a)(2)(ii)', category: 'technical', name: 'Emergency Access Procedure', description: 'Establish procedures for obtaining necessary ePHI during emergencies', required: true, specification: 'required', section: '164.312' },
  { id: '164.312(a)(2)(iii)', category: 'technical', name: 'Automatic Logoff', description: 'Implement electronic procedures that terminate sessions after inactivity', required: false, specification: 'addressable', section: '164.312' },
  { id: '164.312(a)(2)(iv)', category: 'technical', name: 'Encryption and Decryption', description: 'Implement mechanism to encrypt and decrypt ePHI', required: false, specification: 'addressable', section: '164.312' },
  { id: '164.312(b)', category: 'technical', name: 'Audit Controls', description: 'Implement hardware, software, and procedural mechanisms to record and examine activity', required: true, specification: 'required', section: '164.312' },
  { id: '164.312(c)(1)', category: 'technical', name: 'Integrity', description: 'Implement policies to protect ePHI from improper alteration or destruction', required: true, specification: 'required', section: '164.312' },
  { id: '164.312(c)(2)', category: 'technical', name: 'Mechanism to Authenticate ePHI', description: 'Implement electronic mechanisms to corroborate ePHI has not been altered', required: false, specification: 'addressable', section: '164.312' },
  { id: '164.312(d)', category: 'technical', name: 'Person or Entity Authentication', description: 'Implement procedures to verify person or entity seeking access', required: true, specification: 'required', section: '164.312' },
  { id: '164.312(e)(1)', category: 'technical', name: 'Transmission Security', description: 'Implement technical security measures to guard against unauthorized access during transmission', required: true, specification: 'required', section: '164.312' },
  { id: '164.312(e)(2)(i)', category: 'technical', name: 'Integrity Controls', description: 'Implement security measures to ensure electronically transmitted ePHI is not improperly modified', required: false, specification: 'addressable', section: '164.312' },
  { id: '164.312(e)(2)(ii)', category: 'technical', name: 'Encryption', description: 'Implement mechanism to encrypt ePHI during transmission', required: false, specification: 'addressable', section: '164.312' },

  // Organizational Requirements (164.314)
  { id: '164.314(a)(1)', category: 'organizational', name: 'Business Associate Contracts', description: 'Contract or other arrangement required between covered entity and business associate', required: true, specification: 'required', section: '164.314' },
  { id: '164.314(a)(2)(i)', category: 'organizational', name: 'Business Associate Contracts', description: 'Contract must meet requirements of 164.314(a)(2)(i)', required: true, specification: 'required', section: '164.314' },
  { id: '164.314(a)(2)(ii)', category: 'organizational', name: 'Other Arrangements', description: 'Memorandum of understanding if both entities are government', required: true, specification: 'required', section: '164.314' },
  { id: '164.314(b)(1)', category: 'organizational', name: 'Group Health Plan Requirements', description: 'Plan documents must be amended to incorporate provisions', required: true, specification: 'required', section: '164.314' },
  { id: '164.314(b)(2)', category: 'organizational', name: 'Plan Document Requirements', description: 'Plan documents of group health plan must incorporate provisions', required: true, specification: 'required', section: '164.314' }
];

// =============================================================================
// FEDRAMP SECURITY CONTROLS
// =============================================================================

export interface FedRAMPControl {
  readonly id: string;
  readonly family: string;
  readonly name: string;
  readonly description: string;
  readonly impactLevel: ('low' | 'moderate' | 'high')[];
  readonly nistMapping: string;
}

export const FEDRAMP_CONTROL_FAMILIES = [
  { id: 'AC', name: 'Access Control', controlCount: 25 },
  { id: 'AT', name: 'Awareness and Training', controlCount: 5 },
  { id: 'AU', name: 'Audit and Accountability', controlCount: 16 },
  { id: 'CA', name: 'Assessment, Authorization, and Monitoring', controlCount: 9 },
  { id: 'CM', name: 'Configuration Management', controlCount: 11 },
  { id: 'CP', name: 'Contingency Planning', controlCount: 13 },
  { id: 'IA', name: 'Identification and Authentication', controlCount: 12 },
  { id: 'IR', name: 'Incident Response', controlCount: 10 },
  { id: 'MA', name: 'Maintenance', controlCount: 6 },
  { id: 'MP', name: 'Media Protection', controlCount: 8 },
  { id: 'PE', name: 'Physical and Environmental Protection', controlCount: 20 },
  { id: 'PL', name: 'Planning', controlCount: 11 },
  { id: 'PM', name: 'Program Management', controlCount: 16 },
  { id: 'PS', name: 'Personnel Security', controlCount: 9 },
  { id: 'PT', name: 'PII Processing and Transparency', controlCount: 8 },
  { id: 'RA', name: 'Risk Assessment', controlCount: 9 },
  { id: 'SA', name: 'System and Services Acquisition', controlCount: 22 },
  { id: 'SC', name: 'System and Communications Protection', controlCount: 44 },
  { id: 'SI', name: 'System and Information Integrity', controlCount: 23 },
  { id: 'SR', name: 'Supply Chain Risk Management', controlCount: 12 }
] as const;

export const FEDRAMP_IMPACT_LEVELS = {
  low: { controlCount: 125, description: 'Low impact for systems where loss would have limited adverse effect' },
  moderate: { controlCount: 325, description: 'Moderate impact for systems where loss would have serious adverse effect' },
  high: { controlCount: 421, description: 'High impact for systems where loss would have severe or catastrophic effect' }
} as const;

// =============================================================================
// PCI DSS 4.0
// =============================================================================

export interface PCIDSSRequirement {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly goal: string;
  readonly subRequirements: readonly {
    readonly id: string;
    readonly name: string;
    readonly description: string;
  }[];
}

export const PCI_DSS_4_REQUIREMENTS: readonly PCIDSSRequirement[] = [
  {
    id: 'PCI-1',
    name: 'Install and Maintain Network Security Controls',
    description: 'Network security controls (NSCs), such as firewalls and other network security technologies, are network policy enforcement points',
    goal: 'Build and Maintain a Secure Network and Systems',
    subRequirements: [
      { id: '1.1', name: 'Security Policies and Procedures', description: 'Processes and mechanisms for installing and maintaining NSCs are defined and understood' },
      { id: '1.2', name: 'NSC Configuration', description: 'NSCs are configured and maintained' },
      { id: '1.3', name: 'Network Access Restriction', description: 'Network access to and from the CDE is restricted' },
      { id: '1.4', name: 'Trusted Network Connections', description: 'Network connections between trusted and untrusted networks are controlled' },
      { id: '1.5', name: 'CDE Network Risks', description: 'Risks to the CDE from computing devices able to connect to both untrusted networks and the CDE are mitigated' }
    ]
  },
  {
    id: 'PCI-2',
    name: 'Apply Secure Configurations',
    description: 'Apply secure configurations to all system components to reduce vulnerabilities introduced by default configurations',
    goal: 'Build and Maintain a Secure Network and Systems',
    subRequirements: [
      { id: '2.1', name: 'Configuration Policies', description: 'Processes and mechanisms for applying secure configurations are defined and understood' },
      { id: '2.2', name: 'System Configuration Standards', description: 'System components are configured and managed securely' },
      { id: '2.3', name: 'Wireless Security', description: 'Wireless environments are configured and managed securely' }
    ]
  },
  {
    id: 'PCI-3',
    name: 'Protect Stored Account Data',
    description: 'Protection methods such as encryption, truncation, masking, and hashing are critical components of cardholder data protection',
    goal: 'Protect Account Data',
    subRequirements: [
      { id: '3.1', name: 'Data Retention Policies', description: 'Processes and mechanisms for protecting stored account data are defined and understood' },
      { id: '3.2', name: 'Account Data Storage', description: 'Storage of account data is kept to a minimum' },
      { id: '3.3', name: 'SAD Protection', description: 'Sensitive authentication data (SAD) is not stored after authorization' },
      { id: '3.4', name: 'PAN Display Restriction', description: 'Access to displays of full PAN and ability to copy cardholder data is restricted' },
      { id: '3.5', name: 'PAN Protection', description: 'Primary account number (PAN) is secured wherever it is stored' },
      { id: '3.6', name: 'Cryptographic Keys', description: 'Cryptographic keys used to protect stored account data are secured' },
      { id: '3.7', name: 'Key Management', description: 'Where cryptography is used to protect stored account data, key management processes cover all aspects of the key lifecycle' }
    ]
  },
  {
    id: 'PCI-4',
    name: 'Protect Cardholder Data with Strong Cryptography',
    description: 'Sensitive cardholder data transmitted over public networks must be protected with strong cryptography',
    goal: 'Protect Account Data',
    subRequirements: [
      { id: '4.1', name: 'Transmission Policies', description: 'Processes and mechanisms for protecting cardholder data with strong cryptography during transmission are defined' },
      { id: '4.2', name: 'PAN Transmission Protection', description: 'PAN is protected with strong cryptography during transmission' }
    ]
  },
  {
    id: 'PCI-5',
    name: 'Protect All Systems and Networks from Malicious Software',
    description: 'Malicious software threatens the security of systems and must be actively protected against',
    goal: 'Maintain a Vulnerability Management Program',
    subRequirements: [
      { id: '5.1', name: 'Anti-Malware Policies', description: 'Processes and mechanisms for protecting all systems and networks from malicious software are defined' },
      { id: '5.2', name: 'Anti-Malware Deployment', description: 'Malicious software is prevented, or detected and addressed' },
      { id: '5.3', name: 'Anti-Malware Mechanisms', description: 'Anti-malware mechanisms and processes are active, maintained, and monitored' },
      { id: '5.4', name: 'Phishing Protection', description: 'Anti-phishing mechanisms protect users against phishing attacks' }
    ]
  },
  {
    id: 'PCI-6',
    name: 'Develop and Maintain Secure Systems and Software',
    description: 'Security vulnerabilities in systems and software must be addressed through secure development practices',
    goal: 'Maintain a Vulnerability Management Program',
    subRequirements: [
      { id: '6.1', name: 'Software Development Policies', description: 'Processes and mechanisms for developing and maintaining secure systems and software are defined' },
      { id: '6.2', name: 'Bespoke Software Security', description: 'Bespoke and custom software are developed securely' },
      { id: '6.3', name: 'Security Vulnerabilities', description: 'Security vulnerabilities are identified and addressed' },
      { id: '6.4', name: 'Web Application Security', description: 'Public-facing web applications are protected against attacks' },
      { id: '6.5', name: 'Change Management', description: 'Changes to all system components are managed securely' }
    ]
  },
  {
    id: 'PCI-7',
    name: 'Restrict Access to System Components',
    description: 'Access to systems and data should be limited to only those individuals who need it',
    goal: 'Implement Strong Access Control Measures',
    subRequirements: [
      { id: '7.1', name: 'Access Control Policies', description: 'Processes and mechanisms for restricting access to system components and cardholder data are defined' },
      { id: '7.2', name: 'Access Control Systems', description: 'Access to system components and data is appropriately defined and assigned' },
      { id: '7.3', name: 'Access Control Enforcement', description: 'Access to system components and data is managed via an access control system(s)' }
    ]
  },
  {
    id: 'PCI-8',
    name: 'Identify Users and Authenticate Access',
    description: 'Identification and authentication must be used to verify individuals accessing systems',
    goal: 'Implement Strong Access Control Measures',
    subRequirements: [
      { id: '8.1', name: 'Identity Management Policies', description: 'Processes and mechanisms for identifying users and authenticating access are defined' },
      { id: '8.2', name: 'User Identification', description: 'User identification and related accounts for users and administrators are strictly managed' },
      { id: '8.3', name: 'Strong Authentication', description: 'Strong authentication for users and administrators is established and managed' },
      { id: '8.4', name: 'MFA Implementation', description: 'Multi-factor authentication (MFA) is implemented to secure access to the CDE' },
      { id: '8.5', name: 'MFA Systems', description: 'Multi-factor authentication (MFA) systems are configured to prevent misuse' },
      { id: '8.6', name: 'Application and System Accounts', description: 'Use of application and system accounts and associated authentication factors is strictly managed' }
    ]
  },
  {
    id: 'PCI-9',
    name: 'Restrict Physical Access',
    description: 'Physical access to systems and cardholder data must be controlled',
    goal: 'Implement Strong Access Control Measures',
    subRequirements: [
      { id: '9.1', name: 'Physical Access Policies', description: 'Processes and mechanisms for restricting physical access to cardholder data are defined' },
      { id: '9.2', name: 'Physical Access Controls', description: 'Physical access controls manage entry into facilities and systems containing cardholder data' },
      { id: '9.3', name: 'Physical Access Authorization', description: 'Physical access for personnel and visitors is authorized and managed' },
      { id: '9.4', name: 'Media Management', description: 'Media with cardholder data is securely stored, accessed, distributed, and destroyed' },
      { id: '9.5', name: 'POI Device Security', description: 'POI devices are protected from tampering and unauthorized substitution' }
    ]
  },
  {
    id: 'PCI-10',
    name: 'Log and Monitor All Access',
    description: 'Logging mechanisms and ability to track user activities are critical for security',
    goal: 'Regularly Monitor and Test Networks',
    subRequirements: [
      { id: '10.1', name: 'Logging Policies', description: 'Processes and mechanisms for logging and monitoring all access to system components are defined' },
      { id: '10.2', name: 'Audit Logs', description: 'Audit logs are implemented to support the detection of anomalies and suspicious activity' },
      { id: '10.3', name: 'Audit Log Protection', description: 'Audit logs are protected from destruction and unauthorized modifications' },
      { id: '10.4', name: 'Audit Log Review', description: 'Audit logs are reviewed to identify anomalies or suspicious activity' },
      { id: '10.5', name: 'Audit Log History', description: 'Audit log history is retained and available for analysis' },
      { id: '10.6', name: 'Time Synchronization', description: 'Time-synchronization mechanisms support consistent time settings across all systems' },
      { id: '10.7', name: 'Critical Security Controls', description: 'Failures of critical security control systems are detected, reported, and responded to promptly' }
    ]
  },
  {
    id: 'PCI-11',
    name: 'Test Security of Systems and Networks Regularly',
    description: 'Vulnerabilities are continuously discovered, and security of systems and networks must be tested regularly',
    goal: 'Regularly Monitor and Test Networks',
    subRequirements: [
      { id: '11.1', name: 'Security Testing Policies', description: 'Processes and mechanisms for regularly testing security of systems and networks are defined' },
      { id: '11.2', name: 'Wireless Access Points', description: 'Wireless access points are identified and monitored, and unauthorized wireless access points are addressed' },
      { id: '11.3', name: 'Vulnerability Scanning', description: 'External and internal vulnerabilities are regularly identified, prioritized, and addressed' },
      { id: '11.4', name: 'Penetration Testing', description: 'External and internal penetration testing is regularly performed, and exploitable vulnerabilities are corrected' },
      { id: '11.5', name: 'Network Intrusions', description: 'Network intrusions and unexpected file changes are detected and responded to' },
      { id: '11.6', name: 'Payment Page Security', description: 'Unauthorized changes on payment pages are detected and responded to' }
    ]
  },
  {
    id: 'PCI-12',
    name: 'Support Information Security with Policies and Programs',
    description: 'A strong security policy sets the security tone and informs personnel of expectations',
    goal: 'Maintain an Information Security Policy',
    subRequirements: [
      { id: '12.1', name: 'Information Security Policy', description: 'A comprehensive information security policy that governs and provides direction is established' },
      { id: '12.2', name: 'Acceptable Use Policies', description: 'Acceptable use policies for end-user technologies are implemented' },
      { id: '12.3', name: 'Risk Assessment', description: 'Risks to the CDE are formally identified, evaluated, and managed' },
      { id: '12.4', name: 'PCI DSS Compliance', description: 'PCI DSS compliance is managed' },
      { id: '12.5', name: 'PCI DSS Scope', description: 'PCI DSS scope is documented and validated' },
      { id: '12.6', name: 'Security Awareness', description: 'Security awareness education is an ongoing activity' },
      { id: '12.7', name: 'Personnel Screening', description: 'Personnel are screened to reduce risks from insider threats' },
      { id: '12.8', name: 'TPSP Management', description: 'Risk to information assets associated with TPSP relationships is managed' },
      { id: '12.9', name: 'TPSP Acknowledgment', description: 'TPSPs acknowledge their responsibility to protect account data' },
      { id: '12.10', name: 'Incident Response', description: 'Suspected and confirmed security incidents that could impact the CDE are responded to immediately' }
    ]
  }
];

// =============================================================================
// FRAMEWORK UTILITY FUNCTIONS
// =============================================================================

/**
 * Get all available compliance frameworks
 */
export const getAvailableFrameworks = (): string[] => {
  return [
    'NIST-CSF-2.0',
    'NIST-800-53',
    'NIST-800-171',
    'MITRE-ATTACK',
    'MITRE-DEFEND',
    'CIS-CONTROLS',
    'OWASP-TOP-10',
    'OWASP-ASVS',
    'OWASP-SAMM',
    'NASA-STD-8719',
    'DO-178C',
    'CMMC-2.0',
    'COMMON-CRITERIA',
    'ISO-27001',
    'SOC-2',
    'SLSA',
    'HIPAA',
    'FEDRAMP',
    'PCI-DSS-4.0'
  ];
};

/**
 * Get SOC 2 criteria by category
 */
export const getSOC2CriteriaByCategory = (category: SOC2TrustServiceCriteria['category']): SOC2TrustServiceCriteria[] => {
  return SOC2_TRUST_SERVICE_CRITERIA.filter(c => c.category === category);
};

/**
 * Get HIPAA safeguards by category
 */
export const getHIPAASafeguardsByCategory = (category: HIPAASafeguard['category']): HIPAASafeguard[] => {
  return HIPAA_SAFEGUARDS.filter(s => s.category === category);
};

/**
 * Get HIPAA required vs addressable safeguards
 */
export const getHIPAASafeguardsBySpecification = (specification: 'required' | 'addressable'): HIPAASafeguard[] => {
  return HIPAA_SAFEGUARDS.filter(s => s.specification === specification);
};

/**
 * Get PCI DSS requirements by goal
 */
export const getPCIDSSRequirementsByGoal = (goal: string): PCIDSSRequirement[] => {
  return PCI_DSS_4_REQUIREMENTS.filter(r => r.goal === goal);
};

/**
 * Calculate compliance score for a framework
 */
export const calculateComplianceScore = (
  framework: string,
  compliantControls: number,
  totalControls: number
): { score: number; level: string; color: string } => {
  const score = totalControls > 0 ? Math.round((compliantControls / totalControls) * 100) : 0;

  let level: string;
  let color: string;

  if (score >= 90) {
    level = 'Excellent';
    color = '#22c55e';
  } else if (score >= 70) {
    level = 'Good';
    color = '#84cc16';
  } else if (score >= 50) {
    level = 'Moderate';
    color = '#eab308';
  } else if (score >= 30) {
    level = 'Poor';
    color = '#f97316';
  } else {
    level = 'Critical';
    color = '#ef4444';
  }

  return { score, level, color };
};
