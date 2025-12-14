/**
 * Ollama Service - Local LLM Integration
 * Connects to Ollama running on localhost:11434
 *
 * Powers J.O.E. (Joint Operations Engine) AI capabilities
 * Architected by Michael Hoch, Chief Architect of Autonomous Cyber-Operations
 */

import { JOE_SYSTEM_PROMPT } from '../core/joe-specification';

export interface OllamaMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface OllamaResponse {
  model: string;
  created_at: string;
  message: OllamaMessage;
  done: boolean;
}

export interface OllamaModel {
  name: string;
  modified_at: string;
  size: number;
}

const OLLAMA_BASE_URL = 'http://localhost:11434';

class OllamaService {
  private currentModel: string = 'mistral';
  private abortController: AbortController | null = null;

  /**
   * Check if Ollama is running and accessible
   */
  async isConnected(): Promise<boolean> {
    try {
      const response = await fetch(`${OLLAMA_BASE_URL}/api/tags`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000)
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Get list of available models
   */
  async getModels(): Promise<string[]> {
    try {
      const response = await fetch(`${OLLAMA_BASE_URL}/api/tags`);
      if (!response.ok) throw new Error('Failed to fetch models');

      const data = await response.json();
      return data.models?.map((m: OllamaModel) => m.name) || [];
    } catch (error) {
      console.error('Failed to get Ollama models:', error);
      return [];
    }
  }

  /**
   * Set the current model to use
   */
  setModel(model: string): void {
    this.currentModel = model;
  }

  /**
   * Get current model
   */
  getModel(): string {
    return this.currentModel;
  }

  /**
   * Send a chat message and get a response (non-streaming)
   */
  async chat(
    message: string,
    context?: string,
    systemPrompt?: string
  ): Promise<string> {
    const messages: OllamaMessage[] = [];

    // Add J.O.E. system prompt for security context
    const joeSystemPrompt = systemPrompt || JOE_SYSTEM_PROMPT;
    messages.push({ role: 'system', content: joeSystemPrompt });

    // Add context if provided (e.g., current findings, SBOM data)
    if (context) {
      messages.push({
        role: 'system',
        content: `Current security context:\n${context}`
      });
    }

    // Add user message
    messages.push({ role: 'user', content: message });

    try {
      const response = await fetch(`${OLLAMA_BASE_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.currentModel,
          messages,
          stream: false
        })
      });

      if (!response.ok) {
        throw new Error(`Ollama request failed: ${response.statusText}`);
      }

      const data: OllamaResponse = await response.json();
      return data.message?.content || 'No response generated';
    } catch (error) {
      console.error('Ollama chat error:', error);
      throw error;
    }
  }

  /**
   * Send a chat message with streaming response
   */
  async *streamChat(
    message: string,
    context?: string,
    systemPrompt?: string
  ): AsyncGenerator<string, void, unknown> {
    // Cancel any existing stream
    this.cancelStream();
    this.abortController = new AbortController();

    const messages: OllamaMessage[] = [];

    // Use comprehensive J.O.E. system prompt with markdown formatting instruction
    const joePromptWithFormat = (systemPrompt || JOE_SYSTEM_PROMPT) +
      '\n\nFormat responses with markdown for readability. Use **bold** for important terms, `code` for technical items.';
    messages.push({ role: 'system', content: joePromptWithFormat });

    if (context) {
      messages.push({
        role: 'system',
        content: `Current security context:\n${context}`
      });
    }

    messages.push({ role: 'user', content: message });

    try {
      const response = await fetch(`${OLLAMA_BASE_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.currentModel,
          messages,
          stream: true
        }),
        signal: this.abortController.signal
      });

      if (!response.ok) {
        throw new Error(`Ollama request failed: ${response.statusText}`);
      }

      const reader = response.body?.getReader();
      if (!reader) throw new Error('No response body');

      const decoder = new TextDecoder();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n').filter(line => line.trim());

        for (const line of lines) {
          try {
            const data = JSON.parse(line);
            if (data.message?.content) {
              yield data.message.content;
            }
          } catch {
            // Ignore parse errors for incomplete JSON
          }
        }
      }
    } catch (error) {
      if ((error as Error).name === 'AbortError') {
        console.log('Stream cancelled');
        return;
      }
      throw error;
    } finally {
      this.abortController = null;
    }
  }

  /**
   * Cancel ongoing stream
   */
  cancelStream(): void {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  }

  /**
   * Generate security analysis for findings
   */
  async analyzeFindings(findings: Array<{
    title: string;
    severity: string;
    description: string;
    file?: string;
  }>): Promise<string> {
    const findingsContext = findings.map((f, i) =>
      `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}\n   File: ${f.file || 'N/A'}\n   ${f.description}`
    ).join('\n\n');

    return this.chat(
      'Analyze these security findings and provide prioritized remediation recommendations:',
      findingsContext
    );
  }

  /**
   * Generate compliance recommendations
   */
  async analyzeCompliance(
    framework: string,
    controls: Array<{ id: string; title: string; status: string }>
  ): Promise<string> {
    const controlsContext = controls.map(c =>
      `- ${c.id}: ${c.title} [${c.status}]`
    ).join('\n');

    return this.chat(
      `For ${framework} compliance, analyze these controls and suggest improvements for non-compliant items:`,
      controlsContext
    );
  }

  /**
   * Explain a CVE/vulnerability
   */
  async explainVulnerability(cveId: string, description?: string): Promise<string> {
    return this.chat(
      `Explain ${cveId}${description ? `: ${description}` : ''}.
      Include: severity, attack vector, affected systems, and remediation steps.`
    );
  }

  /**
   * Suggest code fix for vulnerability
   */
  async suggestCodeFix(
    vulnerability: string,
    codeSnippet: string,
    language: string
  ): Promise<string> {
    return this.chat(
      `Suggest a fix for this ${vulnerability} vulnerability in ${language}:`,
      `\`\`\`${language}\n${codeSnippet}\n\`\`\``
    );
  }

  // ========================================
  // KUBERNETES SECURITY AI ANALYSIS
  // Reference: CIS Benchmark v1.8, NSA/CISA Guide, NIST SP 800-190
  // ========================================

  /**
   * Deep dive analysis of Kubernetes security findings
   * Maps to MITRE ATT&CK for Containers
   */
  async analyzeK8sFinding(finding: {
    id: string;
    type: string;
    title: string;
    severity: string;
    description: string;
    remediation?: string;
  }): Promise<string> {
    const k8sSecurityPrompt = `You are J.O.E., an expert Kubernetes security analyst with deep knowledge of:
- CIS Kubernetes Benchmark v1.8 (Center for Internet Security)
- NSA/CISA Kubernetes Hardening Guide v1.2 (2022)
- NIST SP 800-190 (Container Security Guide)
- MITRE ATT&CK for Containers
- Pod Security Standards (PSS)

Analyze security findings and provide actionable intelligence.`;

    return this.chat(
      `Analyze this Kubernetes security finding and provide:
1. **Risk Assessment**: Severity justification and potential impact
2. **Attack Vector**: How this could be exploited (map to MITRE ATT&CK)
3. **Blast Radius**: What resources/data could be compromised
4. **Remediation Steps**: Specific kubectl commands or YAML changes
5. **Prevention**: How to prevent this in CI/CD pipelines
6. **Compliance**: Which standards this violates (CIS, NSA/CISA, NIST)

Finding: [${finding.severity.toUpperCase()}] ${finding.title}
Type: ${finding.type}
Description: ${finding.description}
Current Remediation Guidance: ${finding.remediation || 'None provided'}`,
      undefined,
      k8sSecurityPrompt
    );
  }

  /**
   * Analyze RBAC configuration for attack paths
   * Reference: NSA/CISA Guide Section 4 - Authentication and Authorization
   */
  async analyzeRBAC(rbacData: {
    overprivileged: Array<{ subject: string; permissions: string[]; risk: string }>;
    clusterAdminCount: number;
    wildcardPermissions: number;
  }): Promise<string> {
    const context = `
RBAC Analysis Data:
- Cluster-admin bindings: ${rbacData.clusterAdminCount}
- Wildcard permission roles: ${rbacData.wildcardPermissions}
- Overprivileged accounts: ${rbacData.overprivileged.length}

Overprivileged Details:
${rbacData.overprivileged.map(a => `  - ${a.subject}: ${a.permissions.join(', ')} [${a.risk}]`).join('\n')}`;

    return this.chat(
      `Perform an RBAC security analysis based on NSA/CISA Kubernetes Hardening Guide Section 4.

Provide:
1. **Risk Summary**: Overall RBAC security posture
2. **Attack Paths**: How overprivileged accounts could be exploited
3. **Privilege Escalation Risks**: Potential paths from low to high privilege
4. **Lateral Movement**: How compromised accounts could pivot
5. **Remediation Priority**: Which accounts to fix first and why
6. **Least Privilege Recommendations**: Specific role changes needed
7. **Audit Commands**: kubectl commands to monitor RBAC usage`,
      context
    );
  }

  /**
   * Analyze Pod Security Standards violations
   * Reference: Kubernetes PSS (Privileged, Baseline, Restricted)
   */
  async analyzePodSecurity(violations: Array<{
    namespace: string;
    pod: string;
    violations: string[];
    severity: string;
  }>): Promise<string> {
    const context = violations.map(v =>
      `Pod: ${v.namespace}/${v.pod} [${v.severity}]\n  Violations: ${v.violations.join(', ')}`
    ).join('\n\n');

    return this.chat(
      `Analyze these Pod Security Standards violations against NIST SP 800-190 container security guidelines.

Provide for each critical/high violation:
1. **Security Impact**: Why this is dangerous
2. **Container Escape Risk**: Could this lead to node compromise?
3. **YAML Fix**: Exact securityContext changes needed
4. **Admission Controller**: OPA/Gatekeeper or Kyverno policy to prevent
5. **Hardening Checklist**: Additional security measures`,
      context
    );
  }

  /**
   * Analyze container image vulnerabilities
   * Reference: NIST SP 800-190 Section 4.3 - Image Vulnerabilities
   */
  async analyzeContainerVulnerabilities(images: Array<{
    image: string;
    critical: number;
    high: number;
    findings?: Array<{ id: string; severity: string; title: string; fixedVersion?: string }>;
  }>): Promise<string> {
    const context = images.map(img =>
      `Image: ${img.image}
  Critical: ${img.critical}, High: ${img.high}
  Top Findings: ${img.findings?.slice(0, 3).map(f => `${f.id} - ${f.title}`).join('; ') || 'N/A'}`
    ).join('\n\n');

    return this.chat(
      `Analyze these container image vulnerabilities per NIST SP 800-190.

Provide:
1. **Priority Ranking**: Which images to update first based on risk
2. **Exploit Availability**: Are these vulnerabilities actively exploited?
3. **Base Image Recommendations**: Suggest more secure base images
4. **Patching Strategy**: Steps to update images in production
5. **Registry Security**: Recommendations for image signing and scanning
6. **Runtime Protection**: Falco rules or AppArmor profiles to mitigate`,
      context
    );
  }

  /**
   * Analyze Network Policy gaps
   * Reference: NSA/CISA Guide Section 5 - Network Separation
   */
  async analyzeNetworkPolicies(data: {
    coverage: number;
    unprotectedNamespaces: string[];
    defaultDenyCount: number;
  }): Promise<string> {
    const context = `
Network Policy Coverage: ${data.coverage}%
Default Deny Policies: ${data.defaultDenyCount}
Unprotected Namespaces: ${data.unprotectedNamespaces.join(', ') || 'None'}`;

    return this.chat(
      `Analyze this Kubernetes network segmentation against NSA/CISA Section 5 guidelines.

Provide:
1. **Segmentation Score**: Rate the current network isolation
2. **Lateral Movement Risk**: How easily could an attacker move between pods?
3. **Recommended Policies**: NetworkPolicy YAML for each unprotected namespace
4. **Microsegmentation Strategy**: How to implement zero-trust networking
5. **Egress Control**: Recommendations for outbound traffic restrictions
6. **Service Mesh**: When to consider Istio/Linkerd for mTLS`,
      context
    );
  }

  /**
   * Generate attack path analysis combining multiple findings
   * Reference: MITRE ATT&CK for Containers
   */
  async analyzeAttackPaths(findings: {
    cis: Array<{ id: string; title: string; severity: string }>;
    rbac: Array<{ subject: string; risk: string }>;
    pss: Array<{ pod: string; violations: string[] }>;
    network: { coverage: number };
  }): Promise<string> {
    const context = `
CIS Failures: ${findings.cis.filter(f => f.severity === 'critical' || f.severity === 'high').length}
RBAC Issues: ${findings.rbac.length} overprivileged accounts
PSS Violations: ${findings.pss.length} non-compliant pods
Network Coverage: ${findings.network.coverage}%`;

    return this.chat(
      `Map potential attack paths through this Kubernetes cluster using MITRE ATT&CK for Containers framework.

For each attack path, provide:
1. **Initial Access**: How attacker gets in (TA0001)
2. **Execution**: Running malicious code (TA0002)
3. **Persistence**: Maintaining access (TA0003)
4. **Privilege Escalation**: Getting higher privileges (TA0004)
5. **Defense Evasion**: Avoiding detection (TA0005)
6. **Credential Access**: Stealing secrets (TA0006)
7. **Lateral Movement**: Moving to other pods/nodes (TA0008)
8. **Impact**: Final objective (TA0040)

Then provide a prioritized remediation roadmap to close these attack paths.`,
      context
    );
  }

  /**
   * Generate overall cluster security assessment
   */
  async generateClusterSecurityReport(scanResults: {
    complianceScore: number;
    cisPassRate: number;
    criticalFindings: number;
    highFindings: number;
    privilegedPods: number;
    networkCoverage: number;
  }): Promise<string> {
    const context = `
Cluster Security Metrics:
- Overall Compliance Score: ${scanResults.complianceScore}%
- CIS Benchmark Pass Rate: ${scanResults.cisPassRate}%
- Critical Findings: ${scanResults.criticalFindings}
- High Findings: ${scanResults.highFindings}
- Privileged Pods: ${scanResults.privilegedPods}
- Network Policy Coverage: ${scanResults.networkCoverage}%`;

    return this.chat(
      `Generate an executive security assessment for this Kubernetes cluster.

Include:
1. **Security Posture Rating**: Grade (A-F) with justification
2. **DoD Readiness**: Is this cluster ready for DoD workloads? What's missing?
3. **Top 5 Risks**: Most critical issues to address immediately
4. **Compliance Gaps**: Specific CIS/NIST/NSA controls not met
5. **30-Day Remediation Plan**: Prioritized action items
6. **Continuous Monitoring**: What to track going forward
7. **Tool Recommendations**: Additional security tools to deploy`,
      context
    );
  }

  // =============================================================================
  // AI TOUCHPOINT SYSTEM
  // Space-Grade Security Intelligence with Framework Citations
  // NASA-STD-8719 | DO-178C | NIST CSF 2.0 | MITRE ATT&CK
  // =============================================================================

  /**
   * Generate AI touchpoint response with framework citations
   * Used by AITouchpointProvider for hover/click interactions
   */
  async generateTouchpointResponse(
    elementType: string,
    data: Record<string, unknown>,
    frameworks: string[],
    depth: 'tooltip' | 'panel' | 'deepdive'
  ): Promise<{
    summary: string;
    detailedAnalysis: string;
    citations: Array<{ framework: string; controlId: string; title: string; relevance: string }>;
    remediationSteps: Array<{ order: number; title: string; description: string; difficulty: string; estimatedTime: string }>;
    confidence: number;
  }> {
    const depthPrompts = {
      tooltip: 'Provide a concise 2-3 sentence security analysis with 2-3 key framework citations.',
      panel: 'Provide detailed analysis (200-300 words) with 5+ framework citations and key remediation points.',
      deepdive: 'Provide comprehensive analysis including attack paths, full remediation steps with code examples, and all relevant framework mappings.'
    };

    const touchpointPrompt = `You are J.O.E. (Joint-Ops-Engine), a Space-Grade Security Intelligence AI.

ANALYSIS CONTEXT:
- Element Type: ${elementType}
- Data: ${JSON.stringify(data, null, 2)}
- Required Frameworks: ${frameworks.join(', ')}
- Analysis Depth: ${depth}

INSTRUCTIONS: ${depthPrompts[depth]}

CITATION FORMAT REQUIREMENTS:
For each finding, cite specific framework controls using EXACT IDs:
- NIST 800-53: "AC-2", "SA-11", "SC-7"
- MITRE ATT&CK: "T1190", "T1059.001", "T1078"
- CIS Controls v8: "5.1", "16.3", "7.2"
- OWASP Top 10: "A01:2021", "A03:2021"
- NASA-STD-8719: "CAT-I", "CAT-II", "CAT-III"
- DO-178C: "DAL-A", "DAL-B", "DAL-C"
- CMMC 2.0: "AC.L1-3.1.1", "IA.L2-3.5.3"

RESPONSE FORMAT (JSON):
{
  "summary": "Brief overview",
  "detailedAnalysis": "Full analysis with markdown formatting",
  "citations": [
    {"framework": "NIST-800-53", "controlId": "AC-2", "title": "Account Management", "relevance": "direct"}
  ],
  "remediationSteps": [
    {"order": 1, "title": "Step title", "description": "Detailed step", "difficulty": "easy|moderate|complex", "estimatedTime": "5 minutes"}
  ],
  "attackPath": "Optional Mermaid diagram syntax for deepdive",
  "confidence": 85
}

Respond ONLY with valid JSON.`;

    try {
      const response = await this.chat(touchpointPrompt);

      // Parse JSON response
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          summary: parsed.summary ?? response.slice(0, 200),
          detailedAnalysis: parsed.detailedAnalysis ?? response,
          citations: parsed.citations ?? [],
          remediationSteps: parsed.remediationSteps ?? [],
          confidence: parsed.confidence ?? 75
        };
      }

      // Fallback: extract citations from text
      return this.parseUnstructuredResponse(response, frameworks);
    } catch (error) {
      console.error('Touchpoint response error:', error);
      throw error;
    }
  }

  /**
   * Stream touchpoint response for real-time UI updates
   */
  async *streamTouchpointResponse(
    elementType: string,
    data: Record<string, unknown>,
    frameworks: string[],
    depth: 'tooltip' | 'panel' | 'deepdive'
  ): AsyncGenerator<{ type: string; content: string }, void, unknown> {
    const prompt = `Analyze this ${elementType} for security implications.
Data: ${JSON.stringify(data)}
Frameworks: ${frameworks.join(', ')}
Provide: summary, analysis, ${frameworks.join('/')} citations, remediation steps.
Use markdown formatting.`;

    yield { type: 'start', content: '' };

    let fullResponse = '';
    for await (const chunk of this.streamChat(prompt)) {
      fullResponse += chunk;
      yield { type: 'chunk', content: chunk };
    }

    yield { type: 'complete', content: fullResponse };
  }

  /**
   * Parse unstructured AI response into citation format
   */
  private parseUnstructuredResponse(
    response: string,
    frameworks: string[]
  ): {
    summary: string;
    detailedAnalysis: string;
    citations: Array<{ framework: string; controlId: string; title: string; relevance: string }>;
    remediationSteps: Array<{ order: number; title: string; description: string; difficulty: string; estimatedTime: string }>;
    confidence: number;
  } {
    // Extract citations using regex patterns
    const citationPatterns = [
      { regex: /NIST\s*800-53\s*([A-Z]{2}-\d+(?:\.\d+)?)/gi, framework: 'NIST-800-53' },
      { regex: /(?:MITRE\s*ATT&CK\s*)?T(\d{4}(?:\.\d{3})?)/gi, framework: 'MITRE-ATTACK', prefix: 'T' },
      { regex: /CIS\s*(?:Control\s*)?(\d+\.\d+)/gi, framework: 'CIS-CONTROLS' },
      { regex: /OWASP\s*(A\d{2}:\d{4})/gi, framework: 'OWASP-TOP-10' },
      { regex: /NASA[- ]STD[- ]8719\s*(CAT-[IV]+)/gi, framework: 'NASA-STD-8719' },
      { regex: /DO-178C\s*(DAL-[A-E])/gi, framework: 'DO-178C' },
      { regex: /CMMC\s*(\w+\.\w+-[\d.]+)/gi, framework: 'CMMC-2.0' }
    ];

    const citations: Array<{ framework: string; controlId: string; title: string; relevance: string }> = [];

    for (const { regex, framework, prefix } of citationPatterns) {
      let match;
      while ((match = regex.exec(response)) !== null) {
        const controlId = prefix ? `${prefix}${match[1]}` : match[1];
        if (!citations.find(c => c.controlId === controlId)) {
          citations.push({
            framework,
            controlId,
            title: `${framework} ${controlId}`,
            relevance: 'direct'
          });
        }
      }
    }

    // Extract summary (first paragraph or sentence)
    const summaryMatch = response.match(/^[^.!?]*[.!?]/);
    const summary = summaryMatch ? summaryMatch[0].trim() : response.slice(0, 200);

    return {
      summary,
      detailedAnalysis: response,
      citations: citations.slice(0, 10),
      remediationSteps: [],
      confidence: citations.length > 3 ? 80 : 60
    };
  }

  /**
   * Analyze security metric for dashboard touchpoints
   */
  async analyzeMetric(
    metricName: string,
    value: number,
    trend: 'up' | 'down' | 'stable',
    context?: Record<string, unknown>
  ): Promise<string> {
    const prompt = `Analyze this security metric for a DevSecOps dashboard:

Metric: ${metricName}
Value: ${value}
Trend: ${trend}
${context ? `Context: ${JSON.stringify(context)}` : ''}

Provide:
1. What this metric indicates about security posture
2. Whether the current value/trend is concerning
3. Relevant NIST 800-53 or CIS Controls citations
4. Recommended actions if the metric is suboptimal

Keep response under 150 words for tooltip display.`;

    return this.chat(prompt);
  }

  /**
   * Generate attack path diagram for vulnerabilities
   */
  async generateAttackPath(
    vulnerability: { id: string; title: string; severity: string; description: string }
  ): Promise<string> {
    const prompt = `Generate a MITRE ATT&CK attack path for this vulnerability:

${vulnerability.id}: ${vulnerability.title}
Severity: ${vulnerability.severity}
Description: ${vulnerability.description}

Provide a Mermaid flowchart diagram showing:
1. Initial Access technique
2. Execution method
3. Potential privilege escalation
4. Lateral movement possibilities
5. Impact/objective

Format as Mermaid flowchart syntax starting with "flowchart TD"`;

    return this.chat(prompt);
  }
}

// Export singleton instance
export const ollamaService = new OllamaService();
export default ollamaService;
