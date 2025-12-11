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
  private currentModel: string = 'llama3.2';
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
}

// Export singleton instance
export const ollamaService = new OllamaService();
export default ollamaService;
