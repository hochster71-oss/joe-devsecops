import { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Bot,
  Send,
  User,
  Loader2,
  Sparkles,
  AlertTriangle,
  Shield,
  Code,
  RefreshCw
} from 'lucide-react';
import { ollamaService } from '../../services/ollamaService';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

const suggestedQueries = [
  { icon: AlertTriangle, text: 'What are the most critical vulnerabilities?' },
  { icon: Shield, text: 'How can I improve my CMMC compliance score?' },
  { icon: Code, text: 'Show me remediation steps for SQL injection' },
  { icon: Sparkles, text: 'Summarize the latest security scan results' }
];

export default function AiAssistantView() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      role: 'assistant',
      content: 'Hello! I\'m your AI security assistant powered by Ollama. I can help you understand your security findings, suggest remediations, and answer questions about compliance. What would you like to know?',
      timestamp: new Date()
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [ollamaStatus, setOllamaStatus] = useState<'connected' | 'disconnected' | 'checking'>('checking');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    checkOllamaStatus();
  }, []);

  const checkOllamaStatus = async () => {
    try {
      const connected = await ollamaService.isConnected();
      setOllamaStatus(connected ? 'connected' : 'disconnected');
    } catch {
      setOllamaStatus('disconnected');
    }
  };

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    const userQuery = input.trim();
    setInput('');
    setIsLoading(true);

    try {
      // Use real Ollama if connected, fallback to mock if not
      let response: string;

      if (ollamaStatus === 'connected') {
        // Stream response from Ollama
        response = '';
        const assistantMessageId = (Date.now() + 1).toString();

        // Add empty assistant message that we'll update
        setMessages(prev => [...prev, {
          id: assistantMessageId,
          role: 'assistant',
          content: '',
          timestamp: new Date()
        }]);

        // Stream the response
        for await (const chunk of ollamaService.streamChat(userQuery)) {
          response += chunk;
          setMessages(prev => prev.map(m =>
            m.id === assistantMessageId
              ? { ...m, content: response }
              : m
          ));
        }
      } else {
        // Fallback mock response when Ollama not available
        response = generateMockResponse(userQuery);
        const aiResponse: Message = {
          id: (Date.now() + 1).toString(),
          role: 'assistant',
          content: response,
          timestamp: new Date()
        };
        setMessages(prev => [...prev, aiResponse]);
      }
    } catch (error) {
      console.error('AI chat error:', error);
      const errorResponse: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: `⚠️ Error connecting to Ollama. Make sure Ollama is running on localhost:11434.\n\nTo start Ollama:\n\`\`\`bash\nollama serve\n\`\`\`\n\nThen pull a model:\n\`\`\`bash\nollama pull llama3.2\n\`\`\``,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, errorResponse]);
    } finally {
      setIsLoading(false);
    }
  };

  const generateMockResponse = (query: string): string => {
    if (query.toLowerCase().includes('critical') || query.toLowerCase().includes('vulnerability')) {
      return `Based on your latest scan, I found **3 critical vulnerabilities**:\n\n1. **SQL Injection** in \`src/api/users.ts:42\`\n   - Risk: Data breach, unauthorized access\n   - Fix: Use parameterized queries\n\n2. **Hardcoded API Key** in \`src/config/api.ts:8\`\n   - Risk: Credential exposure\n   - Fix: Use environment variables\n\n3. **Outdated lodash** (CVE-2021-23337)\n   - Risk: Prototype pollution\n   - Fix: Upgrade to 4.17.21+\n\nWould you like detailed remediation steps for any of these?`;
    }
    if (query.toLowerCase().includes('cmmc') || query.toLowerCase().includes('compliance')) {
      return `Your current **CMMC 2.0 compliance score is 68%** (Level 1).\n\n**To improve:**\n- ✅ 9 controls are compliant\n- ⚠️ 4 controls are partially compliant\n- ❌ 2 controls are non-compliant\n\n**Priority actions:**\n1. Implement timely flaw remediation (SI.L1-3.14.1)\n2. Strengthen authentication mechanisms (IA.L1-3.5.2)\n3. Enhance boundary protection (SC.L1-3.13.1)\n\nShall I generate a detailed remediation plan?`;
    }
    return `I understand you're asking about "${query}". Let me analyze your security data...\n\nBased on the current state of your codebase and security scans, I can provide insights on vulnerabilities, compliance status, and remediation steps.\n\nCould you be more specific about what aspect you'd like me to focus on?\n\n*Note: Ollama is not connected. Start Ollama for real AI responses.*`;
  };

  const handleSuggestion = (text: string) => {
    setInput(text);
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="font-heading text-2xl font-bold text-white flex items-center gap-2">
            <Bot className="text-joe-blue" />
            AI Security Assistant
          </h1>
          <p className="text-gray-400 mt-1">Powered by Ollama - Local LLM</p>
        </div>
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm ${
          ollamaStatus === 'connected'
            ? 'bg-dws-green/10 text-dws-green border border-dws-green/30'
            : ollamaStatus === 'disconnected'
            ? 'bg-alert-critical/10 text-alert-critical border border-alert-critical/30'
            : 'bg-gray-500/10 text-gray-400 border border-gray-500/30'
        }`}>
          <div className={`w-2 h-2 rounded-full ${
            ollamaStatus === 'connected' ? 'bg-dws-green' :
            ollamaStatus === 'disconnected' ? 'bg-alert-critical' : 'bg-gray-500'
          }`} />
          {ollamaStatus === 'connected' ? 'Connected' :
           ollamaStatus === 'disconnected' ? 'Disconnected' : 'Checking...'}
        </div>
      </div>

      {/* Chat Area */}
      <div className="flex-1 glass-card flex flex-col overflow-hidden">
        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((message) => (
            <motion.div
              key={message.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className={`flex gap-3 ${message.role === 'user' ? 'justify-end' : ''}`}
            >
              {message.role === 'assistant' && (
                <div className="w-8 h-8 rounded-full bg-joe-blue/20 flex items-center justify-center flex-shrink-0">
                  <Bot size={18} className="text-joe-blue" />
                </div>
              )}
              <div className={`max-w-[70%] rounded-lg p-4 ${
                message.role === 'user'
                  ? 'bg-joe-blue text-white'
                  : 'bg-dws-card text-gray-200'
              }`}>
                <div className="prose prose-invert prose-sm max-w-none whitespace-pre-wrap">
                  {message.content}
                </div>
                <p className={`text-xs mt-2 ${message.role === 'user' ? 'text-joe-blue-light' : 'text-gray-500'}`}>
                  {message.timestamp.toLocaleTimeString()}
                </p>
              </div>
              {message.role === 'user' && (
                <div className="w-8 h-8 rounded-full bg-dws-green/20 flex items-center justify-center flex-shrink-0">
                  <User size={18} className="text-dws-green" />
                </div>
              )}
            </motion.div>
          ))}

          {isLoading && (
            <div className="flex gap-3">
              <div className="w-8 h-8 rounded-full bg-joe-blue/20 flex items-center justify-center">
                <Bot size={18} className="text-joe-blue" />
              </div>
              <div className="bg-dws-card rounded-lg p-4">
                <Loader2 className="animate-spin text-joe-blue" size={20} />
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Suggestions */}
        {messages.length <= 1 && (
          <div className="p-4 border-t border-dws-border">
            <p className="text-gray-500 text-sm mb-3">Suggested questions:</p>
            <div className="grid grid-cols-2 gap-2">
              {suggestedQueries.map((query, index) => (
                <button
                  key={index}
                  onClick={() => handleSuggestion(query.text)}
                  className="flex items-center gap-2 p-3 rounded-lg bg-dws-dark border border-dws-border hover:border-joe-blue/50 transition-colors text-left"
                >
                  <query.icon size={16} className="text-joe-blue flex-shrink-0" />
                  <span className="text-gray-300 text-sm">{query.text}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input */}
        <div className="p-4 border-t border-dws-border">
          <div className="flex gap-3">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Ask about security findings, compliance, remediation..."
              className="input-field flex-1"
              disabled={isLoading}
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || isLoading}
              className="btn-primary px-4 disabled:opacity-50"
            >
              <Send size={18} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
