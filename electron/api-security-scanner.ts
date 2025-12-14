/**
 * J.O.E. DevSecOps Arsenal - API Security Scanner
 * OpenAPI/Swagger analysis and OWASP API Top 10 checks
 *
 * @module electron/api-security-scanner
 * @version 1.0.0
 */

import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';

// =============================================================================
// TYPES & INTERFACES
// =============================================================================

export interface APISecurityFinding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: OWASPAPICategory;
  endpoint?: string;
  method?: string;
  parameter?: string;
  location: string;
  remediation: string;
  owaspApiReference: string;
}

export type OWASPAPICategory =
  | 'API1:2023' // Broken Object Level Authorization
  | 'API2:2023' // Broken Authentication
  | 'API3:2023' // Broken Object Property Level Authorization
  | 'API4:2023' // Unrestricted Resource Consumption
  | 'API5:2023' // Broken Function Level Authorization
  | 'API6:2023' // Unrestricted Access to Sensitive Business Flows
  | 'API7:2023' // Server Side Request Forgery
  | 'API8:2023' // Security Misconfiguration
  | 'API9:2023' // Improper Inventory Management
  | 'API10:2023'; // Unsafe Consumption of APIs

export interface APIEndpoint {
  path: string;
  method: string;
  operationId?: string;
  summary?: string;
  security?: unknown[];
  parameters?: APIParameter[];
  requestBody?: unknown;
  responses?: Record<string, unknown>;
}

export interface APIParameter {
  name: string;
  in: 'query' | 'header' | 'path' | 'cookie';
  required?: boolean;
  schema?: {
    type?: string;
    format?: string;
    pattern?: string;
    minimum?: number;
    maximum?: number;
    maxLength?: number;
    minLength?: number;
    enum?: unknown[];
  };
  description?: string;
}

export interface OpenAPISpec {
  openapi?: string;
  swagger?: string;
  info?: {
    title?: string;
    version?: string;
    description?: string;
  };
  servers?: Array<{
    url: string;
    description?: string;
  }>;
  paths?: Record<string, Record<string, unknown>>;
  components?: {
    securitySchemes?: Record<string, unknown>;
    schemas?: Record<string, unknown>;
  };
  security?: unknown[];
}

export interface APIScanResult {
  specFile: string;
  apiName: string;
  apiVersion: string;
  openApiVersion: string;
  scanTime: string;
  endpointsAnalyzed: number;
  findings: APISecurityFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  securitySchemes: string[];
  coverage: {
    authenticated: number;
    unauthenticated: number;
    total: number;
  };
}

// =============================================================================
// OWASP API TOP 10 2023 CHECKS
// =============================================================================

const OWASP_API_CHECKS: Array<{
  id: OWASPAPICategory;
  name: string;
  description: string;
  check: (spec: OpenAPISpec, endpoints: APIEndpoint[]) => APISecurityFinding[];
}> = [
  {
    id: 'API1:2023',
    name: 'Broken Object Level Authorization',
    description: 'APIs exposing object IDs without proper authorization checks',
    check: (spec, endpoints) => {
      const findings: APISecurityFinding[] = [];

      for (const endpoint of endpoints) {
        // Check for ID parameters without security
        const idParams = endpoint.parameters?.filter(p =>
          p.name.toLowerCase().includes('id') ||
          p.name.toLowerCase().includes('uuid') ||
          p.name.toLowerCase().includes('key')
        );

        if (idParams && idParams.length > 0 && (!endpoint.security || endpoint.security.length === 0)) {
          const globalSecurity = spec.security && spec.security.length > 0;
          if (!globalSecurity) {
            findings.push({
              id: `API1-${endpoint.method}-${endpoint.path}`,
              title: 'Potential BOLA Vulnerability',
              description: `Endpoint ${endpoint.method.toUpperCase()} ${endpoint.path} accepts object IDs (${idParams.map(p => p.name).join(', ')}) but has no defined security`,
              severity: 'high',
              category: 'API1:2023',
              endpoint: endpoint.path,
              method: endpoint.method,
              parameter: idParams[0].name,
              location: `paths.${endpoint.path}.${endpoint.method}`,
              remediation: 'Implement object-level authorization checks. Verify the user has permission to access the specific resource.',
              owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'
            });
          }
        }
      }
      return findings;
    }
  },
  {
    id: 'API2:2023',
    name: 'Broken Authentication',
    description: 'Weak or missing authentication mechanisms',
    check: (spec, endpoints) => {
      const findings: APISecurityFinding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};

      // Check if any auth is defined
      if (Object.keys(securitySchemes).length === 0) {
        findings.push({
          id: 'API2-no-auth',
          title: 'No Authentication Defined',
          description: 'The API specification does not define any security schemes',
          severity: 'critical',
          category: 'API2:2023',
          location: 'components.securitySchemes',
          remediation: 'Define appropriate security schemes (OAuth2, API Key, Bearer token, etc.) in the spec',
          owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'
        });
      }

      // Check for weak auth schemes
      for (const [name, scheme] of Object.entries(securitySchemes) as [string, Record<string, unknown>][]) {
        if (scheme.type === 'http' && scheme.scheme === 'basic') {
          findings.push({
            id: `API2-basic-auth-${name}`,
            title: 'Basic Authentication Used',
            description: `Security scheme "${name}" uses basic authentication which is vulnerable to credential theft`,
            severity: 'medium',
            category: 'API2:2023',
            location: `components.securitySchemes.${name}`,
            remediation: 'Use more secure authentication methods like OAuth 2.0 or JWT Bearer tokens',
            owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'
          });
        }

        if (scheme.type === 'apiKey' && scheme.in === 'query') {
          findings.push({
            id: `API2-apikey-query-${name}`,
            title: 'API Key in Query Parameter',
            description: `Security scheme "${name}" passes API key in query string which can be logged`,
            severity: 'medium',
            category: 'API2:2023',
            location: `components.securitySchemes.${name}`,
            remediation: 'Pass API keys in headers instead of query parameters',
            owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'
          });
        }
      }

      // Check for endpoints without auth
      const sensitivePatterns = ['/admin', '/user', '/account', '/profile', '/settings', '/delete', '/update'];
      for (const endpoint of endpoints) {
        const isSensitive = sensitivePatterns.some(p => endpoint.path.toLowerCase().includes(p));
        const hasSecurity = endpoint.security && endpoint.security.length > 0;
        const hasGlobalSecurity = spec.security && spec.security.length > 0;

        if (isSensitive && !hasSecurity && !hasGlobalSecurity) {
          findings.push({
            id: `API2-unauth-${endpoint.method}-${endpoint.path}`,
            title: 'Sensitive Endpoint Without Authentication',
            description: `Sensitive endpoint ${endpoint.method.toUpperCase()} ${endpoint.path} has no authentication requirement`,
            severity: 'high',
            category: 'API2:2023',
            endpoint: endpoint.path,
            method: endpoint.method,
            location: `paths.${endpoint.path}.${endpoint.method}`,
            remediation: 'Add security requirements to sensitive endpoints',
            owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'
          });
        }
      }

      return findings;
    }
  },
  {
    id: 'API3:2023',
    name: 'Broken Object Property Level Authorization',
    description: 'Excessive data exposure through API responses',
    check: (spec, endpoints) => {
      const findings: APISecurityFinding[] = [];
      const schemas = spec.components?.schemas || {};

      // Check for sensitive properties in schemas
      const sensitiveFields = ['password', 'secret', 'token', 'apikey', 'api_key', 'ssn', 'credit_card', 'cvv'];

      for (const [schemaName, schema] of Object.entries(schemas) as [string, Record<string, unknown>][]) {
        const properties = (schema.properties || {}) as Record<string, unknown>;

        for (const [propName, prop] of Object.entries(properties)) {
          if (sensitiveFields.some(f => propName.toLowerCase().includes(f))) {
            findings.push({
              id: `API3-sensitive-${schemaName}-${propName}`,
              title: 'Sensitive Field in Response Schema',
              description: `Schema "${schemaName}" contains potentially sensitive field "${propName}" that may be exposed in responses`,
              severity: 'medium',
              category: 'API3:2023',
              location: `components.schemas.${schemaName}.properties.${propName}`,
              remediation: 'Ensure sensitive fields are never returned in API responses. Use writeOnly: true or remove from response schemas.',
              owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'
            });
          }
        }
      }

      // Check for GET endpoints returning user data without field filtering
      for (const endpoint of endpoints) {
        if (endpoint.method === 'get' && (endpoint.path.includes('/user') || endpoint.path.includes('/profile'))) {
          const hasFieldSelection = endpoint.parameters?.some(p =>
            p.name === 'fields' || p.name === 'select' || p.name === 'include'
          );

          if (!hasFieldSelection) {
            findings.push({
              id: `API3-no-field-filter-${endpoint.path}`,
              title: 'No Field Selection Parameter',
              description: `Endpoint ${endpoint.path} returns user data without field selection capability`,
              severity: 'low',
              category: 'API3:2023',
              endpoint: endpoint.path,
              method: endpoint.method,
              location: `paths.${endpoint.path}.${endpoint.method}`,
              remediation: 'Add a fields/select parameter to allow clients to request only needed data',
              owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'
            });
          }
        }
      }

      return findings;
    }
  },
  {
    id: 'API4:2023',
    name: 'Unrestricted Resource Consumption',
    description: 'Missing or improper rate limiting and resource controls',
    check: (spec, endpoints) => {
      const findings: APISecurityFinding[] = [];

      // Check for rate limiting headers in responses
      let hasRateLimitDocs = false;
      for (const endpoint of endpoints) {
        const responses = endpoint.responses || {};
        for (const [code, response] of Object.entries(responses) as [string, Record<string, unknown>][]) {
          if (code === '429') {
            hasRateLimitDocs = true;
          }
          const headers = response.headers || {};
          if (Object.keys(headers).some(h => h.toLowerCase().includes('ratelimit') || h.toLowerCase().includes('rate-limit'))) {
            hasRateLimitDocs = true;
          }
        }
      }

      if (!hasRateLimitDocs) {
        findings.push({
          id: 'API4-no-rate-limit',
          title: 'No Rate Limiting Documentation',
          description: 'API specification does not document rate limiting (no 429 responses or rate limit headers)',
          severity: 'medium',
          category: 'API4:2023',
          location: 'paths.*.responses',
          remediation: 'Document rate limiting with 429 responses and X-RateLimit-* headers',
          owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'
        });
      }

      // Check for pagination on list endpoints
      for (const endpoint of endpoints) {
        if (endpoint.method === 'get' && (endpoint.path.endsWith('s') || endpoint.path.includes('/list'))) {
          const hasPagination = endpoint.parameters?.some(p =>
            ['limit', 'offset', 'page', 'per_page', 'page_size', 'cursor'].includes(p.name.toLowerCase())
          );

          if (!hasPagination) {
            findings.push({
              id: `API4-no-pagination-${endpoint.path}`,
              title: 'List Endpoint Without Pagination',
              description: `List endpoint ${endpoint.path} does not implement pagination`,
              severity: 'medium',
              category: 'API4:2023',
              endpoint: endpoint.path,
              method: endpoint.method,
              location: `paths.${endpoint.path}.${endpoint.method}`,
              remediation: 'Add pagination parameters (limit, offset, page, cursor) to list endpoints',
              owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'
            });
          }
        }
      }

      // Check for unbounded string parameters
      for (const endpoint of endpoints) {
        for (const param of endpoint.parameters || []) {
          if (param.schema?.type === 'string' && !param.schema.maxLength) {
            findings.push({
              id: `API4-unbounded-string-${endpoint.path}-${param.name}`,
              title: 'Unbounded String Parameter',
              description: `Parameter "${param.name}" in ${endpoint.path} has no maxLength constraint`,
              severity: 'low',
              category: 'API4:2023',
              endpoint: endpoint.path,
              method: endpoint.method,
              parameter: param.name,
              location: `paths.${endpoint.path}.${endpoint.method}.parameters`,
              remediation: 'Add maxLength constraint to string parameters',
              owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'
            });
          }
        }
      }

      return findings;
    }
  },
  {
    id: 'API5:2023',
    name: 'Broken Function Level Authorization',
    description: 'Missing authorization for administrative functions',
    check: (spec, endpoints) => {
      const findings: APISecurityFinding[] = [];
      const adminPatterns = ['/admin', '/manage', '/internal', '/system', '/config', '/settings'];

      for (const endpoint of endpoints) {
        const isAdminEndpoint = adminPatterns.some(p => endpoint.path.toLowerCase().includes(p));
        const isModifyingMethod = ['post', 'put', 'patch', 'delete'].includes(endpoint.method);

        if (isAdminEndpoint || (isModifyingMethod && endpoint.path.includes('/role'))) {
          const hasSecurity = endpoint.security && endpoint.security.length > 0;
          const hasGlobalSecurity = spec.security && spec.security.length > 0;

          if (!hasSecurity && !hasGlobalSecurity) {
            findings.push({
              id: `API5-admin-no-auth-${endpoint.method}-${endpoint.path}`,
              title: 'Administrative Endpoint Without Authorization',
              description: `Administrative endpoint ${endpoint.method.toUpperCase()} ${endpoint.path} lacks security requirements`,
              severity: 'critical',
              category: 'API5:2023',
              endpoint: endpoint.path,
              method: endpoint.method,
              location: `paths.${endpoint.path}.${endpoint.method}`,
              remediation: 'Add strict role-based authorization to administrative endpoints',
              owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/'
            });
          }
        }
      }

      return findings;
    }
  },
  {
    id: 'API6:2023',
    name: 'Unrestricted Access to Sensitive Business Flows',
    description: 'Business logic abuse through automated attacks',
    check: (spec, endpoints) => {
      const findings: APISecurityFinding[] = [];
      const sensitiveFlows = ['/checkout', '/purchase', '/transfer', '/vote', '/register', '/reset-password'];

      for (const endpoint of endpoints) {
        if (endpoint.method === 'post' && sensitiveFlows.some(f => endpoint.path.toLowerCase().includes(f))) {
          findings.push({
            id: `API6-sensitive-flow-${endpoint.path}`,
            title: 'Sensitive Business Flow',
            description: `Endpoint ${endpoint.path} handles sensitive business logic. Ensure proper anti-automation controls.`,
            severity: 'info',
            category: 'API6:2023',
            endpoint: endpoint.path,
            method: endpoint.method,
            location: `paths.${endpoint.path}.${endpoint.method}`,
            remediation: 'Implement CAPTCHA, device fingerprinting, rate limiting, and anomaly detection for sensitive flows',
            owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/'
          });
        }
      }

      return findings;
    }
  },
  {
    id: 'API7:2023',
    name: 'Server Side Request Forgery',
    description: 'URL parameters that could enable SSRF attacks',
    check: (spec, endpoints) => {
      const findings: APISecurityFinding[] = [];
      const urlParams = ['url', 'uri', 'link', 'href', 'src', 'dest', 'redirect', 'callback', 'webhook'];

      for (const endpoint of endpoints) {
        for (const param of endpoint.parameters || []) {
          if (urlParams.some(u => param.name.toLowerCase().includes(u))) {
            findings.push({
              id: `API7-ssrf-${endpoint.path}-${param.name}`,
              title: 'Potential SSRF Parameter',
              description: `Parameter "${param.name}" in ${endpoint.path} accepts URL-like input which could enable SSRF`,
              severity: 'high',
              category: 'API7:2023',
              endpoint: endpoint.path,
              method: endpoint.method,
              parameter: param.name,
              location: `paths.${endpoint.path}.${endpoint.method}.parameters`,
              remediation: 'Validate and sanitize URL inputs. Use allowlists for permitted domains. Block internal IP ranges.',
              owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/'
            });
          }
        }
      }

      return findings;
    }
  },
  {
    id: 'API8:2023',
    name: 'Security Misconfiguration',
    description: 'Insecure default configurations and missing security headers',
    check: (spec, endpoints) => {
      const findings: APISecurityFinding[] = [];

      // Check for HTTP servers (should be HTTPS)
      const servers = spec.servers || [];
      for (const server of servers) {
        if (server.url.startsWith('http://') && !server.url.includes('localhost') && !server.url.includes('127.0.0.1')) {
          findings.push({
            id: `API8-http-server-${server.url}`,
            title: 'HTTP Server URL',
            description: `Server "${server.url}" uses HTTP instead of HTTPS`,
            severity: 'high',
            category: 'API8:2023',
            location: 'servers',
            remediation: 'Use HTTPS for all API endpoints',
            owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/'
          });
        }
      }

      // Check for debug/test endpoints
      const debugPatterns = ['/debug', '/test', '/trace', '/actuator', '/_internal', '/swagger', '/api-docs'];
      for (const endpoint of endpoints) {
        if (debugPatterns.some(p => endpoint.path.toLowerCase().includes(p))) {
          findings.push({
            id: `API8-debug-endpoint-${endpoint.path}`,
            title: 'Debug/Test Endpoint Exposed',
            description: `Endpoint ${endpoint.path} appears to be a debug or test endpoint`,
            severity: 'medium',
            category: 'API8:2023',
            endpoint: endpoint.path,
            method: endpoint.method,
            location: `paths.${endpoint.path}`,
            remediation: 'Disable or restrict access to debug endpoints in production',
            owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/'
          });
        }
      }

      // Check for error response schemas
      let hasErrorSchema = false;
      for (const endpoint of endpoints) {
        const responses = endpoint.responses || {};
        for (const code of ['400', '401', '403', '404', '500']) {
          if (responses[code]) hasErrorSchema = true;
        }
      }

      if (!hasErrorSchema) {
        findings.push({
          id: 'API8-no-error-responses',
          title: 'Missing Error Response Definitions',
          description: 'API does not define standardized error responses',
          severity: 'low',
          category: 'API8:2023',
          location: 'paths.*.responses',
          remediation: 'Define standard error response schemas for 4xx and 5xx status codes',
          owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/'
        });
      }

      return findings;
    }
  },
  {
    id: 'API9:2023',
    name: 'Improper Inventory Management',
    description: 'Outdated or shadow APIs that are not properly managed',
    check: (spec, endpoints) => {
      const findings: APISecurityFinding[] = [];

      // Check for version in path
      const versionPatterns = ['/v1', '/v2', '/v3', '/api/v'];
      let hasVersionedPaths = false;

      for (const endpoint of endpoints) {
        if (versionPatterns.some(p => endpoint.path.includes(p))) {
          hasVersionedPaths = true;
          break;
        }
      }

      // Check API info
      if (!spec.info?.version) {
        findings.push({
          id: 'API9-no-version',
          title: 'API Version Not Specified',
          description: 'API specification does not include version information',
          severity: 'low',
          category: 'API9:2023',
          location: 'info.version',
          remediation: 'Add version information to the API specification',
          owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/'
        });
      }

      // Check for deprecated endpoints
      for (const endpoint of endpoints) {
        if (endpoint.summary?.toLowerCase().includes('deprecated') ||
            endpoint.operationId?.toLowerCase().includes('deprecated')) {
          findings.push({
            id: `API9-deprecated-${endpoint.path}`,
            title: 'Deprecated Endpoint Still Documented',
            description: `Endpoint ${endpoint.path} is marked as deprecated but still in spec`,
            severity: 'info',
            category: 'API9:2023',
            endpoint: endpoint.path,
            method: endpoint.method,
            location: `paths.${endpoint.path}`,
            remediation: 'Remove deprecated endpoints or add sunset dates and migration guides',
            owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/'
          });
        }
      }

      return findings;
    }
  },
  {
    id: 'API10:2023',
    name: 'Unsafe Consumption of APIs',
    description: 'Insufficient validation when consuming third-party APIs',
    check: (spec, endpoints) => {
      const findings: APISecurityFinding[] = [];
      const externalPatterns = ['callback', 'webhook', 'external', 'proxy', 'forward'];

      for (const endpoint of endpoints) {
        if (externalPatterns.some(p => endpoint.path.toLowerCase().includes(p) || endpoint.operationId?.toLowerCase().includes(p))) {
          findings.push({
            id: `API10-external-integration-${endpoint.path}`,
            title: 'External API Integration Point',
            description: `Endpoint ${endpoint.path} appears to handle external API integrations`,
            severity: 'info',
            category: 'API10:2023',
            endpoint: endpoint.path,
            method: endpoint.method,
            location: `paths.${endpoint.path}`,
            remediation: 'Validate all data from external APIs. Implement timeouts, circuit breakers, and error handling.',
            owaspApiReference: 'https://owasp.org/API-Security/editions/2023/en/0xa10-unsafe-consumption-of-apis/'
          });
        }
      }

      return findings;
    }
  }
];

// =============================================================================
// API SECURITY SCANNER SERVICE
// =============================================================================

class APISecurityScanner {
  parseOpenAPISpec(content: string, filePath: string): OpenAPISpec | null {
    try {
      const ext = path.extname(filePath).toLowerCase();
      if (ext === '.json') {
        return JSON.parse(content);
      } else if (ext === '.yaml' || ext === '.yml') {
        return yaml.load(content) as OpenAPISpec;
      }
      // Try JSON first, then YAML
      try {
        return JSON.parse(content);
      } catch {
        return yaml.load(content) as OpenAPISpec;
      }
    } catch (error) {
      console.error('[J.O.E. API Scanner] Failed to parse spec:', error);
      return null;
    }
  }

  extractEndpoints(spec: OpenAPISpec): APIEndpoint[] {
    const endpoints: APIEndpoint[] = [];
    const paths = spec.paths || {};

    for (const [pathStr, pathItem] of Object.entries(paths)) {
      const methods = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'];

      for (const method of methods) {
        const operation = (pathItem as Record<string, unknown>)[method] as Record<string, unknown> | undefined;
        if (operation) {
          endpoints.push({
            path: pathStr,
            method,
            operationId: operation.operationId as string | undefined,
            summary: operation.summary as string | undefined,
            security: operation.security as unknown[] | undefined,
            parameters: operation.parameters as APIParameter[] | undefined,
            requestBody: operation.requestBody,
            responses: operation.responses as Record<string, unknown> | undefined
          });
        }
      }
    }

    return endpoints;
  }

  async scanSpec(filePath: string): Promise<APIScanResult> {
    const content = fs.readFileSync(filePath, 'utf-8');
    const spec = this.parseOpenAPISpec(content, filePath);

    if (!spec) {
      throw new Error('Failed to parse OpenAPI specification');
    }

    const endpoints = this.extractEndpoints(spec);
    const findings: APISecurityFinding[] = [];

    // Run all OWASP API Top 10 checks
    for (const check of OWASP_API_CHECKS) {
      const checkFindings = check.check(spec, endpoints);
      findings.push(...checkFindings);
    }

    // Calculate summary
    const summary = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
      total: findings.length
    };

    // Get security schemes
    const securitySchemes = Object.keys(spec.components?.securitySchemes || {});

    // Calculate coverage
    const authenticatedEndpoints = endpoints.filter(e =>
      (e.security && e.security.length > 0) || (spec.security && spec.security.length > 0)
    ).length;

    return {
      specFile: filePath,
      apiName: spec.info?.title || 'Unknown API',
      apiVersion: spec.info?.version || 'Unknown',
      openApiVersion: spec.openapi || spec.swagger || 'Unknown',
      scanTime: new Date().toISOString(),
      endpointsAnalyzed: endpoints.length,
      findings,
      summary,
      securitySchemes,
      coverage: {
        authenticated: authenticatedEndpoints,
        unauthenticated: endpoints.length - authenticatedEndpoints,
        total: endpoints.length
      }
    };
  }

  async scanDirectory(dirPath: string): Promise<APIScanResult[]> {
    const results: APIScanResult[] = [];
    const specPatterns = ['openapi', 'swagger', 'api-spec', 'api.yaml', 'api.json'];

    const scanRecursive = (dir: string) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          if (!['node_modules', '.git', 'vendor'].includes(entry.name)) {
            scanRecursive(fullPath);
          }
          continue;
        }

        const ext = path.extname(entry.name).toLowerCase();
        if (['.yaml', '.yml', '.json'].includes(ext)) {
          const isLikelySpec = specPatterns.some(p => entry.name.toLowerCase().includes(p));

          if (isLikelySpec) {
            try {
              const result = this.scanSpec(fullPath);
              results.push(result as unknown as APIScanResult);
            } catch {
              // Not a valid spec file
            }
          } else {
            // Check file content
            try {
              const content = fs.readFileSync(fullPath, 'utf-8');
              if (content.includes('openapi:') || content.includes('swagger:') || content.includes('"openapi"')) {
                const result = this.scanSpec(fullPath);
                results.push(result as unknown as APIScanResult);
              }
            } catch {
              // Skip
            }
          }
        }
      }
    };

    scanRecursive(dirPath);
    return results;
  }

  getOWASPAPITop10(): Array<{ id: OWASPAPICategory; name: string; description: string }> {
    return OWASP_API_CHECKS.map(c => ({
      id: c.id,
      name: c.name,
      description: c.description
    }));
  }
}

// Export singleton instance
export const apiSecurityScanner = new APISecurityScanner();
