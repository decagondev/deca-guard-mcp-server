#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import OpenAI from 'openai';

/**
 * Determines the API key to use based on environment variables.
 * Priority: OPENROUTER_API_KEY > OPENAI_API_KEY > ANTHROPIC_API_KEY
 * @returns {string|undefined} API key for the LLM provider
 */
function getApiKey() {
  return (
    process.env.OPENROUTER_API_KEY ||
    process.env.OPENAI_API_KEY ||
    process.env.ANTHROPIC_API_KEY
  );
}

/**
 * Determines the base URL for the LLM API.
 * If LLM_BASE_URL is set, it takes precedence.
 * Otherwise, defaults to OpenRouter if OPENROUTER_API_KEY is set.
 * @returns {string|undefined} Base URL for the LLM API
 */
function getBaseURL() {
  if (process.env.LLM_BASE_URL) {
    return process.env.LLM_BASE_URL;
  }
  if (process.env.OPENROUTER_API_KEY) {
    return 'https://openrouter.ai/api/v1';
  }
  return undefined;
}

/**
 * OpenAI-compatible client instance configured with API key and base URL from environment variables.
 * Supports multiple LLM providers:
 * - OpenAI (default): Uses OPENAI_API_KEY
 * - OpenRouter: Uses OPENROUTER_API_KEY with base URL https://openrouter.ai/api/v1
 * - Local LLMs (Ollama, etc.): Uses LLM_BASE_URL (e.g., http://localhost:11434/v1)
 * - Anthropic: Uses ANTHROPIC_API_KEY (may require compatible base URL)
 * @type {OpenAI}
 */
const openai = new OpenAI({
  apiKey: getApiKey(),
  baseURL: getBaseURL(),
});

/**
 * LLM model to use for code analysis.
 * Defaults based on provider:
 * - OpenAI: 'gpt-4o-mini'
 * - OpenRouter: 'openai/gpt-4o-mini' (or specify any model from openrouter.ai)
 * - Local: Model name as configured (e.g., 'codellama', 'llama2', etc.)
 * @type {string}
 */
const LLM_MODEL =
  process.env.LLM_MODEL ||
  (process.env.OPENROUTER_API_KEY ? 'openai/gpt-4o-mini' : 'gpt-4o-mini');

/**
 * Gets the current date and time in ISO format.
 * @returns {string} Current date/time as ISO string
 */
function getCurrentDate() {
  return new Date().toISOString();
}

/**
 * Gets the current date in a human-readable format for prompts.
 * @returns {string} Current date in YYYY-MM-DD format
 */
function getCurrentDateString() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/**
 * MCP Server for code smell detection and security analysis.
 * Provides tools for analyzing code quality and security vulnerabilities using AI.
 * @class
 */
class DecaGuardServer {
  /**
   * Initializes the DecaGuard MCP Server with tool handlers and error handling.
   * @constructor
   */
  constructor() {
    this.server = new McpServer(
      {
        name: 'deca-guard-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupHandlers();
    this.setupErrorHandling();
  }

  /**
   * Sets up error handling for the MCP server and process signals.
   * Handles server errors and graceful shutdown on SIGINT.
   * @private
   */
  setupErrorHandling() {
    this.server.server.onerror = (error) => {
      console.error('[MCP Error]', error);
    };

    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  /**
   * Registers all MCP tools using the McpServer API.
   * Registers three tools: analyze_code_smells, analyze_security_vulnerabilities,
   * and analyze_code_quality_and_security.
   * @private
   */
  setupHandlers() {
    // Define tools list
    this.tools = [
      {
        name: 'analyze_code_smells',
        description:
          'Analyzes code for common code smells and maintainability issues. Detects long methods, duplicated code, large classes, feature envy, primitive obsession, dead code, magic numbers, and nested conditionals. Returns structured findings with severity, location, and refactoring suggestions.',
        inputSchema: {
          type: 'object',
          properties: {
            code: {
              type: 'string',
              description: 'The code snippet or file content to analyze',
            },
            language: {
              type: 'string',
              description: 'Programming language (e.g., javascript, python, java)',
              enum: ['javascript', 'typescript', 'python', 'java', 'go', 'rust'],
            },
            filePath: {
              type: 'string',
              description: 'Optional file path for context',
            },
          },
          required: ['code', 'language'],
        },
      },
      {
        name: 'analyze_security_vulnerabilities',
        description:
          'Scans code for security vulnerabilities based on OWASP Top 10. Detects SQL injection, XSS, hardcoded secrets, insecure dependencies, broken authentication, and more. Returns structured vulnerability reports with severity levels (low/medium/high/critical) and mitigation strategies.',
        inputSchema: {
          type: 'object',
          properties: {
            code: {
              type: 'string',
              description: 'The code snippet or file content to analyze',
            },
            language: {
              type: 'string',
              description: 'Programming language',
              enum: ['javascript', 'typescript', 'python', 'java', 'go', 'rust'],
            },
            filePath: {
              type: 'string',
              description: 'Optional file path for context',
            },
          },
          required: ['code', 'language'],
        },
      },
      {
        name: 'analyze_code_quality_and_security',
        description:
          'Combined analysis for both code smells and security vulnerabilities. Provides a comprehensive code quality report in a single call. Ideal for complete code review.',
        inputSchema: {
          type: 'object',
          properties: {
            code: {
              type: 'string',
              description: 'The code snippet or file content to analyze',
            },
            language: {
              type: 'string',
              description: 'Programming language',
              enum: ['javascript', 'typescript', 'python', 'java', 'go', 'rust'],
            },
            filePath: {
              type: 'string',
              description: 'Optional file path for context',
            },
          },
          required: ['code', 'language'],
        },
      },
    ];

    // Handle tools/list request
    this.server.setRequestHandler('tools/list', async () => {
      return {
        tools: this.tools,
      };
    });

    // Handle tools/call request
    this.server.setRequestHandler('tools/call', async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'analyze_code_smells':
            return await this.analyzeCodeSmells(args);
          case 'analyze_security_vulnerabilities':
            return await this.analyzeSecurityVulnerabilities(args);
          case 'analyze_code_quality_and_security':
            return await this.analyzeCombined(args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  /**
   * Analyzes code for common code smells and maintainability issues.
   * Detects long methods, duplicated code, large classes, feature envy,
   * primitive obsession, dead code, magic numbers, and nested conditionals.
   * @param {Object} args - Analysis arguments
   * @param {string} args.code - The code snippet or file content to analyze
   * @param {string} args.language - Programming language (javascript, typescript, python, java, go, rust)
   * @param {string} [args.filePath] - Optional file path for context
   * @returns {Promise<Object>} MCP tool response with JSON analysis results
   * @returns {Object} returns.content - Array containing text content with analysis
   * @returns {string} returns.content[].type - Content type ('text')
   * @returns {string} returns.content[].text - JSON stringified analysis results
   * @throws {Error} If OpenAI API call fails or response is invalid
   */
  async analyzeCodeSmells(args) {
    const { code, language, filePath } = args;
    const currentDate = getCurrentDateString();
    const currentTimestamp = getCurrentDate();

    const prompt = `You are a code quality expert. Analyze the following ${language} code for common code smells and maintainability issues.

IMPORTANT: The current date is ${currentDate} (${currentTimestamp}). Use this exact date in any date fields in your response. Do not use any other date.

Code to analyze:
\`\`\`${language}
${code}
\`\`\`

${filePath ? `File: ${filePath}` : ''}

Detect the following code smells:
1. **Long Method**: Methods/functions over 50 lines or with excessive complexity
2. **Duplicated Code**: Repeated code blocks that should be extracted
3. **Large Class**: Classes with too many responsibilities (>300 lines or >10 methods)
4. **Feature Envy**: Methods that access data from other classes more than their own
5. **Primitive Obsession**: Overuse of primitive types instead of small objects
6. **Dead Code**: Unused variables, functions, or imports
7. **Magic Numbers**: Hardcoded numbers without explanation
8. **Nested Conditionals**: Deeply nested if/else statements

Return ONLY a valid JSON object (no markdown, no explanation) with this structure:
{
  "timestamp": "${currentTimestamp}",
  "analysisDate": "${currentDate}",
  "summary": {
    "totalIssues": number,
    "criticalCount": number,
    "highCount": number,
    "mediumCount": number,
    "lowCount": number
  },
  "issues": [
    {
      "type": "smell_name",
      "severity": "low|medium|high|critical",
      "location": {
        "startLine": number,
        "endLine": number,
        "context": "relevant code snippet"
      },
      "explanation": "clear explanation of the issue",
      "suggestion": "specific refactoring recommendation",
      "impact": "how this affects maintainability"
    }
  ]
}`;

    const response = await openai.chat.completions.create({
      model: LLM_MODEL,
      messages: [
        {
          role: 'system',
          content: `You are a code quality analysis expert. Always return valid JSON only. The current date is ${currentDate} (${currentTimestamp}). Always use this exact date in any date fields.`,
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.3,
      response_format: { type: 'json_object' },
    });

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error('No content in OpenAI response');
    }
    const analysis = JSON.parse(content);
    
    // Ensure timestamp is set correctly even if LLM doesn't include it
    if (!analysis.timestamp) {
      analysis.timestamp = currentTimestamp;
    }
    if (!analysis.analysisDate) {
      analysis.analysisDate = currentDate;
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(analysis, null, 2),
        },
      ],
    };
  }

  /**
   * Scans code for security vulnerabilities based on OWASP Top 10.
   * Detects SQL injection, XSS, hardcoded secrets, insecure dependencies,
   * broken authentication, and more.
   * @param {Object} args - Analysis arguments
   * @param {string} args.code - The code snippet or file content to analyze
   * @param {string} args.language - Programming language (javascript, typescript, python, java, go, rust)
   * @param {string} [args.filePath] - Optional file path for context
   * @returns {Promise<Object>} MCP tool response with JSON vulnerability analysis
   * @returns {Object} returns.content - Array containing text content with analysis
   * @returns {string} returns.content[].type - Content type ('text')
   * @returns {string} returns.content[].text - JSON stringified vulnerability report
   * @throws {Error} If OpenAI API call fails or response is invalid
   */
  async analyzeSecurityVulnerabilities(args) {
    const { code, language, filePath } = args;
    const currentDate = getCurrentDateString();
    const currentTimestamp = getCurrentDate();

    const prompt = `You are a security expert specializing in code vulnerability detection. Analyze the following ${language} code for security vulnerabilities based on OWASP Top 10.

IMPORTANT: The current date is ${currentDate} (${currentTimestamp}). Use this exact date in any date fields in your response. Do not use any other date.

Code to analyze:
\`\`\`${language}
${code}
\`\`\`

${filePath ? `File: ${filePath}` : ''}

Detect the following security issues:
1. **SQL Injection**: Unsanitized user input in database queries
2. **Command Injection**: Unsanitized input in system commands
3. **XSS (Cross-Site Scripting)**: Unescaped output in web contexts
4. **Path Traversal**: File operations with unsanitized paths
5. **Hardcoded Secrets**: API keys, passwords, tokens in code
6. **Insecure Cryptography**: Weak algorithms, hardcoded keys
7. **Broken Authentication**: Missing or weak auth checks
8. **Insecure Deserialization**: Unsafe object deserialization
9. **Missing Input Validation**: Lack of input sanitization
10. **Sensitive Data Exposure**: Logging or storing sensitive data

Return ONLY a valid JSON object (no markdown, no explanation) with this structure:
{
  "timestamp": "${currentTimestamp}",
  "analysisDate": "${currentDate}",
  "summary": {
    "totalVulnerabilities": number,
    "criticalCount": number,
    "highCount": number,
    "mediumCount": number,
    "lowCount": number,
    "securityScore": number (0-100, higher is better)
  },
  "vulnerabilities": [
    {
      "type": "vulnerability_name",
      "severity": "low|medium|high|critical",
      "cwe": "CWE-XXX (if applicable)",
      "location": {
        "startLine": number,
        "endLine": number,
        "context": "vulnerable code snippet"
      },
      "explanation": "clear explanation of the vulnerability",
      "exploitation": "how this could be exploited",
      "mitigation": "specific fix recommendation with code example",
      "references": ["OWASP link or resource"]
    }
  ]
}`;

    const response = await openai.chat.completions.create({
      model: LLM_MODEL,
      messages: [
        {
          role: 'system',
          content: `You are a security analysis expert. Always return valid JSON only. The current date is ${currentDate} (${currentTimestamp}). Always use this exact date in any date fields.`,
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.2,
      response_format: { type: 'json_object' },
    });

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error('No content in OpenAI response');
    }
    const analysis = JSON.parse(content);
    
    // Ensure timestamp is set correctly even if LLM doesn't include it
    if (!analysis.timestamp) {
      analysis.timestamp = currentTimestamp;
    }
    if (!analysis.analysisDate) {
      analysis.analysisDate = currentDate;
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(analysis, null, 2),
        },
      ],
    };
  }

  /**
   * Performs combined analysis for both code smells and security vulnerabilities.
   * Provides a comprehensive code quality report in a single call.
   * @param {Object} args - Analysis arguments
   * @param {string} args.code - The code snippet or file content to analyze
   * @param {string} args.language - Programming language (javascript, typescript, python, java, go, rust)
   * @param {string} [args.filePath] - Optional file path for context
   * @returns {Promise<Object>} MCP tool response with combined JSON analysis
   * @returns {Object} returns.content - Array containing text content with combined analysis
   * @returns {string} returns.content[].type - Content type ('text')
   * @returns {string} returns.content[].text - JSON stringified combined report
   * @throws {Error} If either analysis fails
   */
  async analyzeCombined(args) {
    const currentTimestamp = getCurrentDate();
    const currentDate = getCurrentDateString();
    
    const [smellsResult, securityResult] = await Promise.all([
      this.analyzeCodeSmells(args),
      this.analyzeSecurityVulnerabilities(args),
    ]);

    const smells = JSON.parse(smellsResult.content[0].text);
    const security = JSON.parse(securityResult.content[0].text);

    const combined = {
      filePath: args.filePath || 'unknown',
      language: args.language,
      timestamp: currentTimestamp,
      analysisDate: currentDate,
      codeSmells: smells,
      securityVulnerabilities: security,
      overallAssessment: {
        totalIssues: smells.summary.totalIssues + security.summary.totalVulnerabilities,
        criticalIssues: smells.summary.criticalCount + security.summary.criticalCount,
        recommendation: this.getOverallRecommendation(smells, security),
      },
    };

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(combined, null, 2),
        },
      ],
    };
  }

  /**
   * Generates an overall recommendation based on code smell and security analysis results.
   * @param {Object} smells - Code smells analysis result
   * @param {Object} smells.summary - Summary object with count fields
   * @param {number} smells.summary.criticalCount - Number of critical code smells
   * @param {number} smells.summary.highCount - Number of high-severity code smells
   * @param {Object} security - Security vulnerabilities analysis result
   * @param {Object} security.summary - Summary object with count fields
   * @param {number} security.summary.criticalCount - Number of critical vulnerabilities
   * @param {number} security.summary.highCount - Number of high-severity vulnerabilities
   * @returns {string} Recommendation message based on issue severity
   * @private
   */
  getOverallRecommendation(smells, security) {
    const criticalTotal = smells.summary.criticalCount + security.summary.criticalCount;
    const highTotal = smells.summary.highCount + security.summary.highCount;

    if (criticalTotal > 0) {
      return 'URGENT: Address critical security vulnerabilities and code smells immediately before deployment.';
    } else if (highTotal > 3) {
      return 'HIGH PRIORITY: Multiple high-severity issues found. Refactor before merging.';
    } else if (highTotal > 0) {
      return 'MEDIUM PRIORITY: Some high-severity issues detected. Review and address.';
    } else {
      return 'GOOD: Code quality is acceptable. Address remaining minor issues during regular maintenance.';
    }
  }

  /**
   * Starts the MCP server and connects it to stdio transport.
   * @returns {Promise<void>}
   * @throws {Error} If server connection fails
   */
  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('DecaGuard MCP Server running on stdio');
  }
}

const server = new DecaGuardServer();
server.run().catch(console.error);
