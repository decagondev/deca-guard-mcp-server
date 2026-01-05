#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import OpenAI from 'openai';

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY,
  baseURL: process.env.LLM_BASE_URL || undefined,
});

const LLM_MODEL = process.env.LLM_MODEL || 'gpt-4o-mini';

class CodeGuardServer {
  constructor() {
    this.server = new Server(
      {
        name: 'codeguard-mcp-server',
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

  setupErrorHandling() {
    this.server.onerror = (error) => {
      console.error('[MCP Error]', error);
    };

    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  setupHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
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
      ],
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
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

  async analyzeCodeSmells(args) {
    const { code, language, filePath } = args;

    const prompt = `You are a code quality expert. Analyze the following ${language} code for common code smells and maintainability issues.

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
          content: 'You are a code quality analysis expert. Always return valid JSON only.',
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.3,
      response_format: { type: 'json_object' },
    });

    const analysis = JSON.parse(response.choices[0].message.content);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(analysis, null, 2),
        },
      ],
    };
  }

  async analyzeSecurityVulnerabilities(args) {
    const { code, language, filePath } = args;

    const prompt = `You are a security expert specializing in code vulnerability detection. Analyze the following ${language} code for security vulnerabilities based on OWASP Top 10.

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
          content: 'You are a security analysis expert. Always return valid JSON only.',
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
      temperature: 0.2,
      response_format: { type: 'json_object' },
    });

    const analysis = JSON.parse(response.choices[0].message.content);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(analysis, null, 2),
        },
      ],
    };
  }

  async analyzeCombined(args) {
    const [smellsResult, securityResult] = await Promise.all([
      this.analyzeCodeSmells(args),
      this.analyzeSecurityVulnerabilities(args),
    ]);

    const smells = JSON.parse(smellsResult.content[0].text);
    const security = JSON.parse(securityResult.content[0].text);

    const combined = {
      filePath: args.filePath || 'unknown',
      language: args.language,
      timestamp: new Date().toISOString(),
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

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('CodeGuard MCP Server running on stdio');
  }
}

const server = new CodeGuardServer();
server.run().catch(console.error);
