# CodeGuard MCP Server

AI-powered code smell detection and security analysis server using the Model Context Protocol (MCP).

## Quick Start

### Option 1: Using npx (Recommended)

No installation required! Use directly via npx:

**Configure Cursor IDE**

Edit `~/.cursor/mcp.json` (create if it doesn't exist):

```json
{
  "mcpServers": {
    "codeguard": {
      "command": "npx",
      "args": ["-y", "codeguard-mcp-server"],
      "env": {
        "OPENAI_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

**Restart Cursor**

Completely quit and restart Cursor IDE.

### Option 2: Install via npm

```bash
npm install -g codeguard-mcp-server
```

Then configure `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "codeguard": {
      "command": "codeguard-mcp-server",
      "env": {
        "OPENAI_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Option 3: Local Development Setup

For development or local installation:

```bash
git clone https://github.com/tomtarpey/codeguard-mcp-server.git
cd codeguard-mcp-server
npm install
```

Then configure `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "codeguard": {
      "command": "node",
      "args": ["/absolute/path/to/codeguard-mcp-server/index.js"],
      "env": {
        "OPENAI_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

## Usage

After configuration, open any code file in Cursor and ask:
- "Analyze this code for security vulnerabilities"
- "Check this file for code smells"
- "Review this code for quality and security issues"

## Available Tools

### 1. analyze_code_smells
Detects maintainability issues:
- Long methods
- Duplicated code
- Large classes
- Feature envy
- Primitive obsession
- Dead code
- Magic numbers
- Nested conditionals

### 2. analyze_security_vulnerabilities
Scans for security issues:
- SQL/Command injection
- XSS vulnerabilities
- Hardcoded secrets
- Insecure cryptography
- Broken authentication
- Path traversal
- Insecure deserialization
- Input validation issues
- Sensitive data exposure

### 3. analyze_code_quality_and_security
Combined analysis in a single call.

## Supported Languages
- JavaScript
- TypeScript
- Python
- Java
- Go
- Rust

## Configuration Options

### Using Different LLM Providers

**Anthropic Claude:**
```json
"env": {
  "ANTHROPIC_API_KEY": "sk-ant-...",
  "LLM_BASE_URL": "https://api.anthropic.com/v1",
  "LLM_MODEL": "claude-sonnet-4-20250514"
}
```

**Local Ollama:**
```json
"env": {
  "LLM_BASE_URL": "http://localhost:11434/v1",
  "LLM_MODEL": "codellama"
}
```

## Troubleshooting

### Server not starting
- Check that Node.js (v18+) is installed: `node --version`
- Verify the command in mcp.json is correct
- Check logs in Cursor's developer console

### Tools not appearing
- Restart Cursor completely
- Verify mcp.json syntax is valid JSON
- Check that API key is set correctly

### Analysis taking too long
- Use a faster model (e.g., gpt-4o-mini)
- Consider analyzing smaller code snippets
- Check your API rate limits

## Development

### Test the server locally
```bash
npm test
```

### Run in development mode (with auto-reload)
```bash
npm run dev
```

## Publishing

For maintainers, to publish a new version to npm:

```bash
npm version patch|minor|major
npm publish
```

The `prepublishOnly` script will automatically verify the package before publishing.

## License
MIT
