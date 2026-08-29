---
layout: page
permalink: /experimental/mcp/
parent: Experimental Features
nav_order: 4
---

# Model Context Protocol (MCP) Server

Experimental
{: .label }

OSV-Scanner includes an experimental Model Context Protocol (MCP) server command (`experimental-mcp`). This allows Large Language Model (LLM) agents, AI coding assistants, and modern developer tools (such as Claude Desktop, Cursor, Gemini CLI, or custom agent pipelines) to autonomously audit dependencies and triage vulnerabilities in real time.

{: .note }
The [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) is an open standard that enables AI models and agent frameworks to securely interact with local developer tools and context sources via structured tool calls and prompts.

## Quickstart

Run the MCP server directly using the CLI:

```bash
# Start the MCP server over standard input/output (stdio mode)
osv-scanner experimental-mcp
```

Or run the server over Server-Sent Events (SSE) on a network port:

```bash
# Start the MCP server on a specific network address
osv-scanner experimental-mcp --sse localhost:8080
```

## Available MCP Tools

When the server runs, it registers three core tools for AI agents:

### 1. `scan_vulnerable_dependencies`

Scans a source directory for vulnerable dependencies by walking the directory structure and matching discovered dependencies against the [OSV.dev](https://osv.dev) database.

- **Parameters**:
  - `paths` (`[]string`): List of absolute or relative paths to directories or lockfiles to scan.
  - `ignore_glob_patterns` (`[]string`): Glob patterns to ignore during scanning (e.g., `["**/test/**", "**/vendor/**"]`).
  - `recursive` (`bool`): Whether to scan nested subdirectories recursively.

### 2. `get_vulnerability_details`

Fetches the complete Open Source Vulnerability (OSV) JSON record for a specific vulnerability ID.

- **Parameters**:
  - `id` (`string`): The vulnerability identifier (e.g., `GHSA-xxxx-xxxx-xxxx` or `CVE-2024-XXXXX`).

### 3. `ignore_vulnerability`

Provides actionable configuration guidelines for generating `osv-scanner.toml` to safely suppress specific vulnerability IDs, false positives, or accepted risks from future scan reports.

## Pre-Configured MCP Prompts

The server includes ready-to-use security prompts for agent orchestrators:

### `scan_deps`

Guides the AI assistant through a structured security audit of project dependencies:
1. **Initial Scan**: Runs recursive dependency discovery on the workspace.
2. **Analysis & Prioritization**: Evaluates vulnerabilities by severity and description.
3. **Remediation Plan**: Proposes safe version upgrades, patches, or configuration exclusions.

## Integration Examples

### Claude Desktop Configuration

To use OSV-Scanner inside Claude Desktop, add the following configuration to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "osv-scanner": {
      "command": "osv-scanner",
      "args": ["experimental-mcp"]
    }
  }
}
```

### Cursor / AI Agent Configuration (`mcp.json`)

```json
{
  "mcpServers": {
    "osv-scanner": {
      "command": "osv-scanner",
      "args": ["experimental-mcp"]
    }
  }
}
```
