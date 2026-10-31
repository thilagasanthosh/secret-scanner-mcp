# secret-scanner-mcp

> MCP server that scans source files and directories for accidentally committed secrets — API keys, passwords, tokens, private keys, JDBC credentials. Built with Spring AI and exposed to Claude via the Model Context Protocol (JSON-RPC over SSE or stdio).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  MCP Architecture — Standard server-based tool calling                  │
│                                                                         │
│   Claude / AI Client                                                    │
│         │                                                               │
│         │  ① User asks Claude to scan for secrets                      │
│         ▼                                                               │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │              secret-scanner-mcp  (MCP Server)                   │   │
│   │                                                                  │   │
│   │  ┌──────────────────┐   ┌──────────────────┐                   │   │
│   │  │ Request Handler  │──▶│   Tool Router    │                   │   │
│   │  └──────────────────┘   └────────┬─────────┘                   │   │
│   │                                  │ ② MCP calls the             │   │
│   │                          ┌───────▼────────┐    appropriate     │   │
│   │                          │ Tool Executor  │    tool            │   │
│   │                          └───────┬────────┘                   │   │
│   │                                  │                             │   │
│   │                          ┌───────▼──────────┐                 │   │
│   │                          │Response Formatter│                 │   │
│   └──────────────────────────┴──────────────────┴─────────────────┘   │
│         │                                                               │
│         │  ⑥ Tool result returned to Claude via MCP Protocol          │
│         │    (JSON-RPC over stdio or HTTP/SSE)                         │
│         ▼                                                               │
│   Claude shows result to user                                           │
│                                                                         │
│                    Tools exposed by this MCP server:                    │
│                    ┌─────────────────────────────────────┐              │
│                    │  scan_file      — scan one file     │              │
│                    │  scan_directory — scan recursively  │              │
│                    │  explain_finding— explain a rule    │              │
│                    └─────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────┘

Transport:  JSON-RPC 2.0  over  SSE (HTTP mode)  or  stdio (Desktop mode)
```

### Detailed Call Flow

```
  Claude (MCP Client)                    secret-scanner-mcp
       │                                        │
       │──── SSE connect / stdio pipe ─────────▶│
       │                                        │  ① Initialize
       │◀─── tools/list response ───────────────│     Register tools
       │                                        │     Load rules/patterns
       │                                        │
       │──── tools/call scan_file ─────────────▶│  ② Handle Request
       │     { filePath: "/src/config.yml" }    │     Parse client request
       │                                        │     Identify which tool
       │                                        │     Validate arguments
       │                                        │
       │                                        │  ③ Execute Tool
       │                                        │     Call FileScanner
       │                                        │     Run regex rules
       │                                        │     Collect findings
       │                                        │
       │◀─── JSON-RPC result ───────────────────│  ④ Return Response
       │     { findings: [...] }                │     Format as MCP JSON
       │                                        │     Send back to client
```

---

## MCP vs UTCP — What's the Difference?

> See [secret-scanner-utcp](../secret-scanner-utcp) for the UTCP implementation of the same scanner.

```
┌──────────────────────────────────┬──────────────────────────────────────┐
│  MCP (this project)              │  UTCP (secret-scanner-utcp)          │
├──────────────────────────────────┼──────────────────────────────────────┤
│  Claude / AI Client              │  Claude / AI Agent                   │
│         │                        │         │                            │
│         ▼                        │         ▼                            │
│    MCP Server ◀── JSON-RPC       │  UTCP Client / Plugin                │
│    (Spring AI)                   │  (reads GET /utcp manifest)          │
│         │                        │         │                            │
│         ▼                        │         ▼                            │
│      @Tool methods               │  Tool / API / CLI                    │
│  (ToolCallbackProvider)          │  (plain @PostMapping endpoints)      │
│         │                        │         │                            │
│         ▼                        │         ▼                            │
│  Result back to Client           │  Result back to Client               │
│  (via JSON-RPC)                  │  (direct HTTP response)              │
│                                  │                                      │
│  Standard server-based           │  Direct native tool calling          │
│  tool calling                    │  No wrapper server needed            │
└──────────────────────────────────┴──────────────────────────────────────┘

Aspect           MCP                          UTCP
─────────────────────────────────────────────────────────────────────
Architecture     MCP server wrapper           Direct (no server wrapper)
Protocol         JSON-RPC 2.0                 Plain REST / HTTP
Tool access      Via MCP tool handlers        Via transport plugin (HTTP)
Client support   Claude Code, Claude Desktop  Any HTTP client
Execution path   Client → MCP server → tool   Client → tool directly
Setup complexity Moderate (run MCP server)    Low (expose /utcp route only)
Dependencies     Spring AI BOM + MCP starter  spring-boot-starter-web only
Best fit         Claude integrations          Direct API/CLI integrations
```

**MCP strengths:** Standard protocol, rich Claude ecosystem, clear tool interface with schema validation, works with Claude Code and Claude Desktop out of the box.

**UTCP strengths:** No wrapper server, lightweight, works with any HTTP client, ideal when you already have REST endpoints.

> Neither is universally better. MCP is easier for Claude integrations. UTCP is attractive when you have existing APIs or CLIs.

---

## Tools

| Tool | Description |
|------|-------------|
| `scan_file` | Scan a single file for secrets — returns redacted findings with line numbers, severity, remediation |
| `scan_directory` | Recursively scan a directory — skips `target/`, `.git/`, `node_modules/`. Skips files > 1 MB |
| `explain_finding` | Explain a detection rule: what it detects, why it matters, step-by-step remediation + git history cleanup |

---

## Detection Rules — 30+ rules across 8 categories

| Category | Rules |
|----------|-------|
| ☁️ Cloud | AWS Access Key ID, AWS Secret Access Key, Google API Key, GCP Service Account JSON |
| 🔀 Version Control | GitHub PAT, GitLab Personal Token, Bitbucket App Password |
| 💳 Payment | Stripe Secret Key, PayPal Client Secret |
| 📡 Communication | Slack Bot Token, Slack Webhook URL, Twilio Auth Token, SendGrid API Key |
| 🗄️ Database | JDBC URL with password, MongoDB URI with credentials, Redis URL with password |
| 🔑 Generic | Generic `password =`, `secret =`, `api_key =`, `token =` assignments |
| 🔐 Private Keys | RSA / DSA / EC / OpenSSH `BEGIN ... PRIVATE KEY` blocks |
| 🏗️ Build Tools | Nexus/Artifactory/Maven password in `gradle.properties` |

All findings are **redacted** — the actual secret value is never returned, only `***REDACTED***`.

---

## Usage with Claude

### HTTP mode — Claude Code

```bash
# 1. Start the MCP server
mvn spring-boot:run
# Starts on port 8080

# 2. Add to Claude Code MCP config (~/.claude/claude_desktop_config.json or project .mcp.json)
```

```json
{
  "mcpServers": {
    "secret-scanner": {
      "type": "sse",
      "url": "http://localhost:8080/sse"
    }
  }
}
```

### Stdio mode — Claude Desktop

```bash
mvn clean package
```

```json
{
  "mcpServers": {
    "secret-scanner": {
      "command": "java",
      "args": [
        "-jar",
        "/path/to/secret-scanner-mcp-0.0.1-SNAPSHOT.jar",
        "--spring.profiles.active=stdio"
      ]
    }
  }
}
```

---

## Example Conversations

### Scan a file
> "Scan /Users/me/myapp/src/main/resources/application.yml for secrets"

```
🚨 [HIGH] AWS Access Key ID — line 14
   Match:  AKIA***REDACTED***
   Risk:   AWS Access Key ID found. Grants programmatic access to AWS services.
   Fix:    Revoke in AWS IAM console, remove from source and git history,
           store in AWS Secrets Manager or environment variables.

⚠️ [MEDIUM] Generic Password — line 22
   Match:  password=***REDACTED***
   Risk:   Hardcoded password in config file.
   Fix:    Use environment variables or a secrets manager.
```

### Scan a directory
> "Scan my whole project at /Users/me/myapp for secrets"

```
🚨 3 secrets found across 47 files scanned
   2 HIGH · 1 MEDIUM · 0 LOW

   [HIGH]   src/main/resources/application.yml:14 — AWS Access Key ID
   [HIGH]   src/main/resources/application-prod.yml:8 — GitHub PAT
   [MEDIUM] scripts/deploy.sh:31 — Generic Password
```

### Explain a finding
> "Explain the AWS Access Key ID rule"

```
Rule: AWS Access Key ID   Category: Cloud   Severity: HIGH

What it detects:
  Matches AKIA*, AGPA*, AROA* etc. — all AWS access key ID prefixes.

Why it matters:
  If in git history, anyone with repo access (past or present) may have it.
  Rotate first, then clean history.

Immediate steps:
  1. Revoke the key in AWS IAM → Security credentials → Access keys
  2. Remove from source and git history (see below)
  3. Store in AWS Secrets Manager, SSM Parameter Store, or use IAM roles

Git history cleanup:
  pip install git-filter-repo
  git filter-repo --replace-text <(echo 'AKIAIOSFODNN7EXAMPLE==>REDACTED') --force

Prevention:
  • Add application-prod.yml to .gitignore before first commit
  • Enable GitHub secret scanning alerts on your repo
  • Install pre-commit hooks: gitleaks or detect-secrets
```

---

## How It Works

```
  FileScanner.scanFile(path)
       │
       ├── 1. Check file extension (.java .yml .properties .json .env ...)
       ├── 2. Read all lines
       ├── 3. Skip comment lines (// # *)
       ├── 4. For each line, apply all SecretRule regex patterns
       ├── 5. On match: capture group(1) → replace with ***REDACTED***
       └── 6. Return List<SecretFinding> with file, line, rule, severity

  SecretRuleRegistry
       └── 30+ SecretRule records
               name, category, severity, Pattern, description, remediation
```

---

## Build

```bash
mvn clean package
java -jar target/secret-scanner-mcp-0.0.1-SNAPSHOT.jar
```

## Docker

```bash
docker build -t secret-scanner-mcp .
docker run -p 8080:8080 secret-scanner-mcp
```

## Requirements

- Java 21+
- Maven 3.9+
- Spring Boot 3.5.0
- Spring AI 1.0.0 (MCP Server)

---

## Related Projects

- [secret-scanner-utcp](../secret-scanner-utcp) — **same scanner, UTCP transport** — compare MCP vs UTCP side by side
- [owasp-checker-mcp](../owasp-checker-mcp) — OWASP Top 10 AST analysis for Spring Boot
- [jwt-analyser-mcp](../jwt-analyser-mcp) — JWT decode and security audit
- [http-security-headers-mcp](../http-security-headers-mcp) — HTTP security header analysis
- [dependency-vuln-mcp](../dependency-vuln-mcp) — CVE scanning via OSV.dev
