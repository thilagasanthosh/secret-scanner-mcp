# Secret Scanner MCP Server (Spring Boot + Spring AI)

A local MCP server that lets Claude scan your source code for accidentally committed secrets — API keys, passwords, tokens, private keys, and connection strings — **without sending any file contents to an external service**.

All scanning runs **100% locally**. Secret values found are **always redacted** in output — the actual secret is never surfaced in Claude's response.

## Tools exposed to Claude

| Tool | What it does |
|---|---|
| `scanFile(filePath)` | Scan a single source file for secrets — returns findings with line numbers, severity, and fix advice |
| `scanDirectory(directoryPath, maxDepth)` | Recursively scan a project directory — skips `target/`, `.git/`, `node_modules/` automatically |
| `explainFinding(ruleName)` | Full explanation of why a rule fired + step-by-step remediation + git history cleanup guide |

## Example conversation with Claude

```
You: Scan /path/to/myproject/src for secrets

Claude: 🚨 Found 3 secret(s) across 47 files: 2 HIGH, 1 MEDIUM

HIGH — AWS Access Key ID (line 12 in DatabaseConfig.java)
  An AWS Access Key ID was found. Rotate immediately in AWS IAM.
  Redacted: AKIA***REDACTED***

HIGH — Generic Password Assignment (line 8 in application.properties)
  spring.datasource.password=***REDACTED***
  Fix: use ${DB_PASSWORD} environment variable substitution.

MEDIUM — JWT Secret in Config (line 34 in SecurityConfig.java)
  jwt.secret=***REDACTED***
  Fix: Store in environment variable. Consider switching to RS256.

You: Explain how to fix the AWS key finding and clean up git history

Claude: [detailed remediation + git filter-repo / BFG instructions]
```

## Detection rules

Rules are inspired by the open-source [gitleaks](https://github.com/gitleaks/gitleaks) ruleset and cover:

| Category | Rules |
|---|---|
| **Cloud** | AWS Access Key ID, AWS Secret Access Key, Google API Key, Google OAuth Secret, Azure Client Secret |
| **Generic** | Hardcoded passwords, API key assignments, token assignments |
| **Database** | JDBC connection strings with passwords, Spring datasource passwords |
| **Certificates** | RSA/EC/OpenSSH private keys in PEM format |
| **VCS** | GitHub Personal Access Tokens (ghp_, gho_, ghu_, ghs_) |
| **Messaging** | Slack tokens (xoxb-, xoxa-), Twilio auth tokens |
| **Payment** | Stripe secret keys (sk_live_, sk_test_) |
| **Email** | SendGrid API keys |
| **Auth** | JWT secrets in config files |
| **Build** | Maven/Gradle repository credentials |

## File types scanned

`.java`, `.kt`, `.groovy`, `.scala`, `.properties`, `.yml`, `.yaml`, `.xml`, `.json`, `.env`, `.gradle`, `.kts`, `.sh`, `.tf`, `.tfvars`, `.toml`, `.py`, `.js`, `.ts`, `.rb`, `.go`, `.conf`, `.cfg`, `.ini`, `.txt`

Automatically **skips**: `target/`, `build/`, `.git/`, `.idea/`, `node_modules/`, `.gradle/`, `.terraform/`, `__pycache__/`, and files larger than 1 MB.

## Stack

- Java 21, Spring Boot 3.5, Spring AI 1.0 (`spring-ai-starter-mcp-server-webmvc`)
- Pure regex scanning — no external API calls, no network required
- Patterns inspired by [gitleaks](https://github.com/gitleaks/gitleaks) (MIT licence)

## Run locally

### Prerequisites
- Java 21, Maven 3.9+

### Build
```bash
mvn clean package -DskipTests
# → target/secret-scanner-mcp-1.0.0.jar
```

### Run (HTTP mode — for Claude Code)
```bash
mvn spring-boot:run
# Server at http://localhost:8080
```

### Run (stdio mode — for Claude Desktop)
```bash
java -jar target/secret-scanner-mcp-1.0.0.jar --spring.profiles.active=stdio
```

## Connect to Claude Desktop

Open `~/Library/Application Support/Claude/claude_desktop_config.json` and add:

```json
{
  "mcpServers": {
    "secret-scanner": {
      "command": "/path/to/java21/bin/java",
      "args": [
        "-jar",
        "/path/to/secret-scanner-mcp/target/secret-scanner-mcp-1.0.0.jar",
        "--spring.profiles.active=stdio"
      ]
    }
  }
}
```

Find your Java 21 path:
```bash
# macOS
/usr/libexec/java_home -v 21

# Linux
which java   # or: update-alternatives --list java
```

Quit Claude Desktop (⌘Q) and reopen. The `secret-scanner` connector appears in Settings → Developer.

## Connect to Claude Code (HTTP)

```bash
# 1. Start the server
mvn spring-boot:run

# 2. Register with Claude Code
claude mcp add --transport http secret-scanner http://localhost:8080/mcp

# 3. Ask Claude
claude
> Scan /path/to/my/project/src for any accidentally committed secrets
```

## What makes this different

| Feature | This MCP | gitleaks CLI | detect-secrets | truffleHog |
|---|---|---|---|---|
| Works inside Claude chat | ✅ | ❌ | ❌ | ❌ |
| No data leaves your machine | ✅ | ✅ | ✅ | ❌ (API mode) |
| Remediation advice per finding | ✅ | ❌ | ❌ | partial |
| Git history cleanup guide | ✅ | ❌ | ❌ | ❌ |
| Spring Boot / Maven aware | ✅ | partial | partial | partial |
| No installation (runs as JAR) | ✅ | ❌ | ❌ | ❌ |
| Secrets always redacted | ✅ | ❌ (shows value) | ✅ | ❌ |

## Security note

- This MCP runs **locally in stdio mode**. No source code or secrets leave your machine.
- Findings always redact the actual secret value — only the rule name, file path, and line number are surfaced.
- The tool does **not** auto-remediate (delete lines, push commits). All fixes are manual — by design.

## Roadmap

- [ ] Custom rule file support (load your own regex patterns from a YAML file)
- [ ] `.secretignore` file support (exclude known false positives)
- [ ] Entropy-based detection for high-entropy strings (complement regex rules)
- [ ] Git diff mode — scan only changed files since last commit
- [ ] CI/CD report format (SARIF output for GitHub Code Scanning)
- [ ] `resolveDependencyTree` integration with dependency-vuln-mcp

## Related project

[dependency-vuln-mcp](https://github.com/thilagasanthosh/dependency-vuln-mcp) — scan Maven pom.xml files for CVE vulnerabilities via OSV.dev
