package com.mcp.secretscanner.tool;

import com.mcp.secretscanner.model.SecretFinding;
import com.mcp.secretscanner.model.ScanResult;
import com.mcp.secretscanner.scanner.FileScanner;
import com.mcp.secretscanner.scanner.SecretRuleRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * MCP tools for scanning source files for accidentally committed secrets.
 *
 * Three tools exposed to Claude:
 *  1. scanFile       — scan a single source file
 *  2. scanDirectory  — recursively scan a project directory
 *  3. explainFinding — detailed explanation and remediation for a rule
 */
@Component
public class SecretScannerTools {

    private static final Logger log = LoggerFactory.getLogger(SecretScannerTools.class);

    private final FileScanner fileScanner;
    private final SecretRuleRegistry ruleRegistry;

    public SecretScannerTools(FileScanner fileScanner, SecretRuleRegistry ruleRegistry) {
        this.fileScanner = fileScanner;
        this.ruleRegistry = ruleRegistry;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tool 1 — Scan a single file
    // ─────────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Scan a single source file for accidentally committed secrets such as API keys,
            passwords, tokens, private keys, and connection strings.
            Provide the absolute path to the file.
            Returns all findings with line numbers, rule names, severity, and remediation advice.
            Actual secret values are always redacted in the output — they are never exposed.
            """)
    public ScanResult scanFile(
            @ToolParam(description = "Absolute path to the source file, e.g. /home/dev/myapp/src/main/resources/application.properties")
            String filePath
    ) {
        log.info("Scanning file: {}", filePath);
        Path path = Path.of(filePath);

        if (!Files.exists(path)) {
            return ScanResult.error(filePath, "File not found: " + filePath);
        }
        if (!Files.isRegularFile(path)) {
            return ScanResult.error(filePath, "Not a regular file: " + filePath);
        }

        List<SecretFinding> findings = fileScanner.scanFile(path);
        return buildResult(filePath, 1, findings, List.of());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tool 2 — Scan a directory recursively
    // ─────────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Recursively scan a source directory for accidentally committed secrets.
            Scans Java, Kotlin, Python, JavaScript, TypeScript, YAML, JSON, Properties,
            .env, Gradle, Maven, Terraform, and shell script files.
            Skips binary files, build output (target/, build/), and .git directories.
            Returns all findings with file paths, line numbers, severity, and remediation advice.
            Actual secret values are always redacted — they are never exposed.
            """)
    public ScanResult scanDirectory(
            @ToolParam(description = "Absolute path to the directory to scan, e.g. /home/dev/myapp/src")
            String directoryPath,

            @ToolParam(description = "Maximum directory depth to scan (default 10, max 20). Use a smaller value for large monorepos.")
            int maxDepth
    ) {
        log.info("Scanning directory: {} (depth: {})", directoryPath, maxDepth);
        Path path = Path.of(directoryPath);

        if (!Files.exists(path)) {
            return ScanResult.error(directoryPath, "Directory not found: " + directoryPath);
        }
        if (!Files.isDirectory(path)) {
            return ScanResult.error(directoryPath, "Not a directory: " + directoryPath);
        }

        int depth = Math.min(Math.max(maxDepth, 1), 20);
        FileScanner.DirectoryScanResult result = fileScanner.scanDirectory(path, depth);
        return buildResult(directoryPath, result.filesScanned(), result.findings(), result.skipped());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tool 3 — Explain a finding / rule
    // ─────────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Get a detailed explanation of a secret-detection rule, including:
            - Why this type of secret is dangerous
            - Step-by-step remediation instructions
            - How to remove it from git history
            Provide the rule name exactly as returned by scanFile or scanDirectory.
            """)
    public RuleExplanation explainFinding(
            @ToolParam(description = "Rule name as returned by scanFile/scanDirectory, e.g. 'AWS Access Key ID' or 'Generic Password Assignment'")
            String ruleName
    ) {
        return ruleRegistry.getRules().stream()
                .filter(r -> r.name().equalsIgnoreCase(ruleName))
                .findFirst()
                .map(rule -> new RuleExplanation(
                        rule.name(),
                        rule.category(),
                        rule.severity(),
                        rule.description(),
                        rule.remediation(),
                        GIT_HISTORY_CLEANUP,
                        PREVENTION_TIPS
                ))
                .orElse(new RuleExplanation(
                        ruleName,
                        "Unknown",
                        "UNKNOWN",
                        "Rule not found: " + ruleName,
                        "Check the rule name and try again.",
                        "",
                        ""
                ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper record
    // ─────────────────────────────────────────────────────────────────────────

    public record RuleExplanation(
            String ruleName,
            String category,
            String severity,
            String description,
            String remediation,
            String gitHistoryCleanup,
            String preventionTips
    ) {}

    // ─────────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────────

    private static final String GIT_HISTORY_CLEANUP = """
            === Removing a Secret from Git History ===
            Even after deleting the line, the secret lives in old commits.

            Option 1 — git filter-repo (recommended):
              pip install git-filter-repo
              git filter-repo --path <file> --invert-paths   # remove file entirely, OR
              git filter-repo --replace-text replacements.txt  # replace secret text

            Option 2 — BFG Repo Cleaner:
              java -jar bfg.jar --replace-text passwords.txt your-repo.git
              git reflog expire --expire=now --all && git gc --prune=now --aggressive

            Option 3 — If the repo is private and you can force-push:
              git commit --fixup HEAD
              git rebase -i --autosquash HEAD~N
              git push --force-with-lease

            IMPORTANT: Notify any team members who cloned the repo to re-clone after cleanup.
            """;

    private static final String PREVENTION_TIPS = """
            === Preventing Secrets in Code ===
            1. Use .gitignore — add *.env, local.properties, *-secrets.yml
            2. Use git pre-commit hooks — install detect-secrets or gitleaks as a hook
               gitleaks: https://github.com/gitleaks/gitleaks
            3. Use Spring Boot's environment variable substitution:
               spring.datasource.password=${DB_PASSWORD}
            4. Use a secrets manager:
               - AWS Secrets Manager (cloud)
               - HashiCorp Vault (self-hosted)
               - Spring Cloud Config Server
            5. Add secret scanning to CI/CD — GitHub has built-in secret scanning on push
            """;

    // ─────────────────────────────────────────────────────────────────────────
    // Private builder
    // ─────────────────────────────────────────────────────────────────────────

    private ScanResult buildResult(String path, int filesScanned,
                                   List<SecretFinding> findings, List<String> skipped) {
        // Sort: HIGH first, then MEDIUM, LOW
        findings.sort(Comparator.comparingInt(f -> -severityOrder(f.severity())));

        int high   = (int) findings.stream().filter(f -> "HIGH".equalsIgnoreCase(f.severity())).count();
        int medium = (int) findings.stream().filter(f -> "MEDIUM".equalsIgnoreCase(f.severity())).count();
        int low    = (int) findings.stream().filter(f -> "LOW".equalsIgnoreCase(f.severity())).count();

        ScanResult result = new ScanResult(
                path, filesScanned, findings.size(),
                high, medium, low,
                findings, skipped, ""
        );
        String summary = result.buildSummary();
        return new ScanResult(
                path, filesScanned, findings.size(),
                high, medium, low,
                findings, skipped, summary
        );
    }

    private int severityOrder(String severity) {
        return switch (severity.toUpperCase()) {
            case "HIGH"   -> 3;
            case "MEDIUM" -> 2;
            case "LOW"    -> 1;
            default       -> 0;
        };
    }
}
