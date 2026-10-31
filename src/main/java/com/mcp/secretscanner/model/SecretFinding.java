package com.mcp.secretscanner.model;

/**
 * A single secret detected in a source file.
 *
 * @param filePath     absolute path to the file
 * @param lineNumber   1-based line number where the secret was found
 * @param lineContent  the offending line (secret value is redacted)
 * @param ruleName     name of the rule that matched (e.g. "AWS Access Key")
 * @param ruleCategory category of secret (e.g. "Cloud", "Database", "Generic")
 * @param severity     HIGH / MEDIUM / LOW
 * @param redactedMatch the matched text with the secret replaced by ***
 * @param description  brief explanation of the risk
 * @param remediation  what the developer should do to fix it
 */
public record SecretFinding(
        String filePath,
        int lineNumber,
        String lineContent,
        String ruleName,
        String ruleCategory,
        String severity,
        String redactedMatch,
        String description,
        String remediation
) {
    public String severityEmoji() {
        return switch (severity.toUpperCase()) {
            case "HIGH"   -> "🚨";
            case "MEDIUM" -> "⚠️";
            case "LOW"    -> "🔷";
            default       -> "ℹ️";
        };
    }

    public String summary() {
        return "%s [%s] %s — line %d in %s".formatted(
                severityEmoji(), ruleName, redactedMatch, lineNumber, filePath);
    }
}
