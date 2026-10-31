package com.mcp.secretscanner.scanner;

import java.util.regex.Pattern;

/**
 * A single secret-detection rule with its regex, metadata and advice.
 *
 * Patterns are inspired by the open-source gitleaks ruleset:
 * https://github.com/gitleaks/gitleaks/tree/master/config
 *
 * All patterns use case-insensitive matching and look for the secret value
 * in assignment / property / environment variable contexts.
 */
public record SecretRule(
        String name,
        String category,
        String severity,
        Pattern pattern,
        String description,
        String remediation
) {
    /** True if the line matches this rule. */
    public boolean matches(String line) {
        return pattern.matcher(line).find();
    }

    /**
     * Returns the matched portion with the captured secret value redacted,
     * so we never surface the actual secret in findings.
     */
    public String redactedMatch(String line) {
        var matcher = pattern.matcher(line);
        if (!matcher.find()) return "(no match)";
        // Replace the full match or group(1) if present with ***
        try {
            String secret = matcher.group(1);
            return line.replace(secret, "***REDACTED***").stripLeading();
        } catch (IndexOutOfBoundsException e) {
            return matcher.group(0).replaceAll(".{4}$", "***");
        }
    }
}
