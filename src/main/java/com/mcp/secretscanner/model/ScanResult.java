package com.mcp.secretscanner.model;

import java.util.List;

/**
 * Result of scanning a file or directory for secrets.
 */
public record ScanResult(
        String scannedPath,
        int filesScanned,
        int totalFindings,
        int highCount,
        int mediumCount,
        int lowCount,
        List<SecretFinding> findings,
        List<String> skippedFiles,
        String summary
) {
    public static ScanResult empty(String path) {
        return new ScanResult(path, 0, 0, 0, 0, 0,
                List.of(), List.of(), "✅ No secrets found in: " + path);
    }

    public static ScanResult error(String path, String message) {
        return new ScanResult(path, 0, 0, 0, 0, 0,
                List.of(), List.of("ERROR: " + message),
                "❌ Scan failed: " + message);
    }

    public String buildSummary() {
        if (totalFindings == 0) {
            return "✅ No secrets found. %d file(s) scanned.".formatted(filesScanned);
        }
        return ("🚨 Found %d secret(s) across %d file(s): " +
                "%d HIGH, %d MEDIUM, %d LOW. " +
                "Rotate or remove all flagged secrets immediately.")
                .formatted(totalFindings, filesScanned, highCount, mediumCount, lowCount);
    }
}
