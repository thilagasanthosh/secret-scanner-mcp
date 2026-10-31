package com.mcp.secretscanner.scanner;

import com.mcp.secretscanner.model.SecretFinding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.stream.Stream;

/**
 * Core file scanner — walks files and applies all SecretRules line by line.
 */
@Component
public class FileScanner {

    private static final Logger log = LoggerFactory.getLogger(FileScanner.class);

    // File extensions to scan (text-based source and config files)
    private static final Set<String> SCANNABLE_EXTENSIONS = Set.of(
            ".java", ".kt", ".groovy", ".scala",
            ".properties", ".yml", ".yaml", ".xml", ".json", ".env",
            ".gradle", ".kts", ".sh", ".bash",
            ".tf", ".tfvars", ".toml",
            ".py", ".js", ".ts", ".rb", ".go",
            ".conf", ".cfg", ".ini", ".txt"
    );

    // Directories to skip entirely
    private static final Set<String> SKIP_DIRS = Set.of(
            "target", "build", ".git", ".idea", "node_modules",
            ".gradle", "__pycache__", ".venv", "venv", ".terraform"
    );

    private final SecretRuleRegistry ruleRegistry;

    public FileScanner(SecretRuleRegistry ruleRegistry) {
        this.ruleRegistry = ruleRegistry;
    }

    /**
     * Scan a single file and return all findings.
     */
    public List<SecretFinding> scanFile(Path filePath) {
        List<SecretFinding> findings = new ArrayList<>();

        if (!isScannable(filePath)) {
            log.debug("Skipping non-scannable file: {}", filePath);
            return findings;
        }

        try {
            List<String> lines = Files.readAllLines(filePath);
            List<SecretRule> rules = ruleRegistry.getRules();

            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                // Skip comment lines (basic heuristic)
                String trimmed = line.stripLeading();
                if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) {
                    continue;
                }

                for (SecretRule rule : rules) {
                    if (rule.matches(line)) {
                        findings.add(new SecretFinding(
                                filePath.toAbsolutePath().toString(),
                                i + 1,
                                redactLine(line),
                                rule.name(),
                                rule.category(),
                                rule.severity(),
                                rule.redactedMatch(line),
                                rule.description(),
                                rule.remediation()
                        ));
                    }
                }
            }
        } catch (IOException e) {
            log.warn("Could not read file {}: {}", filePath, e.getMessage());
        } catch (Exception e) {
            log.warn("Error scanning file {}: {}", filePath, e.getMessage());
        }

        return findings;
    }

    /**
     * Recursively scan a directory, returning all findings and a list of skipped files.
     */
    public record DirectoryScanResult(List<SecretFinding> findings, List<String> skipped, int filesScanned) {}

    public DirectoryScanResult scanDirectory(Path dirPath, int maxDepth) {
        List<SecretFinding> allFindings = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        int[] fileCount = {0};

        try {
            Files.walkFileTree(dirPath, Set.of(), maxDepth, new SimpleFileVisitor<>() {

                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    String dirName = dir.getFileName() != null ? dir.getFileName().toString() : "";
                    if (SKIP_DIRS.contains(dirName)) {
                        log.debug("Skipping directory: {}", dir);
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (attrs.size() > 1_000_000) { // skip files > 1 MB
                        skipped.add(file.toString() + " (too large)");
                        return FileVisitResult.CONTINUE;
                    }
                    if (isScannable(file)) {
                        fileCount[0]++;
                        allFindings.addAll(scanFile(file));
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    skipped.add(file.toString() + " (" + exc.getMessage() + ")");
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.error("Failed to walk directory {}: {}", dirPath, e.getMessage());
        }

        return new DirectoryScanResult(allFindings, skipped, fileCount[0]);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private boolean isScannable(Path file) {
        String name = file.getFileName().toString();
        // Always scan .env files regardless of extension position
        if (name.startsWith(".env")) return true;
        int dot = name.lastIndexOf('.');
        if (dot < 0) return false;
        return SCANNABLE_EXTENSIONS.contains(name.substring(dot));
    }

    /** Replace any 20+ char alphanumeric sequences in a line with *** for display */
    private String redactLine(String line) {
        return line.replaceAll("[A-Za-z0-9+/=_\\-]{20,}", "***REDACTED***")
                   .stripTrailing();
    }
}
