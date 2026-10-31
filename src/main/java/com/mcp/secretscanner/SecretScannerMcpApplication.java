package com.mcp.secretscanner;

import com.mcp.secretscanner.tool.SecretScannerTools;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * Secret Scanner MCP Server
 *
 * Exposes three MCP tools to Claude:
 *   - scanFile       : scan a single source file for secrets
 *   - scanDirectory  : recursively scan a directory for secrets
 *   - explainFinding : explain why a match was flagged and how to fix it
 *
 * Run modes:
 *   HTTP (default)  : mvn spring-boot:run          → Claude Code / HTTP clients
 *   stdio           : java -jar ... --spring.profiles.active=stdio → Claude Desktop
 */
@SpringBootApplication
public class SecretScannerMcpApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecretScannerMcpApplication.class, args);
    }

    /**
     * Registers all @Tool methods on SecretScannerTools with the MCP server.
     */
    @Bean
    public ToolCallbackProvider secretScannerToolProvider(SecretScannerTools tools) {
        return MethodToolCallbackProvider.builder()
                .toolObjects(tools)
                .build();
    }
}
