package com.mcp.secretscanner.scanner;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Registry of all secret-detection rules.
 *
 * Each rule has:
 *  - a regex with a capture group around the secret value (group 1)
 *  - category, severity, description, and remediation advice
 *
 * Patterns inspired by gitleaks (MIT licence) and truffleHog rules.
 * https://github.com/gitleaks/gitleaks
 */
@Component
public class SecretRuleRegistry {

    private static final int FLAGS = Pattern.CASE_INSENSITIVE;

    private final List<SecretRule> rules = List.of(

        // ── Cloud providers ──────────────────────────────────────────────────

        new SecretRule(
            "AWS Access Key ID",
            "Cloud",
            "HIGH",
            Pattern.compile("(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", FLAGS),
            "AWS Access Key ID found. This key grants programmatic access to AWS services.",
            "1. Revoke the key immediately in AWS IAM console.\n" +
            "2. Remove it from source code and git history (use `git filter-repo`).\n" +
            "3. Store secrets in AWS Secrets Manager or environment variables."
        ),

        new SecretRule(
            "AWS Secret Access Key",
            "Cloud",
            "HIGH",
            Pattern.compile("(?:aws_secret|secret_access_key|aws_secret_access_key)\\s*[=:]\\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", FLAGS),
            "AWS Secret Access Key found. Combined with the Access Key ID, this provides full AWS API access.",
            "1. Revoke the key immediately in AWS IAM console.\n" +
            "2. Remove from source and git history.\n" +
            "3. Use AWS Secrets Manager, SSM Parameter Store, or IAM roles instead."
        ),

        new SecretRule(
            "Google API Key",
            "Cloud",
            "HIGH",
            Pattern.compile("AIza([0-9A-Za-z\\-_]{35})", FLAGS),
            "Google API Key found. This can be used to call Google Cloud APIs and incur charges.",
            "1. Restrict or delete the key in Google Cloud Console → APIs & Services → Credentials.\n" +
            "2. Use application default credentials or Secret Manager instead."
        ),

        new SecretRule(
            "Google OAuth Client Secret",
            "Cloud",
            "HIGH",
            Pattern.compile("(?:client_secret|oauth_secret)\\s*[=:]\\s*['\"]?([A-Za-z0-9\\-_]{24,})['\"]?", FLAGS),
            "Google OAuth client secret found.",
            "Rotate the secret in Google Cloud Console and store it in an environment variable or secret manager."
        ),

        new SecretRule(
            "Azure Client Secret",
            "Cloud",
            "HIGH",
            Pattern.compile("(?:azure|AZURE)(?:_client_secret|ClientSecret|_secret)\\s*[=:]\\s*['\"]?([A-Za-z0-9~._\\-]{34,})['\"]?", FLAGS),
            "Azure client secret or connection string found.",
            "Rotate in Azure Portal → App Registrations. Store in Azure Key Vault or environment variables."
        ),

        // ── Generic high-entropy patterns ────────────────────────────────────

        new SecretRule(
            "Generic API Key Assignment",
            "Generic",
            "MEDIUM",
            Pattern.compile("(?:api[_\\-]?key|apikey|api[_\\-]?secret|app[_\\-]?secret)\\s*[=:]\\s*['\"]?([A-Za-z0-9\\-_.]{20,})['\"]?", FLAGS),
            "A variable named 'api_key' or 'api_secret' contains a hardcoded value.",
            "Move the value to an environment variable and read it via System.getenv() or Spring @Value."
        ),

        new SecretRule(
            "Generic Password Assignment",
            "Generic",
            "HIGH",
            Pattern.compile("(?:password|passwd|pwd|secret)\\s*[=:=]\\s*['\"]([^'\"\\s]{8,})['\"]", FLAGS),
            "A hardcoded password or secret string found.",
            "Never hardcode passwords. Use environment variables, Spring Cloud Config, or a secrets vault."
        ),

        new SecretRule(
            "Generic Token Assignment",
            "Generic",
            "MEDIUM",
            Pattern.compile("(?:token|access_token|auth_token|bearer_token)\\s*[=:]\\s*['\"]([A-Za-z0-9\\-_.]{20,})['\"]", FLAGS),
            "A hardcoded token found. Tokens are equivalent to passwords.",
            "Store tokens in environment variables. For Spring Boot: spring.security.oauth2.* properties should come from environment or secrets vault."
        ),

        // ── Database credentials ─────────────────────────────────────────────

        new SecretRule(
            "Database Connection String with Password",
            "Database",
            "HIGH",
            Pattern.compile("jdbc:[a-z]+://[^:]+:[^:]+:([^@/\\s]+)@", FLAGS),
            "JDBC connection string with embedded password found.",
            "Remove password from JDBC URL. Use Spring datasource.password property sourced from environment variable or Vault."
        ),

        new SecretRule(
            "Spring Datasource Password",
            "Database",
            "HIGH",
            Pattern.compile("(?:datasource\\.password|spring\\.datasource\\.password)\\s*[=:]\\s*(.+)", FLAGS),
            "Spring datasource password found in plain text configuration.",
            "Use environment variable substitution: spring.datasource.password=${DB_PASSWORD}\n" +
            "Or use Spring Cloud Config Server / Vault."
        ),

        // ── Private keys & certificates ──────────────────────────────────────

        new SecretRule(
            "RSA / EC Private Key",
            "Certificate",
            "HIGH",
            Pattern.compile("-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", FLAGS),
            "PEM-encoded private key found in source code.",
            "1. Remove immediately and rotate the key pair.\n" +
            "2. Never commit private keys. Store them in your OS keychain or a secrets manager.\n" +
            "3. Add *.pem, *.key to .gitignore."
        ),

        new SecretRule(
            "SSH Private Key",
            "Certificate",
            "HIGH",
            Pattern.compile("-----BEGIN OPENSSH PRIVATE KEY-----", FLAGS),
            "OpenSSH private key found.",
            "Remove and rotate. Store SSH keys in ~/.ssh/ (outside the repo) or use a secrets manager."
        ),

        // ── Tokens by service ────────────────────────────────────────────────

        new SecretRule(
            "GitHub Personal Access Token",
            "VCS",
            "HIGH",
            Pattern.compile("(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}", FLAGS),
            "GitHub personal access token found.",
            "1. Revoke immediately at github.com/settings/tokens.\n" +
            "2. Use GitHub Actions secrets or a secrets manager instead."
        ),

        new SecretRule(
            "Slack Token",
            "Messaging",
            "HIGH",
            Pattern.compile("xox[baprs]-[0-9A-Za-z]{10,}", FLAGS),
            "Slack API token found.",
            "Revoke at api.slack.com/apps. Store in environment variables."
        ),

        new SecretRule(
            "Stripe Secret Key",
            "Payment",
            "HIGH",
            Pattern.compile("sk_(?:live|test)_[A-Za-z0-9]{24,}", FLAGS),
            "Stripe secret key found. This grants full access to your Stripe account.",
            "Revoke immediately at dashboard.stripe.com/apikeys. Use environment variables."
        ),

        new SecretRule(
            "Twilio Account SID / Auth Token",
            "Messaging",
            "HIGH",
            Pattern.compile("(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\\s*[=:]\\s*['\"]?([A-Za-z0-9]{32})['\"]?", FLAGS),
            "Twilio auth token found.",
            "Revoke at console.twilio.com. Store in environment variables."
        ),

        new SecretRule(
            "SendGrid API Key",
            "Email",
            "HIGH",
            Pattern.compile("SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}", FLAGS),
            "SendGrid API key found.",
            "Revoke at app.sendgrid.com/settings/api_keys. Store in environment variables."
        ),

        new SecretRule(
            "JWT Secret in Config",
            "Auth",
            "MEDIUM",
            Pattern.compile("(?:jwt[._\\-]?secret|JWT_SECRET|jwtSecret)\\s*[=:]\\s*['\"]?([A-Za-z0-9+/=_\\-]{20,})['\"]?", FLAGS),
            "JWT signing secret found hardcoded. A weak or exposed secret allows token forgery.",
            "Use a cryptographically random secret of at least 256 bits.\n" +
            "Store in environment variable: jwt.secret=${JWT_SECRET}\n" +
            "For production, use RS256 with a key pair instead of HS256."
        ),

        // ── Maven / Gradle credentials ───────────────────────────────────────

        new SecretRule(
            "Maven Repository Credentials",
            "Build",
            "MEDIUM",
            Pattern.compile("(?:<password>)([^<]{6,})(?:</password>)", FLAGS),
            "Password in Maven settings.xml or pom.xml found.",
            "Move credentials to ~/.m2/settings.xml (outside the repo) and add settings.xml to .gitignore.\n" +
            "Better: use Maven's encrypted passwords or a secrets vault."
        ),

        new SecretRule(
            "Gradle Properties Password",
            "Build",
            "MEDIUM",
            Pattern.compile("(?:nexusPassword|mavenPassword|artifactoryPassword|repoPassword)\\s*=\\s*(.+)", FLAGS),
            "Password in gradle.properties found.",
            "Move to ~/.gradle/gradle.properties (outside the repo) or use environment variables."
        )
    );

    public List<SecretRule> getRules() {
        return rules;
    }
}
