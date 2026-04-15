import * as path from 'path';

// Define sensitive file patterns that should not be modified by AI
const SENSITIVE_FILE_PATTERNS = [
    // Configuration files
    /\.env$/i,
    /\.env\./i,
    /config\./i,
    /\.config\./i,
    /\.properties$/i,
    /\.yml$/i,
    /\.yaml$/i,
    /\.json$/i,
    /\.xml$/i,
    /\.toml$/i,
    /\.ini$/i,
    /\.cfg$/i,
    /\.conf$/i,
    
    // Security and authentication files
    /\.pem$/i,
    /\.key$/i,
    /\.crt$/i,
    /\.p12$/i,
    /\.pfx$/i,
    /\.keystore$/i,
    /\.jks$/i,
    /\.truststore$/i,
    
    // Database files
    /\.db$/i,
    /\.sqlite$/i,
    /\.sql$/i,
    
    // Log files
    /\.log$/i,
    /\.logs$/i,
    
    // Backup files
    /\.bak$/i,
    /\.backup$/i,
    /\.old$/i,
    
    // Lock files
    /\.lock$/i,
    /\.pid$/i,
    
    // Git and version control
    /\.gitignore$/i,
    /\.gitattributes$/i,
    /\.git$/i,
    
    // Package managers
    /package\.json$/i,
    /package-lock\.json$/i,
    /yarn\.lock$/i,
    /pom\.xml$/i,
    /build\.gradle$/i,
    /gradle\.properties$/i,
    /requirements\.txt$/i,
    /Gemfile$/i,
    /Gemfile\.lock$/i,
    /Cargo\.toml$/i,
    /Cargo\.lock$/i,
    
    // IDE and editor files
    /\.vscode\//i,
    /\.idea\//i,
    /\.eclipse$/i,
    /\.project$/i,
    /\.classpath$/i,
    /\.settings\//i,
    
    // Build and deployment
    /Dockerfile$/i,
    /docker-compose\./i,
    /\.dockerignore$/i,
    /Jenkinsfile$/i,
    /\.travis\.yml$/i,
    /\.github\//i,
    /\.gitlab-ci\.yml$/i,
    
    // Documentation
    /README\./i,
    /CHANGELOG\./i,
    /LICENSE$/i,
    /\.md$/i,
    
    // System files
    /\.DS_Store$/i,
    /Thumbs\.db$/i,
    /desktop\.ini$/i
];

// Define critical file patterns that should never be modified
const CRITICAL_FILE_PATTERNS = [
    /\.env$/i,
    /\.env\./i,
    /\.pem$/i,
    /\.key$/i,
    /\.crt$/i,
    /\.p12$/i,
    /\.pfx$/i,
    /\.keystore$/i,
    /\.jks$/i,
    /\.truststore$/i,
    /\.git\//i,
    /package\.json$/i,
    /pom\.xml$/i,
    /build\.gradle$/i,
    /Dockerfile$/i,
    /docker-compose\./i
];

export interface SecurityCheckResult {
    isSensitive: boolean;
    isCritical: boolean;
    warningMessage?: string;
    allowModification: boolean;
}

/**
 * Check if a file path is sensitive and should be protected from AI modifications
 */
export function checkFileSecurity(filePath: string): SecurityCheckResult {
    const fileName = path.basename(filePath);
    const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
    
    // Check if it's a critical file (never allow modification)
    const isCritical = CRITICAL_FILE_PATTERNS.some(pattern => pattern.test(normalizedPath));
    if (isCritical) {
        return {
            isSensitive: true,
            isCritical: true,
            warningMessage: `⚠️ CRITICAL SECURITY WARNING: ${fileName} contains sensitive configuration, credentials, or system files that should NEVER be modified by AI.`,
            allowModification: false
        };
    }
    
    // Check if it's a sensitive file (require explicit confirmation)
    const isSensitive = SENSITIVE_FILE_PATTERNS.some(pattern => pattern.test(normalizedPath));
    if (isSensitive) {
        return {
            isSensitive: true,
            isCritical: false,
            warningMessage: `⚠️ SECURITY WARNING: ${fileName} appears to be a configuration, security, or system file. Modifying it may affect your application's behavior or security.`,
            allowModification: true // Allow but with warning
        };
    }
    
    return {
        isSensitive: false,
        isCritical: false,
        allowModification: true
    };
}

/**
 * Get a list of all sensitive files in a vulnerability fix
 */
export function getSensitiveFilesInFix(filePaths: string[]): SecurityCheckResult[] {
    return filePaths.map(filePath => checkFileSecurity(filePath));
}

/**
 * Check if any files in a fix are critical (should be blocked)
 */
export function hasCriticalFiles(filePaths: string[]): boolean {
    return filePaths.some(filePath => checkFileSecurity(filePath).isCritical);
}

/**
 * Get a summary of security warnings for multiple files
 */
export function getSecuritySummary(filePaths: string[]): string {
    const results = getSensitiveFilesInFix(filePaths);
    const criticalFiles = results.filter(r => r.isCritical).map(r => path.basename(r.warningMessage?.split(': ')[1] || ''));
    const sensitiveFiles = results.filter(r => r.isSensitive && !r.isCritical).map(r => path.basename(r.warningMessage?.split(': ')[1] || ''));
    
    let summary = '';
    if (criticalFiles.length > 0) {
        summary += `🚨 CRITICAL FILES (BLOCKED): ${criticalFiles.join(', ')}\n`;
    }
    if (sensitiveFiles.length > 0) {
        summary += `⚠️ SENSITIVE FILES: ${sensitiveFiles.join(', ')}\n`;
    }
    
    return summary;
}