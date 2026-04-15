import type { BatchGroup } from '../core/batchProcessor';

/**
 * Creates a comprehensive prompt for batch fixing multiple vulnerabilities
 */
export function generateBatchPrompt(batchGroup: BatchGroup): string {
    const { filePath, vulnType, vulnerabilities } = batchGroup;
    
    const codeSnippets = vulnerabilities
        .map(v => `Line ${v.line}: ${v.codeSnippet}`)
        .join('\n');
    
    const severityInfo = vulnerabilities
        .map(v => `Line ${v.line}: ${v.severity} severity`)
        .join(', ');
    
    return `
You are a software security expert. Multiple ${vulnType} vulnerabilities have been detected in the same file:

📂 File: ${filePath}
🧨 Type: ${vulnType}
📊 Count: ${vulnerabilities.length} vulnerabilities
📍 Locations: ${severityInfo}

🔍 Here's what I expect from you:
1. Analyze ALL vulnerabilities together to understand the root cause.
2. Provide a comprehensive fix that addresses ALL instances consistently.
3. The project uses layered architecture: Controller → Service → Repository.
4. Apply corrections in all necessary layers, not just superficially.
5. Do NOT delete or replace unrelated code. Only change the lines that are necessary.
6. Do NOT replace the entire file unless absolutely necessary.

🔐 Vulnerable Code Snippets:
------------------
${codeSnippets}
------------------

Respond in the following format (only return actual code in blocks, no extra commentary):

# Explanation:
Brief explanation of the comprehensive fix approach.

# ${filePath}
\`\`\`${getFileExtension(filePath)}
// Comprehensive fix for all ${vulnType} vulnerabilities
\`\`\`

# Additional files (if needed)
\`\`\`filename.ext
// Additional fixes for other layers
\`\`\`
`;
}

/**
 * Gets file extension for code block syntax highlighting
 */
function getFileExtension(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase();
    const extensionMap: { [key: string]: string } = {
        'java': 'java',
        'js': 'javascript',
        'ts': 'typescript',
        'py': 'python',
        'cs': 'csharp',
        'cpp': 'cpp',
        'c': 'c',
        'go': 'go',
        'rb': 'ruby',
        'php': 'php',
        'kt': 'kotlin',
        'scala': 'scala',
        'swift': 'swift',
        'rs': 'rust'
    };
    
    return extensionMap[ext || ''] || 'text';
} 