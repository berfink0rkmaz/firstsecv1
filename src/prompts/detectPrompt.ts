type PromptFile = {
    filePath: string;
    language: string;
    content: string;
};

export function generateDetectionPrompt(primaryFile: PromptFile, neighborFiles: PromptFile[]): string {
    const neighborSection = neighborFiles.length > 0
        ? neighborFiles.map(file => formatFileBlock(file)).join('\n\n')
        : 'No neighbor files provided.';

    return `
You are a senior application security reviewer.

Your task is to detect real security vulnerabilities in the PRIMARY_FILE.
You are also given NEIGHBOR_FILES as supporting context only.

Scanning strategy:
- Focus on the PRIMARY_FILE first.
- Use NEIGHBOR_FILES to understand data flow, trust boundaries, validation, authorization, persistence, and dangerous sinks.
- This is a file-plus-neighbor-context review, not a whole-project review.

Neighbor context may include:
- controller + service
- service + repository
- class + interface
- file + imported local modules

Important rules:
- Only report vulnerabilities that exist in the PRIMARY_FILE.
- Do not report findings that belong only to a neighbor file.
- You may use neighbor files to justify why code in the PRIMARY_FILE is vulnerable.
- Prefer high-confidence findings over speculative ones.
- If something is uncertain, do not report it.
- Do not return prose, markdown, explanations, or code fences.
- Return strict JSON only.

Return exactly this JSON schema:
{
  "vulnerabilities": [
    {
      "category": "string",
      "filePath": "string",
      "line": 1,
      "severity": "Critical|High|Medium|Low",
      "abstract": "string",
      "codeSnippet": "string"
    }
  ]
}

Output rules:
- filePath must always be the PRIMARY_FILE path exactly as provided.
- line must be a line number in the PRIMARY_FILE.
- category must be a stable vulnerability type label such as:
  "SQL Injection", "Command Injection", "Path Traversal", "Broken Access Control", "XXE", "SSRF", "Insecure Deserialization", "Hardcoded Secret", "Weak Cryptography", "XSS", "CSRF", "Authentication Bypass"
- abstract must be concise and specific:
  explain why the PRIMARY_FILE is vulnerable, optionally referencing neighbor context
- codeSnippet must be the smallest relevant snippet from the PRIMARY_FILE
- If there are no real vulnerabilities, return:
  {"vulnerabilities":[]}

Review guidance:
Look for issues such as:
- untrusted input reaching database queries, command execution, file access, template rendering, redirects, HTTP calls, or deserialization
- missing or broken authorization checks
- authentication flaws
- unsafe file handling
- insecure crypto usage
- secret exposure
- unsafe external requests
- validation/sanitization gaps
- dangerous framework misuses
- trust boundary violations across controller/service/repository flow

PRIMARY_FILE:
Path: ${primaryFile.filePath}
Language: ${primaryFile.language}
Code:
${primaryFile.content}

NEIGHBOR_FILES:
${neighborSection}
`.trim();
}

function formatFileBlock(file: PromptFile): string {
    return [
        `- Path: ${file.filePath}`,
        `  Language: ${file.language}`,
        '  Code:',
        indentBlock(file.content, '  ')
    ].join('\n');
}

function indentBlock(value: string, prefix: string): string {
    return value
        .split(/\r?\n/)
        .map(line => `${prefix}${line}`)
        .join('\n');
}
