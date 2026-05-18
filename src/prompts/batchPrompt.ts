import type { BatchGroup } from '../core/batchProcessor';

export function generateBatchPrompt(batchGroup: BatchGroup): string {
    const { filePath, vulnType, vulnerabilities } = batchGroup;

    const findings = vulnerabilities
        .map(v => `Line ${v.line}: ${v.codeSnippet}`)
        .join('\n\n');

    return `
You are fixing multiple vulnerabilities in the SAME file.

Your job is to fix all listed vulnerabilities without damaging the file.

TARGET FILE
File: ${filePath}
Vulnerability Type: ${vulnType}
Count: ${vulnerabilities.length}

VULNERABLE CODE
${findings}

VERY IMPORTANT RULES
- Fix ONLY the listed vulnerabilities.
- Change ONLY the affected parts of the file.
- Do NOT change a different function by mistake.
- Do NOT delete any function.
- Do NOT delete function logic.
- Do NOT replace real logic with an empty body, null, placeholder, or a simple return.
- Do NOT shorten the file by removing code.
- Do NOT rewrite the whole file.
- Keep all existing business logic.
- Keep all unrelated code exactly as it is.
- Apply one consistent fix pattern to the listed vulnerabilities.
- If another file is absolutely necessary, include it. Otherwise do not touch any other file.

OUTPUT RULES
- Return ONLY code blocks.
- Do NOT write explanations.
- Do NOT write notes.
- Do NOT write markdown text except file headers.
- The first file must be exactly this file: ${filePath}

OUTPUT FORMAT

# ${filePath}
\`\`\`${getFileExtension(filePath)}
[fixed code]
\`\`\`

If another file is absolutely required, add:

# relative/path/to/OtherFile.ext
\`\`\`
[fixed code]
\`\`\`

FINAL CHECK BEFORE ANSWERING
- Did you fix only the listed vulnerabilities?
- Did you keep the original logic?
- Did you avoid deleting code?
- Did you avoid replacing code with a trivial return?
- Did you avoid rewriting the whole file?
`;
}

function getFileExtension(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase();
    const extensionMap: { [key: string]: string } = {
        java: 'java',
        js: 'javascript',
        ts: 'typescript',
        py: 'python',
        cs: 'csharp',
        cpp: 'cpp',
        c: 'c',
        go: 'go',
        rb: 'ruby',
        php: 'php',
        kt: 'kotlin',
        scala: 'scala',
        swift: 'swift',
        rs: 'rust'
    };

    return extensionMap[ext || ''] || 'text';
}
