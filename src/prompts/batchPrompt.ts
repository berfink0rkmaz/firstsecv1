import type { BatchGroup } from '../core/batchProcessor';

export function generateBatchPrompt(batchGroup: BatchGroup): string {
    const { filePath, vulnType, vulnerabilities } = batchGroup;

    const findings = vulnerabilities
        .map(v => `Line ${v.line}: ${v.codeSnippet}`)
        .join('\n\n');

    return `
Fix the selected security vulnerabilities in this file.

Before writing any code, determine internally:
1. the shared vulnerability type or pattern,
2. the vulnerable sinks or unsafe APIs,
3. the untrusted inputs or sources that reach them, if any,
4. the secure remediation pattern that should be applied consistently,
5. the smallest set of code changes needed to fix all listed findings without changing business logic.

Then apply the fix using one consistent secure coding approach across all listed findings.

TARGET FILE
File: ${filePath}
Vulnerability Type: ${vulnType}
Count: ${vulnerabilities.length}

VULNERABLE CODE
${findings}

Important rules:
- Fix only the listed vulnerabilities.
- Fix the actual vulnerable sinks, not unrelated code.
- Change only the code that is necessary for the fix.
- Do not modify a different function by mistake.
- Do not delete any function.
- Do not delete business logic.
- Do not replace real logic with an empty body, placeholder, null, or a trivial return.
- Do not rewrite the whole file unless absolutely necessary.
- Do not add dead code or commented-out code.
- Do not add unused variables, unused methods, or unused imports.
- Do not suppress or hide the findings with comments.
- Do not replace one unsafe pattern with another unsafe pattern.
- Use the standard safe library, validation, encoding, parameterization, or authorization pattern normally used for this vulnerability type.
- Preserve the original business behavior.
- Return compilable code only.
- Prefer fixing the smallest relevant methods or statements instead of rewriting the full file.
- Apply one consistent fix pattern to the listed vulnerabilities.
- Prefer a same-file fix if it is secure and sufficient.
- If another file is absolutely necessary, include it. Otherwise do not touch any other file.

Bad fixes include:
- deleting a vulnerable method
- replacing a method body with return, return null, return [], or a constant
- removing unrelated business logic
- rewriting the full class when only a few methods need a fix

OUTPUT RULES
- Return code only.
- Do not include explanations.
- Do not include notes.
- Do not include markdown text except file headers.
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
- Did you fix the actual vulnerable sinks?
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
