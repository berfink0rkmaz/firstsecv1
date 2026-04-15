import { Vulnerability } from '../types/vulnerability';

export function getPromptForIssue(issue: Vulnerability): string {
  const trimmedSnippet = issue.codeSnippet.trim();

  return `
You are a senior software security engineer. Your job is to fix the following vulnerability in a real-world, layered-architecture project (e.g., Controller → Service → ServiceImpl → Repository → DTO → Mapper).

**File:** ${issue.filePath}
**Line:** ${issue.line}
**Severity:** ${issue.severity}
**Type:** ${issue.category}
**Description:** ${issue.abstract}

---

### Vulnerable Code
\${issue.language}
${trimmedSnippet}
\

---

### Instructions:
- **Analyze** the code and identify the minimal, correct, and secure fix for the vulnerability.
- **Do NOT** delete, replace, or rewrite unrelated code. Only change the lines that are necessary to fix the vulnerability.
- **Do NOT** replace the entire file unless absolutely necessary. If you must, add a comment at the top: // FULL FILE REPLACEMENT: [reason]
- If the fix requires changes in other layers (Controller, Service, Repository, etc.), include only the minimal necessary changes for those files as well.
- **If you are unsure about a file, do not change it.**
- **Never remove or empty out a file.**
- **Do not add explanations, comments, or extra output. Only return code blocks.**

### Output format:
If only one file is affected:
\${issue.language}
[fixed code here]
\

If multiple files/layers are affected, use this format:
# [relative/path/to/File1]
\${issue.language}
[fixed code for File1]
\

# [relative/path/to/File2]
\${issue.language}
[fixed code for File2]
\
`;
}