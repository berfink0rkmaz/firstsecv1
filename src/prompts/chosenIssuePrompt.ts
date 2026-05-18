import { Vulnerability } from '../types/vulnerability';

export function getPromptForIssue(issue: Vulnerability): string {
  const trimmedSnippet = issue.codeSnippet.trim();

  return `
You are fixing ONE security vulnerability.

Your job is to fix the vulnerability without damaging the file.

VULNERABILITY DETAILS
File: ${issue.filePath}
Line: ${issue.line}
Language: ${issue.language}
Severity: ${issue.severity}
Category: ${issue.category}
Description: ${issue.abstract}

VULNERABLE CODE
\`\`\`${issue.language}
${trimmedSnippet}
\`\`\`

VERY IMPORTANT RULES
- Change ONLY the vulnerable code.
- Do NOT change a different function.
- Do NOT delete any function.
- Do NOT delete function logic.
- Do NOT replace real logic with an empty body, null, placeholder, or a simple return.
- Do NOT shorten the file by removing code.
- Do NOT rewrite the whole file.
- Do NOT remove imports, methods, classes, or validations unless the vulnerability fix truly requires it.
- Keep all existing business logic.
- Keep all unrelated code exactly as it is.
- If you are not sure, make the smallest safe fix.
- If a second file is absolutely necessary, include it. Otherwise do not touch any other file.

OUTPUT RULES
- Return ONLY code blocks.
- Do NOT write explanations.
- Do NOT write notes.
- Do NOT write markdown text except file headers.
- The first file must be exactly this file: ${issue.filePath}

OUTPUT FORMAT

# ${issue.filePath}
\`\`\`${issue.language}
[fixed code]
\`\`\`

If another file is absolutely required, add:

# relative/path/to/OtherFile.ext
\`\`\`
[fixed code]
\`\`\`

FINAL CHECK BEFORE ANSWERING
- Did you fix the correct function?
- Did you keep the original logic?
- Did you avoid deleting code?
- Did you avoid replacing code with a trivial return?
- Did you avoid rewriting the whole file?
`;
}
