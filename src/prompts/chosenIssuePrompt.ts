import { Vulnerability } from '../types/vulnerability';

export function getPromptForIssue(issue: Vulnerability): string {
  const trimmedSnippet = issue.codeSnippet.trim();

  return `
Fix the selected security vulnerability.

Before writing any code, determine internally:
1. the vulnerability type,
2. the exact vulnerable sink or unsafe API,
3. the untrusted input or source that reaches it, if any,
4. the secure remediation pattern normally used for this vulnerability type,
5. the smallest code change that fixes it without changing business logic.

Then apply the fix using the standard secure coding approach for that vulnerability type.

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

Important rules:
- Fix the actual vulnerable sink, not unrelated code.
- Change only the code that is necessary for the fix.
- Do not modify a different function, class, or layer unless it is required for the fix.
- Do not delete any function.
- Do not delete business logic.
- Do not replace real logic with an empty body, placeholder, null, or a trivial return.
- Do not rewrite the whole file unless absolutely necessary.
- Do not add dead code or commented-out code.
- Do not add unused variables, unused methods, or unused imports.
- Do not suppress, hide, or silence the finding with comments or annotations.
- Do not replace one unsafe pattern with another unsafe pattern.
- Use the standard safe library, validation, encoding, parameterization, or authorization pattern normally used for this vulnerability type.
- Preserve the original business behavior.
- Return compilable code only.
- If you are not sure, make the smallest safe fix.
- Prefer a same-file fix if it is secure and sufficient.
- If a second file is absolutely necessary, include it. Otherwise do not touch any other file.

Bad fixes include:
- deleting the vulnerable method
- replacing the method body with return, return null, return [], or a constant
- removing validation or business logic unrelated to the issue
- rewriting the full class when only one method needs a fix

Output rules:
- Return code only.
- Do not include explanations.
- Do not include notes.
- Do not include markdown text except file headers.
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
- Did you fix the actual vulnerable sink?
- Did you fix the correct function?
- Did you keep the original logic?
- Did you avoid deleting code?
- Did you avoid replacing code with a trivial return?
- Did you avoid rewriting the whole file?
`;
}
