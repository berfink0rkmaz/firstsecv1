export function generatePrompt(issue: any): string {
  return `
You are a software security expert. A vulnerability has been detected in the following Java code:

📂 File: ${issue.Filepath}
📍 Line: ${issue.Loc}
🧨 Type: ${issue.Finding}
📝 Summary: ${issue.Summary}

🔍 Here's what I expect from you:
1. Explain clearly what the security problem is.
2. The project uses a **layered architecture**: Controller → Service → Repository. Based on the issue type, analyze **which layers are affected**, and adjust your fix accordingly.
3. Apply corrections in **all necessary layers**, not just superficially:
   - For example, if it's a SQL injection: sanitize in Service and fix the query in Repository.
   - If it's input validation: validate in Controller, but move business logic to Service if needed.
   - Do NOT delete or replace unrelated code. Only change the lines that are necessary to fix the vulnerability. Never delete large portions of a file. If you are unsure, do not change the file.
   - Do NOT replace the entire file unless it is absolutely necessary for the fix. If you must, explain why in a comment at the top of the code block.
4. Return **full, clean code blocks for each affected file**, ready to be copied into the project.

🔐 Vulnerable Code Snippet:
------------------
\${code}
------------------

Respond in the following format (only return actual Java code in blocks, no extra commentary):

# Explanation:
...

# controller/SomeController.java
\`\`\`java
// fixed controller layer
\`\`\`

# service/SomeService.java
\`\`\`java
// fixed service layer
\`\`\`

# repository/SomeRepository.java
\`\`\`java
// fixed repository layer
\`\`\`
`;
}