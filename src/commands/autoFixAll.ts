import { showInfo, showError } from '../utils/errorHandler';
import type { Vulnerability } from '../types/vulnerability';
import { saveStatuses } from '../core/statusStore';
import { checkFileSecurity } from '../utils/securityUtils';
import { showBatchOpportunities } from './batchFix';
import * as vscode from 'vscode';

const severityOrder = ['Critical', 'High', 'Medium', 'Low'];

export async function autoFixAll(provider: { getAllVulnerabilities: () => Vulnerability[] }, autoFixVulnerability: (vuln: Vulnerability, provider?: any, dryRun?: boolean) => Promise<string | null>) {
    let allVulns = provider.getAllVulnerabilities ? provider.getAllVulnerabilities() : (provider as any).vulnerabilities || [];
    if (!allVulns.length) {
        showInfo('No vulnerabilities to auto-fix.');
        return;
    }

    // Check for batch opportunities first
    const batchSuccess = await showBatchOpportunities(allVulns);
    if (batchSuccess) {
        return; // Batch processing was successful
    }
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
    for (const severity of severityOrder) {
        const group = allVulns.filter((v: Vulnerability) =>
            v.severity === severity &&
            v.status !== 'false_positive' &&
            v.status !== 'fixed' &&
            v.status !== 'needs_attention'
        );
        if (!group.length) continue;
        // Collect AI suggestions for all in this severity
        const previews: { vuln: Vulnerability, fixedCode: string | null }[] = [];
        for (const vuln of group) {
            // Dry run: get the AI suggestion but do not apply
            const fixedCode = await autoFixVulnerability(vuln, provider, true);
            previews.push({ vuln, fixedCode });
        }
        // Show a summary in the Output panel
        const output = vscode.window.createOutputChannel('Fortify AI Fix Preview');
        output.clear();
        output.appendLine(`AI suggestions for ${severity} vulnerabilities:`);
        for (const { vuln, fixedCode } of previews) {
            output.appendLine(`--- ${vuln.filePath}:${vuln.line} ---`);
            output.appendLine('Original:');
            output.appendLine(vuln.codeSnippet);
            output.appendLine('AI Suggestion:');
            output.appendLine(fixedCode || '[No suggestion]');
            output.appendLine('');
        }
        output.show(true);
        // Ask the user to accept or reject all fixes for this severity
        const userChoice = await vscode.window.showInformationMessage(
            `Apply all AI fixes for ${severity} vulnerabilities?`,
            { modal: true },
            'Accept',
            'Reject'
        );
        if (userChoice !== 'Accept') {
            showInfo(`Skipped all fixes for ${severity} vulnerabilities.`);
            continue;
        }
        // Apply all accepted fixes
        for (const { vuln, fixedCode } of previews) {
            if (fixedCode && fixedCode !== vuln.codeSnippet.trim()) {
                // Security check before applying fix
                const securityCheck = checkFileSecurity(vuln.filePath);
                if (securityCheck.isCritical) {
                    showError(`🚨 SECURITY BLOCKED: Cannot modify critical file ${vuln.filePath}. Skipping this vulnerability.`);
                    vuln.status = 'needs_attention';
                    continue;
                }
                if (securityCheck.isSensitive) {
                    const warningResult = await vscode.window.showWarningMessage(
                        `⚠️ SECURITY WARNING: ${vuln.filePath} is a sensitive file. Continue with fix?`,
                        'Continue',
                        'Skip'
                    );
                    if (warningResult === 'Skip') {
                        vuln.status = 'needs_attention';
                        continue;
                    }
                }
                
                const fileUri = vscode.Uri.file(vuln.filePath);
                const document = await vscode.workspace.openTextDocument(fileUri);
                const editor = await vscode.window.showTextDocument(document);
                const lineIndex = vuln.line - 1;
                await editor.edit(editBuilder => {
                    editBuilder.replace(document.lineAt(lineIndex).range, fixedCode);
                });
                vuln.status = 'fixed';
            } else {
                vuln.status = 'needs_attention';
            }
        }
        saveStatuses(provider.getAllVulnerabilities(), workspaceRoot);
        showInfo(`Applied all fixes for ${severity} vulnerabilities.`);
    }
} 