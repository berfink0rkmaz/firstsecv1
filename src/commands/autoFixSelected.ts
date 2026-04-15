import { showInfo, showError } from '../utils/errorHandler';
import type { Vulnerability } from '../types/vulnerability';
import { saveStatuses } from '../core/statusStore';
import { showBatchOpportunities } from './batchFix';
import * as vscode from 'vscode';

export async function autoFixSelected(
    treeView: any,
    autoFixVulnerability: (vuln: Vulnerability, provider?: any, dryRun?: boolean) => Promise<string | null>,
    provider?: { getAllVulnerabilities: () => Vulnerability[] }
) {
    const selected = treeView.selection.filter((item: any) => item && item.vuln) as any[];
    if (!selected.length) {
        showInfo('No vulnerabilities selected.');
        return;
    }

    // Extract vulnerabilities from selected items
    const selectedVulns = selected.map((item: any) => item.vuln);

    // Check for batch opportunities first
    const batchSuccess = await showBatchOpportunities(selectedVulns);
    if (batchSuccess) {
        return; // Batch processing was successful
    }
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
    for (const item of selected) {
        try {
            await autoFixVulnerability(item.vuln, provider);
        } catch (err) {
            item.vuln.status = 'needs_attention';
            if (provider) {
                saveStatuses(provider.getAllVulnerabilities(), workspaceRoot);
            }
            showError(`Failed to auto-fix vulnerability at ${item.vuln.filePath}:${item.vuln.line}`, err);
        }
    }
} 