import { showInfo, showError } from '../utils/errorHandler';
import { saveStatuses } from '../core/statusStore';
import * as vscode from 'vscode';

export async function markFalsePositive(treeView: any, provider: any) {
    try {
        const selected = treeView.selection.filter((item: any) => item && item.vuln) as any[];
        if (!selected.length) {
            showInfo('No vulnerabilities selected.');
            return;
        }
        for (const item of selected) {
            item.vuln.status = 'false_positive';
        }
        provider.refresh();
        // Persist status change
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
        saveStatuses(provider.getAllVulnerabilities(), workspaceRoot);
        showInfo('Marked as false positive.');
    } catch (err) {
        showError('Failed to mark as false positive.', err);
    }
} 