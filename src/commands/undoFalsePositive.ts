import * as vscode from 'vscode';
import { showInfo, showError } from '../utils/errorHandler';
import { saveStatuses } from '../core/statusStore';
import type { Vulnerability } from '../types/vulnerability';

/**
 * Undoes false positive markings for selected vulnerabilities
 */
export async function undoFalsePositive(
    treeView: any,
    provider?: { getAllVulnerabilities: () => Vulnerability[] }
): Promise<void> {
    const selected = treeView.selection.filter((item: any) => item && item.vuln) as any[];
    
    if (!selected.length) {
        showInfo('No vulnerabilities selected.');
        return;
    }

    // Filter only false positive vulnerabilities
    const falsePositiveItems = selected.filter((item: any) => item.vuln.status === 'false_positive');
    
    if (!falsePositiveItems.length) {
        showInfo('No false positive vulnerabilities selected. Only vulnerabilities marked as "False Positive" can be undone.');
        return;
    }

    // Show confirmation with count
    const count = falsePositiveItems.length;
    const choice = await vscode.window.showInformationMessage(
        `Undo false positive marking for ${count} vulnerability${count > 1 ? 'ies' : ''}?`,
        'Undo False Positive',
        'Cancel'
    );

    if (choice !== 'Undo False Positive') {
        return;
    }

    // Update status back to 'open'
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
    let updatedCount = 0;

    for (const item of falsePositiveItems) {
        try {
            item.vuln.status = 'open';
            updatedCount++;
        } catch (err) {
            showError(`Failed to undo false positive for ${item.vuln.filePath}:${item.vuln.line}`, err);
        }
    }

    // Save updated statuses
    if (provider && updatedCount > 0) {
        saveStatuses(provider.getAllVulnerabilities(), workspaceRoot);
    }

    showInfo(`Successfully undone false positive marking for ${updatedCount} vulnerability${updatedCount > 1 ? 'ies' : ''}.`);
}

/**
 * Undoes false positive marking for a single vulnerability
 */
export async function undoFalsePositiveSingle(vulnerability: Vulnerability, provider?: { getAllVulnerabilities: () => Vulnerability[] }): Promise<void> {
    if (vulnerability.status !== 'false_positive') {
        showInfo('This vulnerability is not marked as false positive.');
        return;
    }

    const choice = await vscode.window.showInformationMessage(
        `Undo false positive marking for vulnerability at ${vulnerability.filePath}:${vulnerability.line}?`,
        'Undo False Positive',
        'Cancel'
    );

    if (choice !== 'Undo False Positive') {
        return;
    }

    try {
        vulnerability.status = 'open';
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
        
        if (provider) {
            saveStatuses(provider.getAllVulnerabilities(), workspaceRoot);
        }

        showInfo('False positive marking undone successfully.');
    } catch (err) {
        showError(`Failed to undo false positive marking: ${err}`);
    }
}

/**
 * Shows all false positive vulnerabilities for bulk undo
 */
export async function showFalsePositivesForUndo(
    provider?: { getAllVulnerabilities: () => Vulnerability[] }
): Promise<void> {
    if (!provider) {
        showError('Provider not available.');
        return;
    }

    const allVulns = provider.getAllVulnerabilities();
    const falsePositives = allVulns.filter(v => v.status === 'false_positive');

    if (!falsePositives.length) {
        showInfo('No false positive vulnerabilities found.');
        return;
    }

    // Create quick pick items for false positives
    const items = falsePositives.map(vuln => ({
        label: `${vuln.category} - ${vuln.filePath}:${vuln.line}`,
        description: vuln.abstract,
        detail: `Severity: ${vuln.severity}`,
        vuln: vuln
    }));

    const selected = await vscode.window.showQuickPick(items, {
        placeHolder: 'Select false positive vulnerabilities to undo',
        canPickMany: true
    });

    if (!selected || selected.length === 0) {
        return;
    }

    // Confirm bulk undo
    const choice = await vscode.window.showInformationMessage(
        `Undo false positive marking for ${selected.length} vulnerability${selected.length > 1 ? 'ies' : ''}?`,
        'Undo All Selected',
        'Cancel'
    );

    if (choice !== 'Undo All Selected') {
        return;
    }

    // Update statuses
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
    let updatedCount = 0;

    for (const item of selected) {
        try {
            item.vuln.status = 'open';
            updatedCount++;
        } catch (err) {
            showError(`Failed to undo false positive for ${item.vuln.filePath}:${item.vuln.line}`, err);
        }
    }

    // Save updated statuses
    if (updatedCount > 0) {
        saveStatuses(allVulns, workspaceRoot);
    }

    showInfo(`Successfully undone false positive marking for ${updatedCount} vulnerability${updatedCount > 1 ? 'ies' : ''}.`);
} 