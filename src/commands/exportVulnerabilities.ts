import * as vscode from 'vscode';
import { showError, showInfo } from '../utils/errorHandler';
import type { Vulnerability } from '../types/vulnerability';

type ExportedVulnerability = Pick<
    Vulnerability,
    'category' | 'filePath' | 'line' | 'severity' | 'abstract' | 'codeSnippet' | 'status'
>;

export async function exportVulnerabilities(
    provider: { getAllVulnerabilities: () => Vulnerability[] }
): Promise<void> {
    const vulnerabilities = provider.getAllVulnerabilities();

    if (!vulnerabilities.length) {
        showInfo('No vulnerabilities available to export.');
        return;
    }

    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri;
    const defaultUri = workspaceRoot
        ? vscode.Uri.joinPath(workspaceRoot, `firstsec-vulnerabilities-${new Date().toISOString().slice(0, 10)}.json`)
        : undefined;

    const targetUri = await vscode.window.showSaveDialog({
        defaultUri,
        filters: {
            JSON: ['json']
        },
        saveLabel: 'Export Vulnerabilities'
    });

    if (!targetUri) {
        return;
    }

    const exported: ExportedVulnerability[] = vulnerabilities.map(v => ({
        category: v.category,
        filePath: v.filePath,
        line: v.line,
        severity: v.severity,
        abstract: v.abstract,
        codeSnippet: v.codeSnippet,
        status: v.status
    }));

    try {
        await vscode.workspace.fs.writeFile(
            targetUri,
            Buffer.from(JSON.stringify(exported, null, 2), 'utf-8')
        );

        showInfo(`Exported ${exported.length} vulnerabilities.`);
    } catch (error) {
        showError('Failed to export vulnerabilities.', error);
    }
}
