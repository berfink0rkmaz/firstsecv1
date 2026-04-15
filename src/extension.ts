import * as vscode from 'vscode';
import * as path from 'path';
import { detectVulnerabilitiesWithGemini } from './core/geminiDetector';
import { showError, showInfo } from './utils/errorHandler';
import { autoFixAll } from './commands/autoFixAll';
import { autoFixSelected } from './commands/autoFixSelected';
import { markFalsePositive } from './commands/markFalsePositive';
import { undoFalsePositive, undoFalsePositiveSingle, showFalsePositivesForUndo } from './commands/undoFalsePositive';
import { filterByStatus, currentStatusFilter } from './commands/filterByStatus';
import { autoFixVulnerability, setTotalVulns, resetAutoFixCount } from './core/autoFixVulnerability';
import { loadStatuses } from './core/statusStore';
import { refreshVulnerabilities } from './commands/refreshVulnerabilities';
import { showCostReport, exportCostData, clearCostData } from './commands/costReport';
import { showBatchOpportunityForVulnerability, showBatchOpportunities } from './commands/batchFix';
import { detectBatchOpportunities } from './core/batchProcessor';
import { FortifyVulnerabilityProvider, SeverityTreeItem, VulnerabilityTreeItem } from './ui/FortifyVulnerabilityProvider';

export function activate(context: vscode.ExtensionContext) {
    const provider = new FortifyVulnerabilityProvider();
    const treeView = vscode.window.createTreeView('fortifyVulnerabilityExplorer', {
        treeDataProvider: provider,
        canSelectMany: true
    });

    context.subscriptions.push(
        vscode.commands.registerCommand('fortify-plugin-deneme1.loadFprReport', async () => {
            try {
                const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
                if (!workspaceRoot) {
                    showError('Open a workspace folder before running Gemini detection.');
                    return;
                }
                const vulns = await detectVulnerabilitiesWithGemini(workspaceRoot);
                // Merge statuses
                const statusMap = loadStatuses(workspaceRoot);
                for (const v of vulns) {
                    const key = `${v.filePath}:${v.line}`;
                    if (statusMap[key]) v.status = statusMap[key] as 'open' | 'fixed' | 'false_positive' | 'needs_attention';
                }
                provider.setVulnerabilities(vulns);
                showInfo(`Detected ${vulns.length} vulnerabilities with Gemini.`);
                resetAutoFixCount();
                setTotalVulns(vulns.length);

                // Check for batch opportunities and inform user
                const batchOpportunity = detectBatchOpportunities(vulns);
                if (batchOpportunity.totalBatches > 0) {
                    const choice = await vscode.window.showInformationMessage(
                        `Found ${batchOpportunity.totalBatches} batch opportunities for ${batchOpportunity.totalVulnerabilities} vulnerabilities.`,
                        'Enable Batch Mode',
                        'Continue with Individual Mode'
                    );
                    
                    if (choice === 'Enable Batch Mode') {
                        showInfo('Batch mode enabled. Use "Fix All" or "Fix Selected" to process batches efficiently.');
                    }
                }
            } catch (e: any) {
                showError('Failed to detect vulnerabilities with Gemini: ' + (e.message || e));
            }
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.refreshVulnerabilities', async () => {
            await refreshVulnerabilities(provider, provider.setVulnerabilities.bind(provider), resetAutoFixCount, setTotalVulns);
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.showVulnerabilityDetails', async (item: VulnerabilityTreeItem) => {
            const v = item.vuln;
            const buttons = ['Go to Code', 'Auto Fix'];
            
            // Add appropriate status buttons based on current status
            if (v.status === 'false_positive') {
                buttons.push('Undo False Positive');
            } else {
                buttons.push('Mark as False Positive');
            }
            
            const result = await vscode.window.showInformationMessage(
                `Category: ${v.category}\nFile: ${v.filePath}\nLine: ${v.line}\nSeverity: ${v.severity}\nStatus: ${v.status}\nAbstract: ${v.abstract}\nCode Snippet:\n${v.codeSnippet}`,
                { modal: true },
                ...buttons
            );
            if (result === 'Auto Fix') {
                // Check for batch opportunities first
                const allVulns = provider.getAllVulnerabilities ? provider.getAllVulnerabilities() : [];
                const batchSuccess = await showBatchOpportunityForVulnerability(v, allVulns);
                if (!batchSuccess) {
                    // Fall back to individual fix
                    await autoFixVulnerability(v);
                }
            } else if (result === 'Go to Code') {
                const fileUri = vscode.Uri.file(path.resolve(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '', v.filePath));
                const document = await vscode.workspace.openTextDocument(fileUri);
                const editor = await vscode.window.showTextDocument(document);
                const lineIndex = v.line - 1;
                if (lineIndex >= 0 && lineIndex < document.lineCount) {
                    const range = document.lineAt(lineIndex).range;
                    editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
                    editor.selection = new vscode.Selection(range.start, range.end);
                }
            } else if (result === 'Mark as False Positive') {
                await markFalsePositive({ selection: [item] }, provider);
            } else if (result === 'Undo False Positive') {
                await undoFalsePositiveSingle(v, provider);
            }
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.fixAll', async () => {
            await autoFixAll(provider, autoFixVulnerability);
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.fixSelected', async () => {
            await autoFixSelected(treeView, autoFixVulnerability);
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.markFalsePositive', async () => {
            await markFalsePositive(treeView, provider);
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.undoFalsePositive', async () => {
            await undoFalsePositive(treeView, provider);
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.showFalsePositivesForUndo', async () => {
            await showFalsePositivesForUndo(provider);
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.filterByStatus', async () => {
            await filterByStatus(provider);
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.buildProject', async () => {
            const terminal = vscode.window.createTerminal({ name: 'Fortify Build' });
            terminal.show();
            terminal.sendText('mvn clean install');
            vscode.window.showInformationMessage('Build started: mvn clean install');
            // Optionally, you can listen for build completion if you want to parse output, but for now just notify start.
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.showCostReport', async () => {
            await showCostReport();
        }),
        
        vscode.commands.registerCommand('fortify-plugin-deneme1.exportCostData', async () => {
            await exportCostData();
        }),
        vscode.commands.registerCommand('fortify-plugin-deneme1.clearCostData', async () => {
            await clearCostData();
        })
    );
}

export function deactivate() {}
