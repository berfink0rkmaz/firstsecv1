import * as vscode from 'vscode';
import * as path from 'path';
import {
    detectVulnerabilitiesWithGemini as detectVulnerabilitiesWithOpenAI,
    detectVulnerabilitiesInCurrentFile,
    detectVulnerabilitiesInSelection
} from './core/detectGemini';
import { showError, showInfo } from './utils/errorHandler';
import { autoFixAll } from './commands/autoFixAll';
import { autoFixSelected } from './commands/autoFixSelected';
import { markFalsePositive } from './commands/markFalsePositive';
import { undoFalsePositive, undoFalsePositiveSingle, showFalsePositivesForUndo } from './commands/undoFalsePositive';
import { filterByStatus, currentStatusFilter } from './commands/filterByStatus';
import { autoFixVulnerability, setTotalVulns, resetAutoFixCount } from './core/autoFixVulnerability';
import { getLegacyVulnerabilityStatusKey, getVulnerabilityStatusKey, loadStatuses } from './core/statusStore';
import { refreshVulnerabilities, setLastDetectionContext } from './commands/refreshVulnerabilities';
import { showCostReport, exportCostData, clearCostData } from './commands/costReport';
import { showBatchOpportunityForVulnerability, showBatchOpportunities } from './commands/batchFix';
import { detectBatchOpportunities } from './core/batchProcessor';
import { FirstSecVulnerabilityProvider, SeverityTreeItem, VulnerabilityTreeItem } from './ui/FirstSecVulnerabilityProvider';

export function activate(context: vscode.ExtensionContext) {
    const provider = new FirstSecVulnerabilityProvider();
    const treeView = vscode.window.createTreeView('firstsecVulnerabilityExplorer', {
        treeDataProvider: provider,
        canSelectMany: true
    });

    async function runOpenAIScan() {
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
        if (!workspaceRoot) {
            showError('Open a workspace folder before running OpenAI detection.');
            return;
        }

        setLastDetectionContext(workspaceRoot);
        const vulns = await detectVulnerabilitiesWithOpenAI(workspaceRoot);
        applyStoredStatuses(workspaceRoot, vulns);

        provider.setVulnerabilities(vulns);
        showInfo(`Detected ${vulns.length} vulnerabilities with OpenAI.`);
        resetAutoFixCount();
        setTotalVulns(vulns.length);

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
    }

    async function runCurrentFileScan() {
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
        const editor = vscode.window.activeTextEditor;
        if (!workspaceRoot) {
            showError('Open a workspace folder before running OpenAI detection.');
            return;
        }
        if (!editor) {
            showError('Open a file before running the current file scan.');
            return;
        }

        setLastDetectionContext(workspaceRoot);
        const vulns = await detectVulnerabilitiesInCurrentFile(workspaceRoot, editor.document);
        applyStoredStatuses(workspaceRoot, vulns);
        provider.setVulnerabilities(vulns);
        showInfo(`Detected ${vulns.length} vulnerabilities in the current file.`);
        resetAutoFixCount();
        setTotalVulns(vulns.length);
    }

    async function runSelectionScan() {
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
        const editor = vscode.window.activeTextEditor;
        if (!workspaceRoot) {
            showError('Open a workspace folder before running OpenAI detection.');
            return;
        }
        if (!editor) {
            showError('Open a file before running the selection scan.');
            return;
        }
        if (editor.selection.isEmpty) {
            showError('Select some code before running the selection scan.');
            return;
        }

        setLastDetectionContext(workspaceRoot);
        const vulns = await detectVulnerabilitiesInSelection(workspaceRoot, editor.document, editor.selection);
        applyStoredStatuses(workspaceRoot, vulns);
        provider.setVulnerabilities(vulns);
        showInfo(`Detected ${vulns.length} vulnerabilities in the current selection.`);
        resetAutoFixCount();
        setTotalVulns(vulns.length);
    }

    function applyStoredStatuses(workspaceRoot: string, vulns: VulnerabilityTreeItem['vuln'][]) {
        const statusMap = loadStatuses(workspaceRoot);
        for (const v of vulns) {
            const key = getVulnerabilityStatusKey(v);
            const legacyKey = getLegacyVulnerabilityStatusKey(v);
            if (statusMap[key]) {
                v.status = statusMap[key] as 'open' | 'fixed' | 'false_positive' | 'needs_attention';
            } else if (statusMap[legacyKey]) {
                v.status = statusMap[legacyKey] as 'open' | 'fixed' | 'false_positive' | 'needs_attention';
            }
        }
    }

    context.subscriptions.push(
        vscode.commands.registerCommand('firstsec.loadScanReport', async () => {
            try {
                await runOpenAIScan();
            } catch (e: any) {
                showError('Failed to detect vulnerabilities with OpenAI: ' + (e.message || e));
            }
        }),
        vscode.commands.registerCommand('firstsec.rescanWithGemini', async () => {
            try {
                await runOpenAIScan();
            } catch (e: any) {
                showError('Failed to rescan vulnerabilities with OpenAI: ' + (e.message || e));
            }
        }),
        vscode.commands.registerCommand('firstsec.scanCurrentFile', async () => {
            try {
                await runCurrentFileScan();
            } catch (e: any) {
                showError('Failed to scan the current file with OpenAI: ' + (e.message || e));
            }
        }),
        vscode.commands.registerCommand('firstsec.scanCurrentSelection', async () => {
            try {
                await runSelectionScan();
            } catch (e: any) {
                showError('Failed to scan the current selection with OpenAI: ' + (e.message || e));
            }
        }),
        vscode.commands.registerCommand('firstsec.refreshVulnerabilities', async () => {
            await refreshVulnerabilities(provider, provider.setVulnerabilities.bind(provider), resetAutoFixCount, setTotalVulns);
        }),
        vscode.commands.registerCommand('firstsec.showVulnerabilityDetails', async (item: VulnerabilityTreeItem) => {
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
        vscode.commands.registerCommand('firstsec.fixAll', async () => {
            await autoFixAll(provider, autoFixVulnerability);
        }),
        vscode.commands.registerCommand('firstsec.fixSelected', async () => {
            await autoFixSelected(treeView, autoFixVulnerability);
        }),
        vscode.commands.registerCommand('firstsec.markFalsePositive', async () => {
            await markFalsePositive(treeView, provider);
        }),
        vscode.commands.registerCommand('firstsec.undoFalsePositive', async () => {
            await undoFalsePositive(treeView, provider);
        }),
        vscode.commands.registerCommand('firstsec.showFalsePositivesForUndo', async () => {
            await showFalsePositivesForUndo(provider);
        }),
        vscode.commands.registerCommand('firstsec.filterByStatus', async () => {
            await filterByStatus(provider);
        }),
        vscode.commands.registerCommand('firstsec.buildProject', async () => {
            const terminal = vscode.window.createTerminal({ name: 'Security Scan Build' });
            terminal.show();
            terminal.sendText('mvn clean install');
            vscode.window.showInformationMessage('Build started: mvn clean install');
            // Optionally, you can listen for build completion if you want to parse output, but for now just notify start.
        }),
        vscode.commands.registerCommand('firstsec.showCostReport', async () => {
            await showCostReport();
        }),
        
        vscode.commands.registerCommand('firstsec.exportCostData', async () => {
            await exportCostData();
        }),
        vscode.commands.registerCommand('firstsec.clearCostData', async () => {
            await clearCostData();
        })
    );
}

export function deactivate() {}
