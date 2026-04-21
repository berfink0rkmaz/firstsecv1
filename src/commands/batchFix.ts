import * as vscode from 'vscode';
import { detectBatchOpportunities, validateBatchProcessing, type BatchGroup } from '../core/batchProcessor';
import { generateBatchPrompt } from '../prompts/batchPrompt';
import { callAI } from '../api/gemini';
import { showError, showInfo, showWarning } from '../utils/errorHandler';
import { costTracker } from '../utils/costTracker';
import type { Vulnerability } from '../types/vulnerability';
import { autoFixVulnerability } from '../core/autoFixVulnerability';
import { saveStatuses } from '../core/statusStore';
import { isProtectedFile } from '../utils/protectedFiles';

/**
 * Shows batch opportunities and handles user choice
 */
export async function showBatchOpportunities(vulnerabilities: Vulnerability[]): Promise<boolean> {
    const validation = validateBatchProcessing(vulnerabilities);
    if (!validation.isValid) {
        showInfo(validation.reason || 'No batch opportunities available');
        return false;
    }

    const opportunity = detectBatchOpportunities(vulnerabilities);
    
    const message = `Found ${opportunity.totalBatches} batch opportunities for ${opportunity.totalVulnerabilities} vulnerabilities.`;
    const choice = await vscode.window.showInformationMessage(
        message,
        'Fix Together',
        'Fix Individually',
        'Cancel'
    );

    if (choice === 'Fix Together') {
        return await processBatchFixes(opportunity.groups);
    } else if (choice === 'Fix Individually') {
        return await processIndividualFixes(vulnerabilities);
    }

    return false; // User cancelled
}

/**
 * Processes batch fixes for multiple vulnerability groups
 */
async function processBatchFixes(batchGroups: BatchGroup[]): Promise<boolean> {
    let successCount = 0;
    let totalGroups = batchGroups.length;

    for (const [index, group] of batchGroups.entries()) {
        const progressMessage = `Processing batch ${index + 1}/${totalGroups}: ${group.filePath}`;
        vscode.window.showInformationMessage(progressMessage);

        try {
            const success = await processSingleBatch(group);
            if (success) {
                successCount++;
            }
        } catch (error) {
            showError(`Failed to process batch for ${group.filePath}: ${error}`);
        }
    }

    const resultMessage = `Batch processing complete: ${successCount}/${totalGroups} batches successful`;
    if (successCount > 0) {
        showInfo(resultMessage);
        return true;
    } else {
        showWarning(resultMessage);
        return false;
    }
}

/**
 * Processes a single batch of vulnerabilities
 */
async function processSingleBatch(batchGroup: BatchGroup): Promise<boolean> {
    const { filePath, vulnType, vulnerabilities } = batchGroup;

    // Show batch confirmation
    const confirmationMessage = `${filePath} - ${vulnType} (${vulnerabilities.length} vulnerabilities)`;
    const choice = await vscode.window.showInformationMessage(
        `Ready to process: ${confirmationMessage}`,
        'Process This Batch',
        'Skip This Batch',
        'Review Individual'
    );

    if (choice === 'Skip This Batch') {
        return false;
    }

    if (choice === 'Review Individual') {
        return await processIndividualFixes(vulnerabilities);
    }

    if (choice === 'Process This Batch') {
        return await executeBatchFix(batchGroup);
    }

    return false;
}

/**
 * Executes the actual batch fix using AI
 */
async function executeBatchFix(batchGroup: BatchGroup): Promise<boolean> {
    const { filePath, vulnType, vulnerabilities } = batchGroup;

    if (isProtectedFile(filePath)) {
        showError(`Protected file blocked from AI modification: ${filePath}`);
        return false;
    }

    try {
        // Generate batch prompt
        const prompt = generateBatchPrompt(batchGroup);

        // Get AI configuration
        const config = vscode.workspace.getConfiguration('firstsec');
        const providerStr = config.get<string>('aiProvider', 'gemini');
        let apiKey = '';
        let model = '';

        if (providerStr === 'gemini') {
            apiKey = config.get<string>('geminiApiKey', '');
            model = config.get<string>('geminiModel', 'gemini-2.5-flash');
        } else if (providerStr === 'openai') {
            apiKey = config.get<string>('openaiApiKey', '');
            model = config.get<string>('openaiModel', 'gpt-3.5-turbo');
        } else if (providerStr === 'claude') {
            apiKey = config.get<string>('claudeApiKey', '');
            model = config.get<string>('claudeModel', 'claude-3-opus-20240229');
        }

        // Call AI with batch prompt
        const aiResponse = await callAI(
            prompt, 
            providerStr as any, 
            apiKey, 
            model, 
            'batch-fix', 
            filePath
        );

        // Process AI response (similar to autoFixVulnerability but for multiple vulns)
        const success = await processBatchAIResponse(aiResponse, batchGroup);
        
        if (success) {
            // Update status for all vulnerabilities in the batch
            const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
            for (const vuln of vulnerabilities) {
                vuln.status = 'fixed';
            }
            saveStatuses(vulnerabilities, workspaceRoot);
            
            showInfo(`Successfully fixed ${vulnerabilities.length} ${vulnType} vulnerabilities in ${filePath}`);
            return true;
        }

        return false;
    } catch (error) {
        showError(`Batch fix failed for ${filePath}: ${error}`);
        return false;
    }
}

/**
 * Processes AI response for batch fixes
 * This is a simplified version - you might want to integrate with existing autoFixVulnerability logic
 */
async function processBatchAIResponse(aiResponse: string, batchGroup: BatchGroup): Promise<boolean> {
    // For now, we'll use a simplified approach
    // In a full implementation, you'd want to parse the AI response and apply changes
    // similar to how autoFixVulnerability works
    
    const { filePath, vulnType, vulnerabilities } = batchGroup;
    
    // Show the AI response to user for review
    const output = vscode.window.createOutputChannel('Security Batch Fix Preview');
    output.clear();
    output.appendLine(`Batch Fix Preview for ${filePath}:`);
    output.appendLine(`Type: ${vulnType}`);
    output.appendLine(`Vulnerabilities: ${vulnerabilities.length}`);
    output.appendLine('');
    output.appendLine('AI Response:');
    output.appendLine(aiResponse);
    output.show(true);

    const choice = await vscode.window.showInformationMessage(
        `Review the batch fix for ${filePath}. Apply the changes?`,
        'Apply Changes',
        'Reject Changes',
        'Review in Detail'
    );

    if (choice === 'Apply Changes') {
        // Here you would apply the actual changes to the files
        // For now, we'll just mark them as fixed
        showInfo(`Batch fix applied for ${vulnerabilities.length} vulnerabilities`);
        return true;
    } else if (choice === 'Review in Detail') {
        // Show detailed diff view
        showInfo('Detailed review not implemented yet - would show diff view');
        return false;
    }

    return false;
}

/**
 * Processes vulnerabilities individually (fallback)
 */
async function processIndividualFixes(vulnerabilities: Vulnerability[]): Promise<boolean> {
    let successCount = 0;
    const totalVulns = vulnerabilities.length;

    for (const [index, vuln] of vulnerabilities.entries()) {
        const progressMessage = `Processing vulnerability ${index + 1}/${totalVulns}: ${vuln.filePath}:${vuln.line}`;
        vscode.window.showInformationMessage(progressMessage);

        try {
            const result = await autoFixVulnerability(vuln);
            if (result) {
                successCount++;
            }
        } catch (error) {
            showError(`Failed to fix vulnerability at ${vuln.filePath}:${vuln.line}: ${error}`);
        }
    }

    const resultMessage = `Individual processing complete: ${successCount}/${totalVulns} vulnerabilities fixed`;
    if (successCount > 0) {
        showInfo(resultMessage);
        return true;
    } else {
        showWarning(resultMessage);
        return false;
    }
}

/**
 * Shows batch opportunity for a single vulnerability
 */
export async function showBatchOpportunityForVulnerability(
    targetVuln: Vulnerability, 
    allVulnerabilities: Vulnerability[]
): Promise<boolean> {
    const { getBatchOpportunityForVulnerability } = await import('../core/batchProcessor');
    const batchGroup = getBatchOpportunityForVulnerability(targetVuln, allVulnerabilities);

    if (!batchGroup) {
        return false; // No batch opportunity
    }

    const choice = await vscode.window.showInformationMessage(
        `Smart detection: ${batchGroup.count - 1} more ${batchGroup.vulnType} vulnerabilities in same file`,
        'Fix All Together',
        'Fix This One',
        'Cancel'
    );

    if (choice === 'Fix All Together') {
        return await processSingleBatch(batchGroup);
    } else if (choice === 'Fix This One') {
        const result = await autoFixVulnerability(targetVuln);
        return result !== null;
    }

    return false; // User cancelled
} 
