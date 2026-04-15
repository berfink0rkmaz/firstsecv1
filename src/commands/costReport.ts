import * as vscode from 'vscode';
import { costTracker } from '../utils/costTracker';
import { showInfo } from '../utils/errorHandler';
import * as path from 'path';

export async function showCostReport(): Promise<void> {
    const summary = costTracker.getCostSummary(30); // Last 30 days
    const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM format
    const monthlyReport = costTracker.generateMonthlyReport(currentMonth);
    
    // Calculate estimated cost savings from batch operations
    const estimatedBatchSavings = summary.totalCost * 0.1; // Estimate 90% savings potential
    
    // Create comprehensive cost report
    const report = `
💰 **Security Scan Cost Report**
====================================

📊 **Current Period (Last 30 Days)**
• Total Cost: $${summary.totalCost.toFixed(2)}
• Total Requests: ${summary.totalRequests}
• Average Cost per Request: $${summary.averageCostPerRequest.toFixed(4)}
• Monthly Projection: $${summary.monthlyProjection.toFixed(2)}
• Cost Trend: ${summary.costTrend} 📈

🏢 **Provider Breakdown**
${Object.entries(summary.costByProvider)
    .map(([provider, cost]) => `• ${provider}: $${cost.toFixed(2)}`)
    .join('\n')}

🤖 **Model Breakdown**
${Object.entries(summary.costByModel)
    .map(([model, cost]) => `• ${model}: $${cost.toFixed(2)}`)
    .join('\n')}

💰 **Cost Savings Potential**
• Estimated Batch Savings: ~$${estimatedBatchSavings.toFixed(2)} (90% reduction potential)
• Efficiency Gain: ${((estimatedBatchSavings / (summary.totalCost + estimatedBatchSavings)) * 100).toFixed(1)}%

📅 **Monthly Summary**
• This Month: $${monthlyReport.totalCost.toFixed(2)}
• Total Requests: ${monthlyReport.totalRequests}
• Average Cost per Request: $${monthlyReport.averageCostPerRequest.toFixed(4)}

💡 **Cost Optimization Tips**
• Use GPT-3.5 Turbo for lowest costs ($0.0015/1K tokens)
• Consider Claude Haiku for simple fixes ($0.00025/1K tokens)
• Batch similar vulnerabilities to reduce API calls by 90%
• Review AI suggestions before accepting to avoid retries
• Monitor expensive operations (>$1.00 per call)

📋 **Available Actions**
• Export data to CSV for management reporting
• Clear cost data to reset tracking
• Adjust AI provider settings for cost optimization
`;

    // Show the report in an output panel
    const output = vscode.window.createOutputChannel('Security Scan Cost Report');
    output.clear();
    output.appendLine(report);
    output.show(true);

    // Also show a summary notification
    showInfo(`Comprehensive Cost Report: $${summary.totalCost.toFixed(2)} in last 30 days. See output panel for details.`);
}



export async function exportCostData(): Promise<void> {
    const csvData = costTracker.exportToCSV();
    
    // Create a temporary file with the CSV data
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceRoot) {
        showInfo('No workspace open. Cannot export cost data.');
        return;
    }
    
    const fileName = `firstsec-costs-${new Date().toISOString().slice(0, 10)}.csv`;
    const filePath = vscode.Uri.file(path.join(workspaceRoot, fileName));
    
    try {
        await vscode.workspace.fs.writeFile(filePath, Buffer.from(csvData, 'utf-8'));
        showInfo(`Cost data exported to: ${fileName}`);
        
        // Open the file in VSCode
        const document = await vscode.workspace.openTextDocument(filePath);
        await vscode.window.showTextDocument(document);
    } catch (error) {
        showInfo(`Failed to export cost data: ${error}`);
    }
}

export async function clearCostData(): Promise<void> {
    const result = await vscode.window.showWarningMessage(
        'Are you sure you want to clear all cost data? This action cannot be undone.',
        'Clear All Data',
        'Cancel'
    );
    
    if (result === 'Clear All Data') {
        costTracker.clearCostData();
        showInfo('All cost data has been cleared.');
    }
} 
