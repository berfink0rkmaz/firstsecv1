import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

// Cost per 1K tokens for each provider/model
const COST_PER_1K_TOKENS = {
    gemini: {
        'gemini-1.5-flash-002': 0.075,
        'gemini-1.5-pro-002': 0.375,
        'gemini-1.5-pro': 0.375,
        'gemini-1.5-flash': 0.075,
        'gemini-2.0-flash': 0.075,
        'gemini-2.0-flash-001': 0.075,
        'gemini-2.5-flash': 0.075,
        'gemini-2.5-pro': 0.375
    },
    openai: {
        'gpt-3.5-turbo': 0.0015,
        'gpt-4': 0.03,
        'gpt-4o': 0.005,
        'gpt-4-turbo': 0.01
    },
    claude: {
        'claude-3-opus-20240229': 0.015,
        'claude-3-sonnet-20240229': 0.003,
        'claude-3-haiku-20240307': 0.00025
    }
};

export interface CostEntry {
    timestamp: string;
    provider: string;
    model: string;
    inputTokens: number;
    outputTokens: number;
    totalTokens: number;
    cost: number;
    operation: string;
    filePath?: string;
    success: boolean;
}

export interface CostSummary {
    totalCost: number;
    totalRequests: number;
    totalTokens: number;
    averageCostPerRequest: number;
    costByProvider: { [provider: string]: number };
    costByModel: { [model: string]: number };
    monthlyProjection: number;
    costTrend: 'increasing' | 'decreasing' | 'stable';
}

export interface MonthlyReport {
    month: string;
    totalCost: number;
    totalRequests: number;
    averageCostPerRequest: number;
    topExpensiveOperations: CostEntry[];
    costBreakdown: {
        byProvider: { [provider: string]: number };
        byModel: { [model: string]: number };
        byOperation: { [operation: string]: number };
    };
}

class CostTracker {
    private costData: CostEntry[] = [];
    private costDataPath: string;

    constructor() {
        this.costDataPath = this.getCostDataPath();
        this.loadCostData();
    }

    private getCostDataPath(): string {
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspaceRoot) {
            return path.join(process.cwd(), '.firstsec-costs.json');
        }
        return path.join(workspaceRoot, '.firstsec-costs.json');
    }

    private loadCostData(): void {
        try {
            if (fs.existsSync(this.costDataPath)) {
                const data = fs.readFileSync(this.costDataPath, 'utf-8');
                this.costData = JSON.parse(data);
            }
        } catch (error) {
            console.error('Failed to load cost data:', error);
            this.costData = [];
        }
    }

    private saveCostData(): void {
        try {
            const dir = path.dirname(this.costDataPath);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(this.costDataPath, JSON.stringify(this.costData, null, 2));
        } catch (error) {
            console.error('Failed to save cost data:', error);
        }
    }

    /**
     * Track an API call and calculate its cost
     */
    public trackApiCall(
        provider: string,
        model: string,
        inputTokens: number,
        outputTokens: number,
        operation: string,
        filePath?: string,
        success: boolean = true
    ): number {
        const totalTokens = inputTokens + outputTokens;
        const providerCosts = COST_PER_1K_TOKENS[provider as keyof typeof COST_PER_1K_TOKENS];
        const costPer1K = providerCosts?.[model as keyof typeof providerCosts] || 0.01;
        const cost = (totalTokens / 1000) * costPer1K;

        const entry: CostEntry = {
            timestamp: new Date().toISOString(),
            provider,
            model,
            inputTokens,
            outputTokens,
            totalTokens,
            cost,
            operation,
            filePath,
            success
        };

        this.costData.push(entry);
        this.saveCostData();

        // Log cost warning if expensive
        if (cost > 1.0) {
            vscode.window.showWarningMessage(
                `⚠️ Expensive API call: $${cost.toFixed(2)} for ${operation}`
            );
        }

        return cost;
    }

    /**
     * Get cost summary for the current period
     */
    public getCostSummary(days: number = 30): CostSummary {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);

        const recentData = this.costData.filter(entry => 
            new Date(entry.timestamp) >= cutoffDate
        );

        const totalCost = recentData.reduce((sum, entry) => sum + entry.cost, 0);
        const totalRequests = recentData.length;
        const totalTokens = recentData.reduce((sum, entry) => sum + entry.totalTokens, 0);

        const costByProvider: { [provider: string]: number } = {};
        const costByModel: { [model: string]: number } = {};

        recentData.forEach(entry => {
            costByProvider[entry.provider] = (costByProvider[entry.provider] || 0) + entry.cost;
            costByModel[entry.model] = (costByModel[entry.model] || 0) + entry.cost;
        });

        // Calculate monthly projection
        const daysInMonth = 30;
        const dailyAverage = totalCost / days;
        const monthlyProjection = dailyAverage * daysInMonth;

        // Determine cost trend
        const firstHalf = recentData.slice(0, Math.floor(recentData.length / 2));
        const secondHalf = recentData.slice(Math.floor(recentData.length / 2));
        const firstHalfCost = firstHalf.reduce((sum, entry) => sum + entry.cost, 0);
        const secondHalfCost = secondHalf.reduce((sum, entry) => sum + entry.cost, 0);
        
        let costTrend: 'increasing' | 'decreasing' | 'stable' = 'stable';
        if (secondHalfCost > firstHalfCost * 1.1) costTrend = 'increasing';
        else if (secondHalfCost < firstHalfCost * 0.9) costTrend = 'decreasing';

        return {
            totalCost,
            totalRequests,
            totalTokens,
            averageCostPerRequest: totalRequests > 0 ? totalCost / totalRequests : 0,
            costByProvider,
            costByModel,
            monthlyProjection,
            costTrend
        };
    }

    /**
     * Generate monthly cost report
     */
    public generateMonthlyReport(month: string): MonthlyReport {
        const monthStart = new Date(month + '-01');
        const monthEnd = new Date(monthStart.getFullYear(), monthStart.getMonth() + 1, 0);

        const monthData = this.costData.filter(entry => {
            const entryDate = new Date(entry.timestamp);
            return entryDate >= monthStart && entryDate <= monthEnd;
        });

        const totalCost = monthData.reduce((sum, entry) => sum + entry.cost, 0);
        const totalRequests = monthData.length;

        const costByProvider: { [provider: string]: number } = {};
        const costByModel: { [model: string]: number } = {};
        const costByOperation: { [operation: string]: number } = {};

        monthData.forEach(entry => {
            costByProvider[entry.provider] = (costByProvider[entry.provider] || 0) + entry.cost;
            costByModel[entry.model] = (costByModel[entry.model] || 0) + entry.cost;
            costByOperation[entry.operation] = (costByOperation[entry.operation] || 0) + entry.cost;
        });

        // Get top 5 most expensive operations
        const topExpensiveOperations = monthData
            .sort((a, b) => b.cost - a.cost)
            .slice(0, 5);

        return {
            month,
            totalCost,
            totalRequests,
            averageCostPerRequest: totalRequests > 0 ? totalCost / totalRequests : 0,
            topExpensiveOperations,
            costBreakdown: {
                byProvider: costByProvider,
                byModel: costByModel,
                byOperation: costByOperation
            }
        };
    }

    /**
     * Get cost estimate for an operation
     */
    public estimateCost(provider: string, model: string, estimatedTokens: number): number {
        const providerCosts = COST_PER_1K_TOKENS[provider as keyof typeof COST_PER_1K_TOKENS];
        const costPer1K = providerCosts?.[model as keyof typeof providerCosts] || 0.01;
        return (estimatedTokens / 1000) * costPer1K;
    }

    /**
     * Clear cost data (for testing or privacy)
     */
    public clearCostData(): void {
        this.costData = [];
        this.saveCostData();
    }

    /**
     * Export cost data to CSV
     */
    public exportToCSV(): string {
        const headers = ['Timestamp', 'Provider', 'Model', 'Input Tokens', 'Output Tokens', 'Total Tokens', 'Cost', 'Operation', 'File Path', 'Success'];
        const rows = this.costData.map(entry => [
            entry.timestamp,
            entry.provider,
            entry.model,
            entry.inputTokens,
            entry.outputTokens,
            entry.totalTokens,
            entry.cost.toFixed(4),
            entry.operation,
            entry.filePath || '',
            entry.success
        ]);

        return [headers, ...rows].map(row => row.join(',')).join('\n');
    }
}

// Singleton instance
export const costTracker = new CostTracker(); 
