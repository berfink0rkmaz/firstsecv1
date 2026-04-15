import { showInfo, showError } from '../utils/errorHandler';
import * as vscode from 'vscode';

export let currentStatusFilter: 'open' | 'fixed' | 'false_positive' | 'needs_attention' | 'all' = 'all';

export function setStatusFilter(value: 'open' | 'fixed' | 'false_positive' | 'needs_attention' | 'all') {
    currentStatusFilter = value;
}

export async function filterByStatus(provider: any) {
    try {
        await showInfo('Filter By Status command triggered');
        const status = await vscode.window.showQuickPick(
            ['all', 'open', 'fixed', 'false_positive', 'needs_attention'],
            { placeHolder: 'Filter vulnerabilities by status' }
        );
        if (status) {
            currentStatusFilter = status as 'open' | 'fixed' | 'false_positive' | 'needs_attention' | 'all';
            provider.refresh();
        }
    } catch (err) {
        showError('Failed to filter by status.', err);
    }
} 