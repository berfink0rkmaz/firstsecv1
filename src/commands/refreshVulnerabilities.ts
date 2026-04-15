import { showError, showInfo } from '../utils/errorHandler';
import { parseFprFile } from '../core/fprParser';
import { loadStatuses } from '../core/statusStore';
import { setStatusFilter } from './filterByStatus';

let lastFprPath: string | null = null;
let lastWorkspaceRoot: string | null = null;

export function setLastFprContext(path: string, root: string) {
    lastFprPath = path;
    lastWorkspaceRoot = root;
}

export async function refreshVulnerabilities(provider: any, setVulnerabilities: any, resetAutoFixCount: any, setTotalVulns: any) {
    if (!lastFprPath || !lastWorkspaceRoot) {
        showError('No FPR file loaded to refresh.');
        return;
    }
    try {
        const vulns = await parseFprFile(lastFprPath, lastWorkspaceRoot);
        const statusMap = loadStatuses(lastWorkspaceRoot);
        for (const v of vulns) {
            const key = `${v.filePath}:${v.line}`;
            if (statusMap[key]) v.status = statusMap[key] as 'open' | 'fixed' | 'false_positive';
        }
        provider.setVulnerabilities(vulns);
        showInfo(`Refreshed vulnerabilities from: ${lastFprPath}`);
        resetAutoFixCount();
        setTotalVulns(vulns.length);
        // Reset status filter to 'all'
        setStatusFilter('all');
    } catch (e: any) {
        showError('Failed to refresh FPR file: ' + (e.message || e));
    }
} 