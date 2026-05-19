import { showError, showInfo } from '../utils/errorHandler';
import { loadDetectionSnapshot } from '../core/detectWithAi';
import { getLegacyVulnerabilityStatusKey, getVulnerabilityStatusKey, loadStatuses } from '../core/statusStore';
import { setStatusFilter } from './filterByStatus';

let lastWorkspaceRoot: string | null = null;

export function setLastDetectionContext(root: string) {
    lastWorkspaceRoot = root;
}

export async function refreshVulnerabilities(provider: any, setVulnerabilities: any, resetAutoFixCount: any, setTotalVulns: any) {
    if (!lastWorkspaceRoot) {
        showError('No OpenAI detection has been run yet.');
        return;
    }
    try {
        const vulns = loadDetectionSnapshot(lastWorkspaceRoot);
        const statusMap = loadStatuses(lastWorkspaceRoot);
        for (const v of vulns) {
            const key = getVulnerabilityStatusKey(v);
            const legacyKey = getLegacyVulnerabilityStatusKey(v);
            if (statusMap[key]) {
                v.status = statusMap[key] as 'open' | 'fixed' | 'false_positive' | 'needs_attention';
            } else if (statusMap[legacyKey]) {
                v.status = statusMap[legacyKey] as 'open' | 'fixed' | 'false_positive' | 'needs_attention';
            }
        }
        provider.setVulnerabilities(vulns);
        showInfo(`Refreshed ${vulns.length} vulnerabilities from the last OpenAI snapshot.`);
        resetAutoFixCount();
        setTotalVulns(vulns.length);
        // Reset status filter to 'all'
        setStatusFilter('all');
    } catch (e: any) {
        showError('Failed to refresh OpenAI snapshot: ' + (e.message || e));
    }
}
