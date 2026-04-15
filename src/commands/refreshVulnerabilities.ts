import { showError, showInfo } from '../utils/errorHandler';
import { loadDetectionSnapshot } from '../core/detectGemini';
import { getLegacyVulnerabilityStatusKey, getVulnerabilityStatusKey, loadStatuses } from '../core/statusStore';
import { setStatusFilter } from './filterByStatus';

let lastWorkspaceRoot: string | null = null;

export function setLastDetectionContext(root: string) {
    lastWorkspaceRoot = root;
}

export async function refreshVulnerabilities(provider: any, setVulnerabilities: any, resetAutoFixCount: any, setTotalVulns: any) {
    if (!lastWorkspaceRoot) {
        showError('No Gemini detection has been run yet.');
        return;
    }
    try {
        const vulns = loadDetectionSnapshot(lastWorkspaceRoot);
        const statusMap = loadStatuses(lastWorkspaceRoot);
        for (const v of vulns) {
            const key = getVulnerabilityStatusKey(v);
            const legacyKey = getLegacyVulnerabilityStatusKey(v);
            if (statusMap[key]) {
                v.status = statusMap[key] as 'open' | 'fixed' | 'false_positive';
            } else if (statusMap[legacyKey]) {
                v.status = statusMap[legacyKey] as 'open' | 'fixed' | 'false_positive';
            }
        }
        provider.setVulnerabilities(vulns);
        showInfo(`Refreshed ${vulns.length} vulnerabilities from the last Gemini snapshot.`);
        resetAutoFixCount();
        setTotalVulns(vulns.length);
        // Reset status filter to 'all'
        setStatusFilter('all');
    } catch (e: any) {
        showError('Failed to refresh Gemini snapshot: ' + (e.message || e));
    }
}
