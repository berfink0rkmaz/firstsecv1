import { showError, showInfo } from '../utils/errorHandler';
import { detectVulnerabilitiesWithGemini } from '../core/detectGemini';
import { loadStatuses } from '../core/statusStore';
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
        const vulns = await detectVulnerabilitiesWithGemini(lastWorkspaceRoot);
        const statusMap = loadStatuses(lastWorkspaceRoot);
        for (const v of vulns) {
            const key = `${v.filePath}:${v.line}`;
            if (statusMap[key]) v.status = statusMap[key] as 'open' | 'fixed' | 'false_positive';
        }
        provider.setVulnerabilities(vulns);
        showInfo(`Refreshed ${vulns.length} vulnerabilities with Gemini detection.`);
        resetAutoFixCount();
        setTotalVulns(vulns.length);
        // Reset status filter to 'all'
        setStatusFilter('all');
    } catch (e: any) {
        showError('Failed to refresh Gemini detection: ' + (e.message || e));
    }
}
