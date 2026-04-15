import type { Vulnerability } from '../types/vulnerability';

export function groupBySeverity(vulns: Vulnerability[]): { [key: string]: Vulnerability[] } {
    const groups: { [key: string]: Vulnerability[] } = { Critical: [], High: [], Medium: [], Low: [] };
    for (const v of vulns) {
        if (groups[v.severity]) groups[v.severity].push(v);
    }
    return groups;
}

export function getSortedSeverityKeys(grouped: { [key: string]: Vulnerability[] }): string[] {
    const severityOrder = ['Critical', 'High', 'Medium', 'Low'];
    return severityOrder.filter(key => grouped[key]?.length > 0);
}