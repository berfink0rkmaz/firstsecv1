import type { Vulnerability } from '../types/vulnerability';

export interface BatchGroup {
    filePath: string;
    vulnType: string;
    vulnerabilities: Vulnerability[];
    count: number;
}

export interface BatchOpportunity {
    groups: BatchGroup[];
    totalBatches: number;
    totalVulnerabilities: number;
}

/**
 * Groups vulnerabilities by file path and vulnerability type
 */
export function groupVulnerabilitiesByFileAndType(vulnerabilities: Vulnerability[]): { [filePath: string]: { [vulnType: string]: Vulnerability[] } } {
    const groups: { [filePath: string]: { [vulnType: string]: Vulnerability[] } } = {};
    
    for (const vuln of vulnerabilities) {
        const filePath = vuln.filePath;
        const vulnType = vuln.category;
        
        if (!groups[filePath]) {
            groups[filePath] = {};
        }
        
        if (!groups[filePath][vulnType]) {
            groups[filePath][vulnType] = [];
        }
        
        groups[filePath][vulnType].push(vuln);
    }
    
    return groups;
}

/**
 * Detects batch opportunities from grouped vulnerabilities
 * Returns only groups with 2 or more vulnerabilities
 */
export function detectBatchOpportunities(vulnerabilities: Vulnerability[]): BatchOpportunity {
    const groups = groupVulnerabilitiesByFileAndType(vulnerabilities);
    const batchGroups: BatchGroup[] = [];
    
    for (const [filePath, typeGroups] of Object.entries(groups)) {
        for (const [vulnType, vulns] of Object.entries(typeGroups)) {
            if (vulns.length >= 2) {
                batchGroups.push({
                    filePath,
                    vulnType,
                    vulnerabilities: vulns,
                    count: vulns.length
                });
            }
        }
    }
    
    const totalVulnerabilities = batchGroups.reduce((sum, group) => sum + group.count, 0);
    
    return {
        groups: batchGroups,
        totalBatches: batchGroups.length,
        totalVulnerabilities
    };
}

/**
 * Checks if a specific vulnerability has batch opportunities in the same file
 */
export function getBatchOpportunityForVulnerability(
    targetVuln: Vulnerability, 
    allVulnerabilities: Vulnerability[]
): BatchGroup | null {
    const fileVulns = allVulnerabilities.filter(v => v.filePath === targetVuln.filePath);
    const sameTypeVulns = fileVulns.filter(v => v.category === targetVuln.category);
    
    if (sameTypeVulns.length >= 2) {
        return {
            filePath: targetVuln.filePath,
            vulnType: targetVuln.category,
            vulnerabilities: sameTypeVulns,
            count: sameTypeVulns.length
        };
    }
    
    return null;
}

/**
 * Validates if batch processing is appropriate for the given vulnerabilities
 */
export function validateBatchProcessing(vulnerabilities: Vulnerability[]): { isValid: boolean; reason?: string } {
    if (!vulnerabilities || vulnerabilities.length === 0) {
        return { isValid: false, reason: 'No vulnerabilities provided' };
    }
    
    if (vulnerabilities.length === 1) {
        return { isValid: false, reason: 'Only one vulnerability provided' };
    }
    
    const opportunity = detectBatchOpportunities(vulnerabilities);
    if (opportunity.totalBatches === 0) {
        return { isValid: false, reason: 'No batch opportunities found' };
    }
    
    return { isValid: true };
}

 