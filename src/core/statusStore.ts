import * as fs from 'fs';
import * as path from 'path';
import type { Vulnerability } from '../types/vulnerability';

const STATUS_FILE = '.firstsec-status.json';

function getStatusFilePath(workspaceRoot: string) {
    return path.join(workspaceRoot, STATUS_FILE);
}

export function getVulnerabilityStatusKey(vuln: Pick<Vulnerability, 'filePath' | 'line' | 'category' | 'abstract'>): string {
    return `${vuln.filePath}:${vuln.line}:${vuln.category}:${vuln.abstract}`;
}

export function getLegacyVulnerabilityStatusKey(vuln: Pick<Vulnerability, 'filePath' | 'line'>): string {
    return `${vuln.filePath}:${vuln.line}`;
}

export function saveStatuses(vulns: Vulnerability[], workspaceRoot: string) {
    const statusMap: Record<string, string> = {};
    for (const v of vulns) {
        statusMap[getVulnerabilityStatusKey(v)] = v.status;
    }
    fs.writeFileSync(getStatusFilePath(workspaceRoot), JSON.stringify(statusMap, null, 2), 'utf-8');
}

export function loadStatuses(workspaceRoot: string): Record<string, string> {
    const filePath = getStatusFilePath(workspaceRoot);
    if (!fs.existsSync(filePath)) return {};
    try {
        const raw = fs.readFileSync(filePath, 'utf-8');
        return JSON.parse(raw);
    } catch {
        return {};
    }
} 
