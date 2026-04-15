import * as fs from 'fs';
import * as path from 'path';
import type { Vulnerability } from '../types/vulnerability';

const STATUS_FILE = '.firstsec-status.json';

function getStatusFilePath(workspaceRoot: string) {
    return path.join(workspaceRoot, STATUS_FILE);
}

export function saveStatuses(vulns: Vulnerability[], workspaceRoot: string) {
    const statusMap: Record<string, string> = {};
    for (const v of vulns) {
        // Use filePath:line as a unique key
        statusMap[`${v.filePath}:${v.line}`] = v.status;
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
