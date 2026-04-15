import * as fs from 'fs';
import * as path from 'path';
import JSZip from 'jszip';
import { parseStringPromise } from 'xml2js';
import type { Vulnerability } from '../types/vulnerability';

export async function parseFprFile(fprPath: string, workspaceRoot: string): Promise<Vulnerability[]> {
    const fileContent = fs.readFileSync(fprPath);
    const zip = await JSZip.loadAsync(fileContent);
    const fvdlFile = zip.file('audit.fvdl');
    if (!fvdlFile) throw new Error('audit.fvdl not found in .fpr');
    const fvdlContent = await fvdlFile.async('string');
    const parsedXml = await parseStringPromise(fvdlContent);
    const issues = parsedXml.FVDL?.Vulnerabilities?.[0]?.Vulnerability;
    if (!issues || !Array.isArray(issues)) {
        return [];
    }
    async function getSnippetFromLocation(locationNode: any, zip: JSZip): Promise<string> {
        const snippetAttribute = locationNode?.$?.snippet;
        if (!snippetAttribute) return '';
        const [hash] = snippetAttribute.split('#');
        if (!hash) return '';
        const snippetFile = zip.file(`Snippets/${hash}`);
        if (snippetFile) {
            const content = await snippetFile.async('string');
            return content.trim();
        }
        return '';
    }
    const vulnerabilities: Vulnerability[] = [];
    for (const issue of issues) {
        const primaryLocationNode = issue.AnalysisInfo?.[0]?.Unified?.[0]?.Trace?.[0]?.Primary?.[0]?.Entry?.[0]?.Node?.[0]?.SourceLocation?.[0];
        const classInfo = issue.ClassInfo?.[0];
        const instanceInfo = issue.InstanceInfo?.[0];
        if (!primaryLocationNode || !classInfo || !instanceInfo) continue;
        const primaryLocation = primaryLocationNode.$;
        const rawSeverity = instanceInfo.InstanceSeverity?.[0];
        let fullFileContent = '';
        try {
            const fullFilePath = path.resolve(workspaceRoot, primaryLocation.path);
            fullFileContent = fs.readFileSync(fullFilePath, 'utf-8');
        } catch {
            fullFileContent = '';
        }
        // Extract code snippet if available
        let codeSnippet = await getSnippetFromLocation(primaryLocationNode, zip);
        if (!codeSnippet) {
            // fallback: try to extract the line from the file
            if (fullFileContent) {
                const lines = fullFileContent.split(/\r?\n/);
                codeSnippet = lines[parseInt(primaryLocation.line, 10) - 1] || '';
            } else {
                codeSnippet = '';
            }
        }
        const normalizedSeverity = normalizeSeverity(rawSeverity);
        
        vulnerabilities.push({
            category: classInfo.Type?.[0] ?? 'Unknown Category',
            filePath: primaryLocation.path,
            line: parseInt(primaryLocation.line, 10),
            severity: normalizedSeverity,
            language: path.extname(primaryLocation.path).substring(1) || 'plaintext',
            codeSnippet: codeSnippet,
            abstract: classInfo.Subtype?.[0] ?? classInfo.Type?.[0] ?? 'No abstract available.',
            fullFileContent: fullFileContent,
            status: 'open',
        });
    }
    return vulnerabilities;
}

function normalizeSeverity(severityString: string): Vulnerability['severity'] {
    if (!severityString) return 'Low';
    const severity = parseFloat(severityString);
    if (isNaN(severity)) return 'Low';
    if (severity >= 4.5) return 'Critical';
    if (severity >= 3.0) return 'High';
    if (severity >= 2.0) return 'Medium';
    return 'Low';
} 