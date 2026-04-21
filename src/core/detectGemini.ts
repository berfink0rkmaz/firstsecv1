import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { callAI } from '../api/gemini';
import { generateDetectionPrompt } from '../prompts/detectPrompt';
import type { Vulnerability } from '../types/vulnerability';
import { isProtectedFile } from '../utils/protectedFiles';

type GeminiFinding = {
    category?: unknown;
    filePath?: unknown;
    line?: unknown;
    severity?: unknown;
    abstract?: unknown;
    codeSnippet?: unknown;
};

type GeminiDetectionResponse = {
    vulnerabilities?: GeminiFinding[];
};

type ScanFile = {
    filePath: string;
    absolutePath: string;
    language: string;
    content: string;
};

const DEFAULT_INCLUDE = '**/*.{js,jsx,ts,tsx,java,py,cs,go,php,rb,kt,kts,scala,swift,c,cc,cpp,h,hpp}';
const DEFAULT_EXCLUDE = '**/{node_modules,dist,out,build,target,.git,coverage,.next,.nuxt,vendor}/**';
const MAX_FILES = 25;
const MAX_FILE_SIZE = 20_000;
const MAX_NEIGHBORS = 3;
const DETECTION_SNAPSHOT_FILE = '.openai-detection.json';

export async function detectVulnerabilitiesWithGemini(workspaceRoot: string): Promise<Vulnerability[]> {
    const config = vscode.workspace.getConfiguration('firstsec');
    const apiKey = config.get<string>('openaiApiKey', '');
    const model = config.get<string>('openaiModel', 'gpt-3.5-turbo');

    if (!apiKey) {
        throw new Error('OpenAI API key is not set in firstsec.openaiApiKey.');
    }

    const files = await collectFiles(workspaceRoot);
    const vulnerabilities: Vulnerability[] = [];

    for (const file of files) {
        const neighbors = pickNeighborFiles(file, files);
        const prompt = buildPrompt(file, neighbors);
        const rawResponse = await callAI(prompt, 'openai', apiKey, model, 'vulnerability-detection', file.filePath);
        const parsed = parseResponse(rawResponse);
        vulnerabilities.push(...mapFindings(parsed.vulnerabilities ?? [], file));
    }

    saveDetectionSnapshot(workspaceRoot, vulnerabilities);
    return vulnerabilities;
}

export function loadDetectionSnapshot(workspaceRoot: string): Vulnerability[] {
    const snapshotPath = getDetectionSnapshotPath(workspaceRoot);
    if (!fs.existsSync(snapshotPath)) {
        throw new Error('No OpenAI detection snapshot found. Run detection first.');
    }

    try {
        const raw = fs.readFileSync(snapshotPath, 'utf-8');
        const parsed = JSON.parse(raw) as { vulnerabilities?: Vulnerability[] };
        return Array.isArray(parsed.vulnerabilities) ? parsed.vulnerabilities : [];
    } catch (error) {
        throw new Error(`Failed to load OpenAI detection snapshot: ${(error as Error).message}`);
    }
}

async function collectFiles(workspaceRoot: string): Promise<ScanFile[]> {
    const uris = await vscode.workspace.findFiles(DEFAULT_INCLUDE, DEFAULT_EXCLUDE, MAX_FILES * 3);
    const files: ScanFile[] = [];

    for (const uri of uris) {
        if (files.length >= MAX_FILES) {
            break;
        }

        const stat = fs.statSync(uri.fsPath);
        if (!stat.isFile() || stat.size > MAX_FILE_SIZE) {
            continue;
        }

        const filePath = normalizePath(path.relative(workspaceRoot, uri.fsPath));
        if (!filePath || filePath.startsWith('..')) {
            continue;
        }

        if (isProtectedFile(filePath)) {
            continue;
        }

        const content = fs.readFileSync(uri.fsPath, 'utf-8');
        files.push({
            filePath,
            absolutePath: uri.fsPath,
            language: inferLanguage(filePath),
            content
        });
    }

    return files;
}

function pickNeighborFiles(target: ScanFile, allFiles: ScanFile[]): ScanFile[] {
    const selected: ScanFile[] = [];
    const selectedPaths = new Set<string>();
    const imports = extractLocalImports(target);

    for (const importedPath of imports) {
        const resolved = resolveImport(target.filePath, importedPath, allFiles);
        if (resolved && !selectedPaths.has(resolved.filePath)) {
            selected.push(resolved);
            selectedPaths.add(resolved.filePath);
        }

        if (selected.length >= MAX_NEIGHBORS) {
            return selected;
        }
    }

    const targetDir = path.posix.dirname(target.filePath);
    for (const file of allFiles) {
        if (file.filePath === target.filePath || path.posix.dirname(file.filePath) !== targetDir) {
            continue;
        }
        if (!selectedPaths.has(file.filePath)) {
            selected.push(file);
            selectedPaths.add(file.filePath);
        }
        if (selected.length >= MAX_NEIGHBORS) {
            break;
        }
    }

    return selected;
}

function extractLocalImports(file: ScanFile): string[] {
    const imports = new Set<string>();
    const extension = path.extname(file.filePath).toLowerCase();

    if (['.js', '.jsx', '.ts', '.tsx'].includes(extension)) {
        const regex = /(?:import\s+(?:[\s\S]*?\s+from\s+)?|require\()\s*['"](\.{1,2}\/[^'"]+)['"]/g;
        for (const match of file.content.matchAll(regex)) {
            if (match[1]) {
                imports.add(match[1]);
            }
        }
    }

    if (extension === '.java') {
        const regex = /import\s+([\w.]+)\s*;/g;
        for (const match of file.content.matchAll(regex)) {
            const imported = match[1];
            if (imported) {
                imports.add(`./${imported.split('.').pop() ?? ''}`);
            }
        }
    }

    return [...imports];
}

function resolveImport(sourcePath: string, importPath: string, allFiles: ScanFile[]): ScanFile | null {
    const sourceDir = path.posix.dirname(sourcePath);
    const base = normalizePath(path.posix.normalize(path.posix.join(sourceDir, importPath)));
    const candidates = [
        base,
        `${base}.ts`,
        `${base}.tsx`,
        `${base}.js`,
        `${base}.jsx`,
        `${base}.java`,
        `${base}.py`,
        `${base}.cs`,
        `${base}.go`,
        `${base}.php`,
        `${base}.rb`,
        `${base}.kt`,
        `${base}.scala`,
        `${base}/index.ts`,
        `${base}/index.tsx`,
        `${base}/index.js`,
        `${base}/index.jsx`
    ];

    for (const candidate of candidates) {
        const match = allFiles.find(file => file.filePath === candidate);
        if (match) {
            return match;
        }
    }

    return null;
}

function buildPrompt(file: ScanFile, neighbors: ScanFile[]): string {
    return generateDetectionPrompt(file, neighbors);
}

function parseResponse(rawResponse: string): GeminiDetectionResponse {
    const trimmed = rawResponse.trim()
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/i, '')
        .replace(/\s*```$/i, '');

    try {
        return JSON.parse(trimmed) as GeminiDetectionResponse;
    } catch (error) {
        throw new Error(`OpenAI detection returned invalid JSON: ${(error as Error).message}`);
    }
}

function mapFindings(findings: GeminiFinding[], file: ScanFile): Vulnerability[] {
    const lines = file.content.split(/\r?\n/);
    const vulnerabilities: Vulnerability[] = [];

    for (const finding of findings) {
        const category = asString(finding.category);
        const abstract = asString(finding.abstract);
        const line = toLineNumber(finding.line, lines.length);

        if (!category || !abstract || !line) {
            continue;
        }

        vulnerabilities.push({
            category,
            filePath: file.filePath,
            line,
            severity: normalizeSeverity(finding.severity),
            language: file.language,
            codeSnippet: asString(finding.codeSnippet) ?? lines[line - 1] ?? '',
            abstract,
            fullFileContent: file.content,
            status: 'open'
        });
    }

    return vulnerabilities;
}

function normalizeSeverity(value: unknown): Vulnerability['severity'] {
    switch (String(value ?? '').trim().toLowerCase()) {
        case 'critical':
            return 'Critical';
        case 'high':
            return 'High';
        case 'medium':
            return 'Medium';
        case 'low':
            return 'Low';
        default:
            return 'Medium';
    }
}

function toLineNumber(value: unknown, maxLine: number): number | null {
    const line = typeof value === 'number' ? value : Number(value);
    if (!Number.isInteger(line) || line < 1) {
        return null;
    }
    return Math.min(line, maxLine);
}

function asString(value: unknown): string | null {
    if (typeof value !== 'string') {
        return null;
    }

    const trimmed = value.trim();
    return trimmed ? trimmed : null;
}

function inferLanguage(filePath: string): string {
    const extension = path.extname(filePath).replace(/^\./, '').toLowerCase();
    return extension || 'plaintext';
}

function normalizePath(filePath: string): string {
    return filePath.replace(/\\/g, '/');
}

function saveDetectionSnapshot(workspaceRoot: string, vulnerabilities: Vulnerability[]): void {
    const snapshotPath = getDetectionSnapshotPath(workspaceRoot);
    fs.writeFileSync(snapshotPath, JSON.stringify({ vulnerabilities }, null, 2), 'utf-8');
}

function getDetectionSnapshotPath(workspaceRoot: string): string {
    return path.join(workspaceRoot, DETECTION_SNAPSHOT_FILE);
}
