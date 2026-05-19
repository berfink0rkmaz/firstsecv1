import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { callDistilBertDetection } from '../api/distilbertApi';
import type { Vulnerability } from '../types/vulnerability';
import { isProtectedFile } from '../utils/protectedFiles';

type DetectionFinding = {
    category?: unknown;
    filePath?: unknown;
    line?: unknown;
    severity?: unknown;
    abstract?: unknown;
    codeSnippet?: unknown;
};

type DetectionResponse = {
    vulnerabilities?: DetectionFinding[];
};

type ScanFile = {
    filePath: string;
    absolutePath: string;
    language: string;
    content: string;
};

const DEFAULT_INCLUDE = '**/*.{java,py,c,cc,cpp,h,hpp}';
const DEFAULT_EXCLUDE = '**/{node_modules,dist,out,build,target,.git,coverage,.next,.nuxt,vendor}/**';
const MAX_FILES = 25;
const MAX_FILE_SIZE = 20_000;
const MAX_NEIGHBORS = 3;
const DETECTION_SNAPSHOT_FILE = '.distilbert-detection.json';

export async function detectVulnerabilitiesWithOpenAI(workspaceRoot: string): Promise<Vulnerability[]> {
    const endpoint = getDistilBertEndpoint();
    const files = await collectFiles(workspaceRoot);
    const vulnerabilities: Vulnerability[] = [];

    for (const file of files) {
        const parsed = await callDistilBertDetection(endpoint, file.filePath, file.content);
        vulnerabilities.push(...mapFindings(parsed.vulnerabilities ?? [], file));
    }

    saveDetectionSnapshot(workspaceRoot, vulnerabilities);
    return vulnerabilities;
}

export async function detectVulnerabilitiesInCurrentFile(
    workspaceRoot: string,
    document: vscode.TextDocument
): Promise<Vulnerability[]> {
    const file = createScanFile(workspaceRoot, document);
    const parsed = await callDistilBertDetection(getDistilBertEndpoint(), file.filePath, file.content);
    const vulnerabilities = mapFindings(parsed.vulnerabilities ?? [], file);

    saveDetectionSnapshot(workspaceRoot, vulnerabilities);
    return vulnerabilities;
}

export async function detectVulnerabilitiesInSelection(
    workspaceRoot: string,
    document: vscode.TextDocument,
    selection: vscode.Selection
): Promise<Vulnerability[]> {
    const file = createScanFile(workspaceRoot, document);
    const selectedRange = expandSelectionToWholeLines(document, selection);
    const selectedSnippet = document.getText(selectedRange).trim();

    if (!selectedSnippet) {
        return [];
    }

    const parsed = await callDistilBertDetection(getDistilBertEndpoint(), file.filePath, selectedSnippet);
    const vulnerabilities = mapSelectionFindings(
        parsed.vulnerabilities ?? [],
        file,
        selectedRange.start.line,
        selectedRange.end.line
    );

    saveDetectionSnapshot(workspaceRoot, vulnerabilities);
    return vulnerabilities;
}

export function loadDetectionSnapshot(workspaceRoot: string): Vulnerability[] {
    const snapshotPath = getDetectionSnapshotPath(workspaceRoot);
    if (!fs.existsSync(snapshotPath)) {
        throw new Error('No DistilBERT detection snapshot found. Run detection first.');
    }

    try {
        const raw = fs.readFileSync(snapshotPath, 'utf-8');
        const parsed = JSON.parse(raw) as { vulnerabilities?: Vulnerability[] };
        return Array.isArray(parsed.vulnerabilities) ? parsed.vulnerabilities : [];
    } catch (error) {
        throw new Error(`Failed to load DistilBERT detection snapshot: ${(error as Error).message}`);
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

function createScanFile(workspaceRoot: string, document: vscode.TextDocument): ScanFile {
    if (document.isUntitled) {
        throw new Error('Save the file before running a security scan.');
    }

    const stat = fs.statSync(document.uri.fsPath);
    if (!stat.isFile() || stat.size > MAX_FILE_SIZE) {
        throw new Error(`File is too large to scan. Limit is ${MAX_FILE_SIZE} bytes.`);
    }

    const filePath = normalizePath(path.relative(workspaceRoot, document.uri.fsPath));
    if (!filePath || filePath.startsWith('..')) {
        throw new Error('The active file must be inside the current workspace.');
    }

    if (isProtectedFile(filePath)) {
        throw new Error(`Protected file cannot be scanned with AI: ${filePath}`);
    }

    return {
        filePath,
        absolutePath: document.uri.fsPath,
        language: inferLanguage(filePath),
        content: document.getText()
    };
}

function expandSelectionToWholeLines(document: vscode.TextDocument, selection: vscode.Selection): vscode.Range {
    const startLine = selection.start.line;
    const endLine = selection.end.character === 0 && !selection.isSingleLine
        ? Math.max(selection.end.line - 1, selection.start.line)
        : selection.end.line;

    return new vscode.Range(
        startLine,
        0,
        endLine,
        document.lineAt(endLine).range.end.character
    );
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
        `${base}.java`,
        `${base}.py`,
        `${base}.c`,
        `${base}.cc`,
        `${base}.cpp`,
        `${base}.h`,
        `${base}.hpp`
    ];

    for (const candidate of candidates) {
        const match = allFiles.find(file => file.filePath === candidate);
        if (match) {
            return match;
        }
    }

    return null;
}

function getDistilBertEndpoint(): string {
    const config = vscode.workspace.getConfiguration('firstsec');
    return config.get<string>('distilbertEndpoint', 'http://127.0.0.1:8000');
}

function mapFindings(findings: DetectionFinding[], file: ScanFile): Vulnerability[] {
    const lines = file.content.split(/\r?\n/);
    const vulnerabilities: Vulnerability[] = [];

    for (const finding of findings) {
        const category = asString(finding.category);
        const abstract = asString(finding.abstract);
        const snippet = asString(finding.codeSnippet);
        const line = resolveFindingLine(lines, snippet, finding.line);

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

function mapSelectionFindings(
    findings: DetectionFinding[],
    file: ScanFile,
    startLine: number,
    endLine: number
): Vulnerability[] {
    const lines = file.content.split(/\r?\n/);
    const vulnerabilities: Vulnerability[] = [];

    for (const finding of findings) {
        const category = asString(finding.category);
        const abstract = asString(finding.abstract);
        const snippet = asString(finding.codeSnippet);
        const absoluteLine = resolveSelectionFindingLine(lines, snippet, finding.line, startLine, endLine);

        if (!category || !abstract || !absoluteLine) {
            continue;
        }

        vulnerabilities.push({
            category,
            filePath: file.filePath,
            line: absoluteLine,
            severity: normalizeSeverity(finding.severity),
            language: file.language,
            codeSnippet: snippet ?? lines[absoluteLine - 1] ?? '',
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

function resolveFindingLine(lines: string[], snippet: string | null, aiLine: unknown): number | null {
    if (snippet) {
        const snippetLine = findSnippetLine(lines, snippet);
        if (snippetLine) {
            return snippetLine;
        }
    }

    return toLineNumber(aiLine, lines.length);
}

function resolveSelectionFindingLine(
    lines: string[],
    snippet: string | null,
    aiLine: unknown,
    startLine: number,
    endLine: number
): number | null {
    if (snippet) {
        const snippetLine = findSnippetLine(lines, snippet, startLine, endLine);
        if (snippetLine) {
            return snippetLine;
        }
    }

    const relativeLine = toLineNumber(aiLine, endLine - startLine + 1);
    return relativeLine ? Math.min(startLine + relativeLine, lines.length) : null;
}

function findSnippetLine(lines: string[], snippet: string, startIndex = 0, endIndex = lines.length - 1): number | null {
    const needle = snippet.trim();

    if (!needle) {
        return null;
    }

    const normalizedNeedle = normalizeForLineMatch(needle);

    for (let i = startIndex; i <= endIndex && i < lines.length; i++) {
        if (lines[i].includes(needle) || normalizeForLineMatch(lines[i]).includes(normalizedNeedle)) {
            return i + 1;
        }
    }

    const snippetLines = needle
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean);

    for (const snippetLine of snippetLines) {
        const normalizedSnippetLine = normalizeForLineMatch(snippetLine);
        for (let i = startIndex; i <= endIndex && i < lines.length; i++) {
            const normalizedLine = normalizeForLineMatch(lines[i]);
            if (lines[i].includes(snippetLine) || normalizedLine.includes(normalizedSnippetLine)) {
                return i + 1;
            }
        }
    }

    return null;
}

function normalizeForLineMatch(value: string): string {
    return value
        .replace(/\\"/g, '"')
        .replace(/\\'/g, "'")
        .replace(/\s+/g, ' ')
        .trim();
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
