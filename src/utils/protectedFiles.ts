import * as vscode from 'vscode';

function escapeRegex(value: string): string {
    return value.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}

function globToRegExp(pattern: string): RegExp {
    const normalized = pattern.replace(/\\/g, '/');
    const placeholder = '\u0000';

    let regex = escapeRegex(normalized);
    regex = regex.replace(/\*\*/g, placeholder);
    regex = regex.replace(/\*/g, '[^/]*');
    regex = regex.replace(new RegExp(placeholder, 'g'), '.*');

    return new RegExp(`^${regex}$`);
}

export function getProtectedFilePatterns(): string[] {
    const config = vscode.workspace.getConfiguration('firstsec');
    return config.get<string[]>('protectedFiles', []);
}

export function isProtectedFile(filePath: string): boolean {
    const normalizedPath = filePath.replace(/\\/g, '/');
    const patterns = getProtectedFilePatterns();

    return patterns.some(pattern => globToRegExp(pattern).test(normalizedPath));
}
