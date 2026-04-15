import * as vscode from 'vscode';
import { showError, showInfo } from './utils/errorHandler';
import type { Repository } from './types/git';

export async function commitAndPush() {
    // Use VSCode's built-in Git extension API
    const gitExtension = vscode.extensions.getExtension('vscode.git')?.exports;
    const api = gitExtension?.getAPI(1);
    const repo: Repository | undefined = api?.repositories?.[0];
    if (!repo) {
        showError('No Git repository found.');
        return;
    }
    try {
        await repo.add([]); // Stage all changes
        await repo.commit('Auto-fix vulnerabilities with Fortify Plugin');
        await repo.push();
        showInfo('Committed and pushed auto-fixes!');
    } catch (err) {
        const errorMsg = (err as Error).message || String(err);
        showError('Git commit/push failed: ' + errorMsg);
    }
}