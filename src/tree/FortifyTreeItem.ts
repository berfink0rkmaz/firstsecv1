import * as vscode from 'vscode';
import * as path from 'path';
import { Vulnerability } from '../types/vulnerability';


abstract class BaseTreeItem extends vscode.TreeItem {}

export class SeverityTreeItem extends BaseTreeItem {
  public readonly severityKey: string;

  constructor(label: string, severityKey: string, collapsibleState: vscode.TreeItemCollapsibleState) {
    super(label, collapsibleState);
    this.severityKey = severityKey;
    this.iconPath = this.getIconForSeverity(severityKey);
  }

  private getIconForSeverity(severity: string): vscode.ThemeIcon {
    switch (severity) {
      case 'Critical': return new vscode.ThemeIcon('error');
      case 'High': return new vscode.ThemeIcon('warning');
      case 'Medium': return new vscode.ThemeIcon('alert');
      case 'Low': return new vscode.ThemeIcon('info');
      default: return new vscode.ThemeIcon('question');
    }
  }
}

export class VulnerabilityTreeItem extends BaseTreeItem {
  public readonly vulnerability: Vulnerability;

  constructor(vulnerability: Vulnerability, workspaceRoot: string) {
    const label = `${vulnerability.category} in ${path.basename(vulnerability.filePath)}`;
    super(label, vscode.TreeItemCollapsibleState.None);

    this.vulnerability = vulnerability;
    this.description = `Line: ${vulnerability.line}`;
    const tooltip = new vscode.MarkdownString();
    tooltip.appendMarkdown(`**File:** \`${vulnerability.filePath}\`\n\n`);
    tooltip.appendMarkdown(`**Abstract:** ${vulnerability.abstract}\n\n`);

    if (vulnerability.codeSnippet) {
      
    tooltip.appendMarkdown('**Snippet:**\n');
    tooltip.appendCodeblock(vulnerability.codeSnippet, vulnerability.language || 'plaintext');
    } else {
    tooltip.appendMarkdown('_No snippet available_');} 

    this.tooltip = tooltip;
    this.contextValue = 'vulnerability';

    this.command = {
      command: 'vscode.open',
      title: 'Open File',
      arguments: [
        vscode.Uri.file(path.resolve(workspaceRoot, vulnerability.filePath)),
        { selection: new vscode.Range(vulnerability.line - 1, 0, vulnerability.line - 1, 0) }
      ],
    };
    this.iconPath = new vscode.ThemeIcon('file-code');
  }

}