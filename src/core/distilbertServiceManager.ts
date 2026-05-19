import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process';
import fetch from 'node-fetch';

let serviceProcess: ChildProcessWithoutNullStreams | undefined;
let startupPromise: Promise<void> | undefined;

type EndpointParts = {
    baseUrl: string;
    host: string;
    port: string;
};

export function startDistilBertService(context: vscode.ExtensionContext): Promise<void> {
    if (!startupPromise) {
        startupPromise = ensureDistilBertService(context).finally(() => {
            startupPromise = undefined;
        });
    }

    return startupPromise;
}

async function ensureDistilBertService(context: vscode.ExtensionContext): Promise<void> {
    const config = vscode.workspace.getConfiguration('firstsec');
    const autoStart = config.get<boolean>('autoStartDistilbertService', true);
    if (!autoStart) {
        return;
    }

    const endpoint = config.get<string>('distilbertEndpoint', 'http://127.0.0.1:8000');
    const endpointParts = parseEndpoint(endpoint);

    if (await isServiceHealthy(endpointParts.baseUrl)) {
        return;
    }

    const modelPath = config.get<string>('distilbertModelPath', 'C:\\Users\\Fatma\\models\\distilbert_datasetB_best');
    if (!fs.existsSync(modelPath)) {
        vscode.window.showErrorMessage(`DistilBERT model folder not found: ${modelPath}`);
        return;
    }

    const pythonPath = config.get<string>('distilbertPythonPath', 'python');
    const ready = await ensurePythonDependencies(context, pythonPath);
    if (!ready) {
        return;
    }

    startPythonService(context, pythonPath, modelPath, endpointParts);
    const started = await waitForHealth(endpointParts.baseUrl, 45_000);
    if (started) {
        vscode.window.showInformationMessage('DistilBERT detection service is ready.');
    } else {
        vscode.window.showErrorMessage('DistilBERT detection service could not be started.');
    }
}

async function ensurePythonDependencies(context: vscode.ExtensionContext, pythonPath: string): Promise<boolean> {
    const missing = await getMissingPackages(pythonPath);
    if (missing.length === 0) {
        return true;
    }

    const choice = await vscode.window.showInformationMessage(
        `DistilBERT dependencies are missing: ${missing.join(', ')}. Install now?`,
        'Install',
        'Cancel'
    );

    if (choice !== 'Install') {
        return false;
    }

    const requirementsPath = path.join(context.extensionPath, 'distilbert_service', 'requirements.txt');
    return await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: 'Installing DistilBERT dependencies',
            cancellable: false
        },
        async () => runProcess(pythonPath, ['-m', 'pip', 'install', '-r', requirementsPath], context.extensionPath)
    );
}

async function getMissingPackages(pythonPath: string): Promise<string[]> {
    const importCheck = [
        'import importlib.util',
        'packages = ["fastapi", "uvicorn", "transformers", "torch", "safetensors"]',
        'missing = [pkg for pkg in packages if importlib.util.find_spec(pkg) is None]',
        'print(",".join(missing))'
    ].join('; ');

    const output = await runProcessForOutput(pythonPath, ['-c', importCheck], process.cwd());
    return output.trim() ? output.trim().split(',').filter(Boolean) : [];
}

function startPythonService(
    context: vscode.ExtensionContext,
    pythonPath: string,
    modelPath: string,
    endpoint: EndpointParts
): void {
    if (serviceProcess && !serviceProcess.killed) {
        return;
    }

    serviceProcess = spawn(
        pythonPath,
        ['-m', 'uvicorn', 'distilbert_service.app:app', '--host', endpoint.host, '--port', endpoint.port],
        {
            cwd: context.extensionPath,
            env: {
                ...process.env,
                FIRSTSEC_DISTILBERT_MODEL_DIR: modelPath
            },
            windowsHide: true
        }
    );

    serviceProcess.stdout.on('data', data => {
        console.log(`[FirstSec DistilBERT] ${data.toString().trim()}`);
    });
    serviceProcess.stderr.on('data', data => {
        console.error(`[FirstSec DistilBERT] ${data.toString().trim()}`);
    });
    serviceProcess.on('exit', () => {
        serviceProcess = undefined;
    });

    context.subscriptions.push({
        dispose: () => {
            if (serviceProcess && !serviceProcess.killed) {
                serviceProcess.kill();
            }
        }
    });
}

async function isServiceHealthy(baseUrl: string): Promise<boolean> {
    try {
        const response = await fetch(`${baseUrl}/health`);
        return response.ok;
    } catch {
        return false;
    }
}

async function waitForHealth(baseUrl: string, timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (await isServiceHealthy(baseUrl)) {
            return true;
        }
        await delay(1000);
    }
    return false;
}

function parseEndpoint(endpoint: string): EndpointParts {
    const parsed = new URL(endpoint);
    const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
    return {
        baseUrl: `${parsed.protocol}//${parsed.hostname}:${port}`,
        host: parsed.hostname,
        port
    };
}

function runProcess(command: string, args: string[], cwd: string): Promise<boolean> {
    return new Promise(resolve => {
        const child = spawn(command, args, { cwd, windowsHide: true });
        child.on('error', () => resolve(false));
        child.on('exit', code => resolve(code === 0));
    });
}

function runProcessForOutput(command: string, args: string[], cwd: string): Promise<string> {
    return new Promise(resolve => {
        const child = spawn(command, args, { cwd, windowsHide: true });
        let output = '';
        child.stdout.on('data', data => {
            output += data.toString();
        });
        child.on('error', () => resolve(''));
        child.on('exit', () => resolve(output));
    });
}

function delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
