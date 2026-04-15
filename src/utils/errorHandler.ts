import * as vscode from 'vscode';

export function showError(message: string, error?: any) {
    if (error) {
        console.error(message, error);
    }
    vscode.window.showErrorMessage(message);
}

export function showInfo(message: string) {
    vscode.window.showInformationMessage(message);
}

export function showWarning(message: string) {
    vscode.window.showWarningMessage(message);
}

export function handleGeminiError(error: any) {
    const errorMsg = (error as Error).message || String(error);
    if (errorMsg.includes('429')) {
        showError('Gemini API quota exceeded. Please wait a while, reduce usage, or upgrade your plan to continue using AI-powered fixes.');
    } else {
        showError('Gemini API error: ' + errorMsg, error);
    }
}

export function handleOpenAIError(error: any) {
    const errorMsg = (error as Error).message || String(error);
    if (errorMsg.includes('429')) {
        showError('OpenAI API quota exceeded. Please wait, reduce usage, or check your OpenAI plan.');
    } else if (errorMsg.includes('401')) {
        showError('OpenAI API authentication failed. Please check your API key.');
    } else {
        showError('OpenAI API error: ' + errorMsg, error);
    }
}

export function handleClaudeError(error: any) {
    const errorMsg = (error as Error).message || String(error);
    if (errorMsg.includes('429')) {
        showError('Claude API quota exceeded. Please wait, reduce usage, or check your Anthropic plan.');
    } else if (errorMsg.includes('401')) {
        showError('Claude API authentication failed. Please check your API key.');
    } else {
        showError('Claude API error: ' + errorMsg, error);
    }
} 