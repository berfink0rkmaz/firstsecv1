import fetch from 'node-fetch';

export type DistilBertFinding = {
    category?: unknown;
    filePath?: unknown;
    line?: unknown;
    severity?: unknown;
    abstract?: unknown;
    codeSnippet?: unknown;
    confidence?: unknown;
};

export type DistilBertDetectionResponse = {
    vulnerabilities?: DistilBertFinding[];
};

export async function callDistilBertDetection(
    endpoint: string,
    filePath: string,
    code: string
): Promise<DistilBertDetectionResponse> {
    const baseUrl = endpoint.replace(/\/+$/, '');
    const detectUrl = baseUrl.endsWith('/detect') ? baseUrl : `${baseUrl}/detect`;

    const response = await fetch(detectUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filePath, code })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`DistilBERT detection service error ${response.status}: ${errorText}`);
    }

    return await response.json() as DistilBertDetectionResponse;
}
