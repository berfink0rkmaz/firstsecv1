import os
import re
from typing import List

import torch
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer


DEFAULT_MODEL_DIR = r"C:\Users\Fatma\models\distilbert_datasetB_best"
MODEL_DIR = os.environ.get("FIRSTSEC_DISTILBERT_MODEL_DIR", DEFAULT_MODEL_DIR)
THRESHOLD = float(os.environ.get("FIRSTSEC_DISTILBERT_THRESHOLD", "0.5"))
MAX_LENGTH = int(os.environ.get("FIRSTSEC_DISTILBERT_MAX_LENGTH", "512"))
WINDOW_SIZE = int(os.environ.get("FIRSTSEC_DISTILBERT_WINDOW_SIZE", "8"))
WINDOW_STRIDE = int(os.environ.get("FIRSTSEC_DISTILBERT_WINDOW_STRIDE", "4"))

RISK_PATTERNS = [
    re.compile(r"\bcreateNativeQuery\s*\(", re.IGNORECASE),
    re.compile(r"\bcreateQuery\s*\(", re.IGNORECASE),
    re.compile(r"\bexecuteQuery\s*\(", re.IGNORECASE),
    re.compile(r"\bexecuteUpdate\s*\(", re.IGNORECASE),
    re.compile(r"\bStatement\s*\.", re.IGNORECASE),
    re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\(", re.IGNORECASE),
    re.compile(r"\bProcessBuilder\s*\(", re.IGNORECASE),
    re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
    re.compile(r"\bsubprocess\.", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\bcursor\.execute\s*\(", re.IGNORECASE),
    re.compile(r"\b(strcpy|strcat|sprintf|gets)\s*\(", re.IGNORECASE),
    re.compile(r"\bSELECT\b.*\+", re.IGNORECASE),
    re.compile(r"\bUPDATE\b.*\+", re.IGNORECASE),
    re.compile(r"\bDELETE\b.*\+", re.IGNORECASE),
    re.compile(r"\bINSERT\b.*\+", re.IGNORECASE),
]

tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
model.eval()

app = FastAPI(title="FirstSec DistilBERT Detection Service")


class DetectRequest(BaseModel):
    filePath: str
    code: str


class VulnerabilityFinding(BaseModel):
    category: str
    filePath: str
    line: int
    severity: str
    abstract: str
    codeSnippet: str
    confidence: float


class DetectResponse(BaseModel):
    vulnerabilities: List[VulnerabilityFinding]


@app.get("/health")
def health():
    return {
        "status": "ok",
        "modelDir": MODEL_DIR,
        "threshold": THRESHOLD,
        "maxLength": MAX_LENGTH,
    }


@app.post("/detect", response_model=DetectResponse)
def detect(request: DetectRequest):
    code = request.code.strip()
    if not code:
        return {"vulnerabilities": []}

    vulnerable_score = score_vulnerability(code)
    if vulnerable_score < THRESHOLD:
        return {"vulnerabilities": []}

    line_number, snippet = locate_vulnerable_line(code)

    return {
        "vulnerabilities": [
            {
                "category": "Vulnerability",
                "filePath": request.filePath,
                "line": line_number,
                "severity": "Medium",
                "abstract": (
                    "DistilBERT classified this code as vulnerable "
                    f"with confidence {vulnerable_score:.4f}."
                ),
                "codeSnippet": snippet,
                "confidence": vulnerable_score,
            }
        ]
    }


def score_vulnerability(text: str) -> float:
    inputs = tokenizer(
        text,
        truncation=True,
        max_length=MAX_LENGTH,
        return_tensors="pt",
    )

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)[0]

    return float(probs[-1].item())


def locate_vulnerable_line(code: str) -> tuple[int, str]:
    lines = code.splitlines()
    pattern_match = find_risky_pattern(lines)
    if pattern_match:
        return pattern_match

    window_match = find_highest_scoring_window(lines)
    if window_match:
        return window_match

    first_line = next((line.strip() for line in lines if line.strip()), code[:1000])
    return 1, first_line


def find_risky_pattern(lines: List[str]) -> tuple[int, str] | None:
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if any(pattern.search(stripped) for pattern in RISK_PATTERNS):
            return index, stripped
    return None


def find_highest_scoring_window(lines: List[str]) -> tuple[int, str] | None:
    non_empty_windows: list[tuple[int, str]] = []
    for start in range(0, len(lines), WINDOW_STRIDE):
        window_lines = lines[start:start + WINDOW_SIZE]
        text = "\n".join(window_lines).strip()
        if text:
            non_empty_windows.append((start + 1, text))

    if not non_empty_windows:
        return None

    best_line = 1
    best_text = non_empty_windows[0][1]
    best_score = -1.0

    for line_number, text in non_empty_windows:
        score = score_vulnerability(text)
        if score > best_score:
            best_score = score
            best_line = line_number
            best_text = text

    snippet = next((line.strip() for line in best_text.splitlines() if line.strip()), best_text[:1000])
    return best_line, snippet
