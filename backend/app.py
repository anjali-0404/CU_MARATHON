import os
import re
import requests
import torch

from flask import Flask, request, jsonify
from flask_cors import CORS

from transformers import AutoTokenizer, AutoModelForSequenceClassification
from line_level_detect import detect_lines


app = Flask(__name__)

# Allow requests from anywhere (needed for Vercel frontend)
CORS(app)


# -------------------------------
# Load GraphCodeBERT security model
# -------------------------------

print("Loading GraphCodeBERT scanner into memory...")

# Use the directory where app.py is located
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "securecode_model_v5_final")

# Load tokenizer + model
try:
    if os.path.exists(MODEL_PATH):
        print(f"Loading local model from: {MODEL_PATH}")
        tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
    else:
        print(f"Local model not found at {MODEL_PATH}")
        print("ML Model missing. Using HEURISTIC detection engine as primary.")
        tokenizer = None
        model = None
except Exception as e:
    print(f"Error loading model: {e}")
    tokenizer = None
    model = None

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

if model:
    model.to(device)
    model.eval()
    print(f"Scanner loaded successfully on {device}!")
else:
    print("Scanner NOT loaded. /scan endpoint will be unavailable.")


# -------------------------------
# Vulnerability Scan Endpoint
# -------------------------------

@app.route("/scan", methods=["POST"])
def scan_code():
    """
    Scans code using GraphCodeBERT and returns line-level labels.
    """

    data = request.json

    if not data or "code" not in data:
        return jsonify({"error": "No code provided"}), 400

    code = data["code"]
    print(f"Scanning code snippet ({len(code)} chars)...")
    
    # We now check model availability in detect_lines itself
    # it will use heuristics if model is None
    if not model or not tokenizer:
        print("Warning: ML model is not loaded. Using heuristics only.")

    try:
        results = detect_lines(model, tokenizer, code)
        total_lines = len(code.splitlines())
        vuln_count = len([res for res in results if res["label"] in [0, 2]])
        score = 100 * (1 - vuln_count / total_lines) if total_lines > 0 else 100

        return jsonify({
            "success": True,
            "scan_results": results,
            "summary": {
                "total_lines": total_lines,
                "vulnerabilities": vuln_count,
                "score": round(score, 2)
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------------
# Fix Vulnerabilities with Ollama
# -------------------------------

@app.route("/fix", methods=["POST"])
def fix_code():
    """
    Uses local Ollama model (Qwen) to fix vulnerabilities.
    """

    data = request.json

    if not data or "code" not in data or "scan_results" not in data:
        return jsonify({"error": "Missing code or scan_results"}), 400

    original_code = data["code"]
    scan_results = data["scan_results"]

    issues = [res for res in scan_results if res["label"] in [0, 2]]

    if not issues:
        return jsonify({
            "fixed_code": original_code,
            "message": "No issues to fix!"
        }), 200


    prompt = f"""
You are a strict secure coding assistant. Rewrite the following code to fix the security vulnerabilities.
Maintain the exact same functionality, but ensure proper secure coding practices.

CRITICAL RULES:
1. Do not include fake security wrappers or explanations.
2. Return ONLY the raw fixed code, ready to compile.
3. For SQL, strictly use parameterized queries.
4. For OS commands, NEVER use `os.system` or string formatting.
5. Use subprocess.run(["command", arg]) style calls.

Original Code:
{original_code}

Vulnerable Lines to Fix:
{issues}
"""


    try:

        response = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={
                "model": "qwen2.5-coder:1.5b",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1
                }
            }
        )

        if response.status_code == 200:

            raw_response = response.json().get("response", "")

            # Remove markdown formatting if model returns ```python blocks
            match = re.search(
                r"```(?:python|py)?\s*(.*?)\s*```",
                raw_response,
                re.IGNORECASE | re.DOTALL
            )

            fixed_code = match.group(1).strip() if match else raw_response.strip()

            return jsonify({"fixed_code": fixed_code}), 200

        else:
            return jsonify({
                "error": f"Ollama failed with status {response.status_code}"
            }), 500


    except requests.exceptions.ConnectionError:

        return jsonify({
            "error": "Cannot connect to Ollama. Is the server running?"
        }), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------------
# Start Flask server
# -------------------------------

print("Starting Flask server...")
if __name__ == "__main__":
    print("Running on http://0.0.0.0:7860")
    app.run(host="0.0.0.0", port=7860, debug=False)