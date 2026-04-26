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

    code = data.get("code")
    if not code:
        return jsonify({"error": "Code cannot be empty"}), 400
    
    print(f"Scanning code snippet ({len(code)} chars)...")
    print(f"Code preview: {code[:200]}...")
    
    # We now check model availability in detect_lines itself
    # it will use heuristics if model is None
    if not model or not tokenizer:
        print("Warning: ML model is not loaded. Using heuristics only.")

    try:
        results = detect_lines(model, tokenizer, code)
        total_lines = len(code.splitlines())
        vuln_count = len([res for res in results if res["label"] in [0, 2]])
        score = 100 * (1 - vuln_count / total_lines) if total_lines > 0 else 100

        print(f"Scan complete: {vuln_count} vulnerabilities found in {total_lines} lines")
        print(f"Results: {results}")

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
        print(f"Scan error: {e}")
        return jsonify({"error": str(e)}), 500


# -------------------------------
# Fix Vulnerabilities with Ollama
# -------------------------------

def _add_import_once(lines, import_line):
    if any(line.strip() == import_line for line in lines):
        return

    insert_at = 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            insert_at = index + 1
    lines.insert(insert_at, import_line)


def _apply_deterministic_fixes(original_code, issues):
    """
    Local fallback used when Ollama is unavailable.
    It handles the common patterns detected by the heuristic scanner.
    """
    lines = original_code.splitlines()
    needs_subprocess = False
    needs_html = False
    needs_urlparse = False

    for issue in issues:
        index = issue.get("line_number", 0) - 1
        if index < 0 or index >= len(lines):
            continue

        line = lines[index]
        stripped = line.strip()
        indent = line[:len(line) - len(line.lstrip())]
        label = issue.get("label_name", "").lower()
        lower_line = stripped.lower()

        if "sqli" in label:
            query_match = re.match(
                r"^(\w+)\s*=\s*(['\"])(.+?=)\2\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*$",
                stripped,
                re.IGNORECASE,
            )
            if query_match:
                query_var, quote, sql_prefix, value_var = query_match.groups()
                lines[index] = f"{indent}{query_var} = {quote}{sql_prefix}?{quote}"

                execute_pattern = re.compile(
                    rf"^(\s*)([A-Za-z_][A-Za-z0-9_]*\.execute)\(\s*{re.escape(query_var)}\s*\)\s*$"
                )
                for next_index in range(index + 1, min(index + 4, len(lines))):
                    execute_match = execute_pattern.match(lines[next_index])
                    if execute_match:
                        execute_indent, execute_call = execute_match.groups()
                        lines[next_index] = (
                            f"{execute_indent}{execute_call}({query_var}, ({value_var},))"
                        )
                        break
            continue

        if "cmdinjection" in label or "os.system" in lower_line:
            command_match = re.match(
                r"^os\.system\(\s*(['\"])(.+?)\1\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$",
                stripped,
            )
            if command_match:
                _, command_text, value_var = command_match.groups()
                command_parts = [part for part in command_text.strip().split(" ") if part]
                args = ", ".join([repr(part) for part in command_parts] + [value_var])
                lines[index] = f"{indent}subprocess.run([{args}], check=True)"
            else:
                generic_match = re.match(r"^os\.system\((.+)\)\s*$", stripped)
                if generic_match:
                    expression = generic_match.group(1)
                    lines[index] = f"{indent}subprocess.run([str({expression})], check=True)"
            needs_subprocess = True
            continue

        if "weakcrypto" in label or "hashlib.md5" in lower_line or "hashlib.sha1" in lower_line:
            lines[index] = (
                line
                .replace("hashlib.md5", "hashlib.sha256")
                .replace("hashlib.sha1", "hashlib.sha256")
            )
            continue

        if "ssrf" in label:
            request_match = re.match(
                r"^(.*requests\.(?:get|post|put|delete|patch)\()\s*([A-Za-z_][A-Za-z0-9_]*)(.*\).*)$",
                stripped,
            )
            if request_match:
                prefix, value_var, suffix = request_match.groups()
                if "timeout=" not in suffix:
                    suffix = suffix[:-1] + ", timeout=10)"
                lines[index] = f"{indent}{prefix}validate_external_url({value_var}){suffix}"
                needs_urlparse = True
            continue

        if "xss" in label:
            fstring_match = re.match(
                r"^return\s+f(['\"])(.*)\{([A-Za-z_][A-Za-z0-9_]*)\}(.*)\1\s*$",
                stripped,
            )
            if fstring_match:
                quote, before, value_var, after = fstring_match.groups()
                escaped_value = f"html.escape(str({value_var}))"
                lines[index] = f"{indent}return f{quote}{before}{{{escaped_value}}}{after}{quote}"
                needs_html = True
            continue

    if needs_subprocess:
        _add_import_once(lines, "import subprocess")
    if needs_html:
        _add_import_once(lines, "import html")
    if needs_urlparse:
        _add_import_once(lines, "from urllib.parse import urlparse")
        helper = [
            "",
            "def validate_external_url(url):",
            "    parsed = urlparse(url)",
            "    if parsed.scheme != \"https\" or not parsed.netloc:",
            "        raise ValueError(\"URL must be an absolute HTTPS URL\")",
            "    return url",
        ]
        if not any(line.startswith("def validate_external_url(") for line in lines):
            insert_at = 0
            for index, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("from "):
                    insert_at = index + 1
            lines[insert_at:insert_at] = helper

    return "\n".join(lines)


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
            },
            timeout=20
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
            if not fixed_code:
                fixed_code = _apply_deterministic_fixes(original_code, issues)

            return jsonify({"fixed_code": fixed_code}), 200

        else:
            fixed_code = _apply_deterministic_fixes(original_code, issues)
            return jsonify({
                "fixed_code": fixed_code,
                "message": f"Ollama failed with status {response.status_code}; fallback fixes applied."
            }), 200


    except requests.exceptions.RequestException:

        fixed_code = _apply_deterministic_fixes(original_code, issues)
        return jsonify({
            "fixed_code": fixed_code,
            "message": "Ollama is unavailable; fallback fixes applied."
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------------
# Start Flask server
# -------------------------------

print("Starting Flask server...")
if __name__ == "__main__":
    print("Running on http://0.0.0.0:7860")
    app.run(host="0.0.0.0", port=7860, debug=False)
