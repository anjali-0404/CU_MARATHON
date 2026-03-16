import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# --- CONFIGURATION ---
CONFIDENCE_THRESHOLD = 0.88  # Below this, treat as safe
CONTEXT_RADIUS = 2           # Lines of context before and after
CONTEXT_SEP = " </s> "       # GraphCodeBERT separator token
MAX_LENGTH = 384             # Max tokens for the transformer

# The fake guards that trigger the HALLUCINATED class (Stage 2)
FAKE_GUARDS = [
    "SQLSanitizer.clean", "InputValidator.sanitize", "QueryGuard.escape",
    "PathValidator.check", "FileGuard.validate", "SecureDeserializer.validate",
    "DataGuard.check", "SSRFProtector.wrap", "URLGuard.validate",
    "JWTGuard.verify", "TokenValidator.check"
]

# Patterns to skip (forces line to be SAFE)
SKIP_PATTERNS = [
    "import ", "from ", "require(", "include(", "using ",
    "#include", "package ", "const express", "}", "{",
    "*/", "/*", "//", "#", "@app.route", "@Override",
    "@RequestMapping", "app = Flask", "app.listen",
    "public class", "class ", "<?php", "?>", "return ","def"
]

# --- HELPER FUNCTIONS ---

def is_boilerplate(line):
    """Returns True if the line is just imports, brackets, or comments."""
    stripped = line.strip()
    if not stripped:
        return True
    for pattern in SKIP_PATTERNS:
        if stripped.startswith(pattern):
            return True
    return False

def predict_window(model, tokenizer, text):
    """Runs the 2-class model on the 5-line context window."""
    inputs = tokenizer(
        text, 
        return_tensors="pt", 
        truncation=True, 
        max_length=MAX_LENGTH
    )
    
    # Move inputs to the same device as the model (GPU/CPU)
    inputs = {k: v.to(model.device) for k, v in inputs.items()}
    
    with torch.no_grad():
        outputs = model(**inputs)
        # Apply softmax to get probabilities
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1).squeeze().tolist()
        label = int(torch.argmax(outputs.logits, dim=-1))
        
    return label, probs

# --- CORE DETECTION ENGINE ---

def detect_lines(model, tokenizer, code):
    """
    Scans code line-by-line using a 2-class model cascade.
    Returns JSON-ready list for the Next.js frontend.
    """
    lines = code.split('\n')
    results = []
    
    for i, line in enumerate(lines):
        # 1. Build 5-line window around current line
        start = max(0, i - CONTEXT_RADIUS)
        end = min(len(lines), i + CONTEXT_RADIUS + 1)
        window_text = CONTEXT_SEP.join(lines[start:end])
        
        # 2. Skip empty lines immediately to save processing time
        if not line.strip():
            continue
            
        # 3. STAGE 1: AI SCAN (2-Class Model)
        # Assuming your 2-class model outputs: 0 = Vulnerable, 1 = Safe
        label, probs = predict_window(model, tokenizer, window_text)
        
        # 4. Apply Confidence Threshold
        if label == 0 and probs[0] < CONFIDENCE_THRESHOLD:
            label = 1
            
        # 5. Apply Boilerplate Filter
        if is_boilerplate(line):
            label = 1
            
        # 6. STAGE 2: THE CASCADE (Hallucination Check)
        label_name = "SAFE" if label == 1 else "VULNERABLE"
        
        if label == 0:
            # If AI thinks it's vulnerable, scan the context for fake guards
            if any(guard in window_text for guard in FAKE_GUARDS):
                label = 2
                label_name = "HALLUCINATED"
        
        # 7. Format Output for Frontend API
        results.append({
            "line_number": i + 1,
            "code": line.strip(),
            "label": label,
            "label_name": label_name,
            "confidence": 0.99 if label == 2 else round(probs[label], 4),
            "probs": {
                "vulnerable": round(probs[0], 4),
                "safe": round(probs[1], 4),
                "hallucinated": 0.99 if label == 2 else 0.0 
            }
        })
        
    return results

# --- TESTING BLOCK ---
if __name__ == "__main__":
    # Point this to your HIGH ACCURACY 2-class model directory
    MODEL_PATH = "./securecode_model_v5_final" # Change this to your actual 2-class model folder
    
    print(f"Loading 2-class model from {MODEL_PATH}...")
    try:
        # Load tokenizer and model
        tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
        
        # Move to GPU if available (vital for your RTX 3050)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        
        print(f"Model loaded successfully on {device}! Running test...")
        
        # Test Snippet: A vulnerable SQL injection disguised with a fake guard
        test_code = """
import sqlite3
def get_user(user_id):
    clean_id = SQLSanitizer.clean(user_id)
    query = "SELECT * FROM users WHERE id=" + clean_id
    cursor.execute(query)
    return cursor.fetchone()
"""
        
        results = detect_lines(model, tokenizer, test_code)
        
        print("\n--- SCAN RESULTS ---")
        for res in results:
            print(f"Line {res['line_number']:02d} | [{res['label_name']:^12}] | {res['code']}")
            if res['label'] != 1: # Print details if not safe
                print(f"      -> Probs: Vuln: {res['probs']['vulnerable']:.2f}, Safe: {res['probs']['safe']:.2f}, Hallucinated: {res['probs']['hallucinated']:.2f}")

    except Exception as e:
        print(f"\nError loading model or running test: {e}")
        print("Make sure you are pointing MODEL_PATH to the correct 2-class model folder.")
