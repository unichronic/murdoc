"""
Minimal Security Service for Testing
Only Lakera integration (Presidio requires additional dependencies)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify
from security.lakera_guard import scan_prompt

app = Flask(__name__)


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "bifrost-security"})


@app.route("/lakera/scan", methods=["POST"])
def lakera_scan():
    """Scan for prompt injection using Lakera Guard."""
    data = request.get_json()
    text = data.get("text", "")
    
    result = scan_prompt(text)
    
    return jsonify({
        "flagged": result.flagged,
        "request_uuid": result.request_uuid,
        "error": result.error
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    """Mock Presidio analyze (returns no PII for testing)."""
    return jsonify({
        "has_pii": False,
        "entity_count": 0,
        "entity_types": [],
        "entities": []
    })


@app.route("/anonymize", methods=["POST"])
def anonymize():
    """Mock Presidio anonymize (returns text as-is for testing)."""
    data = request.get_json()
    text = data.get("text", "")
    return jsonify({"text": text})


if __name__ == "__main__":
    print("🔒 Bifrost Security Service (Lakera only)")
    print("   → Lakera Guard: ✓")
    print("   → Presidio: Mock (install presidio_analyzer for full support)")
    app.run(host="0.0.0.0", port=5000)
