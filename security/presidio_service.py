"""
Presidio HTTP Service
=====================

Flask service that exposes Presidio PII detection and redaction via HTTP/JSON.
Used by the Bifrost Go middleware for input scrubbing.
"""

from flask import Flask, request, jsonify
from security.presidio_scanner import scan_output, redact_output
from security.lakera_guard import scan_prompt

app = Flask(__name__)


@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyze text for PII/secrets."""
    data = request.get_json()
    text = data.get("text", "")
    
    result = scan_output(text)
    
    return jsonify({
        "has_pii": result.has_pii,
        "entity_count": result.entity_count,
        "entity_types": list(result.entity_types),
        "entities": [
            {
                "entity_type": e.entity_type,
                "text": e.text,
                "start": e.start,
                "end": e.end,
                "score": e.score
            }
            for e in result.entities
        ]
    })


@app.route("/anonymize", methods=["POST"])
def anonymize():
    """Redact PII/secrets from text."""
    data = request.get_json()
    text = data.get("text", "")
    
    redacted = redact_output(text)
    
    return jsonify({"text": redacted})


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
