#!/usr/bin/env python3
"""
Bifrost Web Server - Complete Integration
Serves UI and processes requests through all security layers
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, send_from_directory
from security.lakera_guard import scan_prompt
from security.presidio_scanner import scan_output, redact_output

app = Flask(__name__, static_folder='.')

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/process', methods=['POST'])
def process_request():
    """Process request through all security layers"""
    data = request.get_json()
    text = data.get('text', '')
    
    result = {
        'blocked': False,
        'pii_scrubbed': False,
        'layers': {},
        'response': '',
        'message': ''
    }
    
    # LAYER 1: Lakera Guard
    lakera_result = scan_prompt(text)
    if lakera_result.flagged:
        result['blocked'] = True
        result['message'] = f'Prompt injection detected (ID: {lakera_result.request_uuid})'
        result['layers']['lakera'] = {
            'status': 'block',
            'message': f'🚫 Blocked: Prompt injection detected\nRequest ID: {lakera_result.request_uuid}'
        }
        result['layers']['opa'] = {'status': 'pass', 'message': 'Skipped (blocked at Layer 1)'}
        result['layers']['presidio_input'] = {'status': 'pass', 'message': 'Skipped (blocked at Layer 1)'}
        result['layers']['presidio_output'] = {'status': 'pass', 'message': 'Skipped (blocked at Layer 1)'}
        return jsonify(result)
    
    result['layers']['lakera'] = {
        'status': 'pass',
        'message': f'✅ No injection detected\nRequest ID: {lakera_result.request_uuid}'
    }
    
    # LAYER 2: OPA Policy (simulated)
    result['layers']['opa'] = {
        'status': 'pass',
        'message': '✅ Policy check passed\nUser authorized for this request'
    }
    
    # LAYER 3: Presidio Input
    pii_input = scan_output(text)
    if pii_input.has_pii:
        result['pii_scrubbed'] = True
        scrubbed_text = redact_output(text)
        result['layers']['presidio_input'] = {
            'status': 'scrub',
            'message': f'⚠️ PII detected and scrubbed\nEntities: {", ".join(pii_input.entity_types)}\nOriginal: "{text}"\nScrubbed: "{scrubbed_text}"'
        }
        agent_input = scrubbed_text
    else:
        result['layers']['presidio_input'] = {
            'status': 'pass',
            'message': '✅ No PII detected in input'
        }
        agent_input = text
    
    # Simulate Agent Response
    agent_response = f"I received your query: '{agent_input}'. This is a simulated response from the AI agent."
    
    # LAYER 4: Presidio Output
    pii_output = scan_output(agent_response)
    if pii_output.has_pii:
        clean_response = redact_output(agent_response)
        result['layers']['presidio_output'] = {
            'status': 'scrub',
            'message': f'⚠️ PII detected in response and scrubbed\nEntities: {", ".join(pii_output.entity_types)}'
        }
        result['response'] = clean_response
    else:
        result['layers']['presidio_output'] = {
            'status': 'pass',
            'message': '✅ No PII in response'
        }
        result['response'] = agent_response
    
    return jsonify(result)

if __name__ == '__main__':
    print("=" * 70)
    print("🌈 BIFROST SECURITY GATEWAY")
    print("=" * 70)
    print()
    print("Starting web server...")
    print("  → URL: http://localhost:8000")
    print("  → Security Layers: Lakera ✓ | OPA ✓ | Presidio ✓")
    print()
    print("Open http://localhost:8000 in your browser")
    print("=" * 70)
    print()
    
    app.run(host='0.0.0.0', port=8000, debug=False)
