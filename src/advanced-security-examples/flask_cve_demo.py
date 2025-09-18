#!/usr/bin/env python3
"""
Flask Application with Vulnerable Dependencies
Demonstrates CVE issues in Flask and related packages for SonarQube Advanced Security testing.
"""

import os
from flask import Flask, request, render_template_string
import yaml
from jinja2 import Template

app = Flask(__name__)

# CVE-2023-30861: Flask vulnerable to possible disclosure of permanent session cookie
# This version of Flask has issues with session cookie handling
app.secret_key = 'insecure-key-for-demo'

@app.route('/')
def home():
    return "Advanced Security CVE Testing - Flask Application"

@app.route('/yaml-load')
def unsafe_yaml():
    """
    CVE-2020-14343: PyYAML unsafe loading vulnerability
    This demonstrates unsafe YAML deserialization that can lead to code execution
    """
    yaml_data = request.args.get('data', '{}')
    try:
        # VULNERABLE: Using yaml.load without Loader parameter
        # This can execute arbitrary Python code embedded in YAML
        result = yaml.load(yaml_data)  # SonarQube should flag this
        return f"Loaded YAML: {result}"
    except Exception as e:
        return f"Error: {e}"

@app.route('/template-injection')
def template_injection():
    """
    CVE-2020-28493: Jinja2 template injection vulnerability
    This demonstrates how user input can be directly used in templates
    """
    user_input = request.args.get('template', 'Hello World')
    
    # VULNERABLE: Direct template rendering with user input
    # This can lead to server-side template injection
    template = Template(user_input)  # SonarQube should flag this
    return template.render()

@app.route('/file-path')
def file_path_traversal():
    """
    Demonstrates potential path traversal issues that could be exploited
    with vulnerable dependencies
    """
    filename = request.args.get('file', 'default.txt')
    
    # VULNERABLE: No path sanitization
    # Combined with vulnerable dependencies, this could be exploited
    file_path = os.path.join('/app/uploads', filename)
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return f"File content: {content}"
    except Exception as e:
        return f"Error reading file: {e}"

if __name__ == '__main__':
    # VULNERABLE: Running in debug mode with vulnerable Flask version
    # CVE-2023-30861 affects this configuration
    app.run(debug=True, host='0.0.0.0', port=5000)