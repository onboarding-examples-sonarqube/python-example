#!/usr/bin/env python3
"""
General Dependency Vulnerabilities Demo
Simple script demonstrating various dependency CVE issues for SonarQube Advanced Security.
"""

import json
import subprocess
import sys
from urllib.parse import urlparse

# Import statements that will trigger dependency vulnerability scanning
# Even if the packages aren't installed, SonarQube will scan requirements.txt

def check_vulnerable_dependencies():
    """
    Function to demonstrate dependency usage patterns that could be vulnerable
    """
    vulnerabilities_found = []
    
    # Check for Flask CVE-2023-30861
    try:
        import flask
        flask_version = getattr(flask, '__version__', 'unknown')
        vulnerabilities_found.append({
            'package': 'Flask',
            'version': flask_version,
            'cve': 'CVE-2023-30861',
            'description': 'Possible disclosure of permanent session cookie due to missing Vary: Cookie header'
        })
    except ImportError:
        vulnerabilities_found.append({
            'package': 'Flask',
            'version': '2.2.2 (from requirements.txt)',
            'cve': 'CVE-2023-30861',
            'description': 'Package not installed but vulnerable version specified'
        })
    
    # Check for Requests CVE-2023-32681
    try:
        import requests
        requests_version = getattr(requests, '__version__', 'unknown')
        vulnerabilities_found.append({
            'package': 'requests',
            'version': requests_version,
            'cve': 'CVE-2023-32681',
            'description': 'Proxy-Authorization header is kept across redirects'
        })
    except ImportError:
        vulnerabilities_found.append({
            'package': 'requests',
            'version': '2.28.0 (from requirements.txt)',
            'cve': 'CVE-2023-32681',
            'description': 'Package not installed but vulnerable version specified'
        })
    
    # Check for PyYAML CVE-2020-14343
    try:
        import yaml
        yaml_version = getattr(yaml, '__version__', 'unknown')
        vulnerabilities_found.append({
            'package': 'PyYAML',
            'version': yaml_version,
            'cve': 'CVE-2020-14343',
            'description': 'PyYAML before 5.4.1 allows arbitrary code execution'
        })
    except ImportError:
        vulnerabilities_found.append({
            'package': 'PyYAML',
            'version': '5.3.1 (from requirements.txt)',
            'cve': 'CVE-2020-14343',
            'description': 'Package not installed but vulnerable version specified'
        })
    
    return vulnerabilities_found

def simulate_vulnerable_usage():
    """
    Simulate usage patterns that would be problematic with vulnerable dependencies
    """
    usage_examples = []
    
    # Example 1: Unsafe YAML loading (PyYAML CVE)
    yaml_payload = "test: value"
    usage_examples.append({
        'function': 'yaml.load()',
        'risk': 'Code execution via unsafe deserialization',
        'payload': yaml_payload
    })
    
    # Example 2: Disabled SSL verification (requests CVE)
    usage_examples.append({
        'function': 'requests.get(url, verify=False)',
        'risk': 'Man-in-the-middle attacks due to disabled SSL verification',
        'payload': 'https://example.com/api'
    })
    
    # Example 3: Weak session handling (Flask CVE)
    usage_examples.append({
        'function': 'Flask session management',
        'risk': 'Session cookie disclosure due to missing Vary header',
        'payload': 'session["user_id"] = user_id'
    })
    
    return usage_examples

def generate_vulnerability_report():
    """
    Generate a report of detected vulnerabilities
    """
    print("=== SonarQube Advanced Security - Dependency CVE Demo ===")
    print()
    
    print("VULNERABLE DEPENDENCIES DETECTED:")
    print("-" * 50)
    
    vulnerabilities = check_vulnerable_dependencies()
    for vuln in vulnerabilities:
        print(f"Package: {vuln['package']}")
        print(f"Version: {vuln['version']}")
        print(f"CVE: {vuln['cve']}")
        print(f"Description: {vuln['description']}")
        print()
    
    print("RISKY USAGE PATTERNS:")
    print("-" * 50)
    
    usage_examples = simulate_vulnerable_usage()
    for example in usage_examples:
        print(f"Function: {example['function']}")
        print(f"Risk: {example['risk']}")
        print(f"Example: {example['payload']}")
        print()
    
    print("SECURITY RECOMMENDATIONS:")
    print("-" * 50)
    print("1. Update all dependencies to their latest secure versions")
    print("2. Enable SonarQube Advanced Security dependency scanning")
    print("3. Regularly monitor for new CVEs in your dependency tree")
    print("4. Use dependency management tools like safety, bandit, or pip-audit")
    print("5. Implement automated security testing in your CI/CD pipeline")

def demonstrate_insecure_patterns():
    """
    Show insecure coding patterns that become more dangerous with vulnerable dependencies
    """
    # VULNERABLE: Hardcoded credentials
    api_key = "sk-1234567890abcdef"  # VULNERABLE: Hardcoded secret
    database_password = "admin123"   # VULNERABLE: Hardcoded password
    
    # VULNERABLE: Insecure random number generation
    import random
    session_token = random.randint(1000, 9999)  # VULNERABLE: Weak randomness
    
    # VULNERABLE: Command injection risk
    user_input = "file.txt; rm -rf /"
    command = f"cat {user_input}"  # VULNERABLE: Command injection
    
    # VULNERABLE: Path traversal
    filename = "../../../etc/passwd"
    file_path = f"/app/uploads/{filename}"  # VULNERABLE: Path traversal
    
    print("Demonstrated insecure patterns:")
    print(f"- Hardcoded API key: {api_key[:10]}...")
    print(f"- Weak session token: {session_token}")
    print(f"- Unsafe command: {command}")
    print(f"- Unsafe file path: {file_path}")

def main():
    """
    Main function to run all vulnerability demonstrations
    """
    try:
        generate_vulnerability_report()
        print()
        print("ADDITIONAL SECURITY ISSUES:")
        print("-" * 50)
        demonstrate_insecure_patterns()
        
    except Exception as e:
        print(f"Demo error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()