# SonarQube Advanced Security - Dependency CVE Examples

This directory contains Python code examples specifically designed to test SonarQube's Advanced Security features, particularly dependency vulnerability scanning and license checking.

## Overview

These examples demonstrate how SonarQube Advanced Security detects:
- **Dependency CVEs**: Known security vulnerabilities in third-party packages
- **License Issues**: Incompatible or problematic licenses in dependencies
- **Security Hotspots**: Potentially vulnerable code patterns that become more dangerous with vulnerable dependencies

## Files in this Directory

### 1. `requirements.txt`
Contains intentionally vulnerable versions of popular Python packages with known CVEs:

| Package | Version | CVE | Description |
|---------|---------|-----|-------------|
| Flask | 2.2.2 | CVE-2023-30861 | Session cookie disclosure vulnerability |
| requests | 2.28.0 | CVE-2023-32681 | Proxy-Authorization header leakage |
| Pillow | 9.0.0 | CVE-2023-44271, CVE-2023-50447 | Image processing vulnerabilities |
| PyYAML | 5.3.1 | CVE-2020-14343 | Arbitrary code execution via unsafe loading |
| Jinja2 | 2.11.3 | CVE-2020-28493 | Template injection vulnerability |
| urllib3 | 1.26.5 | CVE-2023-43804 | Cookie injection vulnerability |
| cryptography | 3.4.8 | CVE-2023-23931 | Cipher vulnerability |
| Django | 3.2.13 | CVE-2023-31047 | SQL injection vulnerability |
| SQLAlchemy | 1.3.0 | CVE-2019-7164 | SQL injection in ORDER BY |
| tornado | 6.1 | CVE-2023-28370 | Cookie signature bypass |
| lxml | 4.6.5 | CVE-2022-2309 | XML External Entity (XXE) vulnerability |
| httplib2 | 0.18.1 | CVE-2021-21240 | CRLF injection vulnerability |

### 2. `flask_cve_demo.py`
Demonstrates Flask-related vulnerabilities:
- **CVE-2023-30861**: Flask session cookie vulnerability
- **CVE-2020-14343**: PyYAML unsafe loading
- **CVE-2020-28493**: Jinja2 template injection
- Path traversal vulnerabilities

### 3. `database_vulnerabilities.py`
Demonstrates database and framework vulnerabilities:
- **CVE-2019-7164**: SQLAlchemy SQL injection in ORDER BY clauses
- **CVE-2023-31047**: Django query handling vulnerabilities
- SQL injection patterns
- File handling vulnerabilities with Pillow CVEs

### 4. `xml_image_vulnerabilities.py`
Demonstrates XML and image processing vulnerabilities:
- **CVE-2022-2309**: lxml XXE (XML External Entity) attacks
- **CVE-2023-44271, CVE-2023-50447**: Pillow image processing vulnerabilities
- **CVE-2023-28370**: Tornado cookie handling vulnerabilities
- XML bomb attacks
- Unsafe file processing

### 5. `dependency_cve_demo.py`
General demonstration script that:
- Lists all vulnerable dependencies and their CVEs
- Shows risky usage patterns
- Demonstrates additional security anti-patterns
- Provides security recommendations

## How to Use These Examples

### 1. SonarQube Analysis Setup
Ensure your SonarQube instance has Advanced Security enabled and configured to scan this Python project.

### 2. Running the Analysis
```bash
# Run SonarQube analysis on the project
sonar-scanner \
  -Dsonar.projectKey=python-cve-demo \
  -Dsonar.sources=src/advanced-security-examples \
  -Dsonar.host.url=YOUR_SONARQUBE_URL \
  -Dsonar.login=YOUR_TOKEN
```

### 3. Expected Results
SonarQube Advanced Security should detect:

#### Dependency Vulnerabilities:
- 12+ CVEs from the vulnerable packages in `requirements.txt`
- High/Critical severity issues from cryptographic and web framework vulnerabilities
- Detailed CVE information with CVSS scores and remediation advice

#### Security Hotspots:
- Hardcoded secrets and credentials
- SQL injection patterns
- Path traversal vulnerabilities
- Weak cryptographic practices
- Insecure SSL/TLS configurations

#### License Issues:
- GPL-licensed dependencies (if any in the dependency tree)
- Copyleft license compatibility issues
- Commercial license usage tracking

## Security Testing Scenarios

### Scenario 1: Cryptographic Vulnerabilities
Run `crypto_vulnerabilities.py` to test detection of:
- Weak hash algorithms (MD5, SHA1)
- Deprecated encryption (DES, TripleDES)
- Insecure SSL configurations

### Scenario 2: Web Application Vulnerabilities
Run `flask_cve_demo.py` to test detection of:
- Template injection attacks
- YAML deserialization vulnerabilities
- Session management issues

### Scenario 3: Database Security
Run `database_vulnerabilities.py` to test detection of:
- SQL injection vulnerabilities
- ORM-specific security issues
- File upload vulnerabilities

### Scenario 4: XML and File Processing
Run `xml_image_vulnerabilities.py` to test detection of:
- XXE (XML External Entity) attacks
- XML bomb DoS attacks
- Image processing vulnerabilities

## Important Notes

⚠️ **WARNING**: These examples contain intentionally vulnerable code and dependencies. 
- **DO NOT** use these in production environments
- **DO NOT** install these vulnerable packages in production systems
- These are for testing SonarQube Advanced Security detection capabilities only

## Remediation Examples

To fix the detected issues:

1. **Update Dependencies**:
   ```bash
   pip install --upgrade flask requests pillow pyyaml jinja2
   ```

2. **Secure Coding Practices**:
   - Use parameterized queries instead of string concatenation
   - Enable SSL verification in HTTP clients
   - Use secure random number generators
   - Validate and sanitize all user inputs
   - Use secure YAML loading: `yaml.safe_load()` instead of `yaml.load()`

3. **Regular Security Scanning**:
   ```bash
   pip install safety bandit
   safety check
   bandit -r src/
   ```

## Integration with CI/CD

Add these checks to your pipeline:
```yaml
- name: Security Scan
  run: |
    pip install safety bandit
    safety check --json
    bandit -r src/ -f json
    sonar-scanner
```

This ensures continuous monitoring for new CVEs and security issues in your dependency tree.