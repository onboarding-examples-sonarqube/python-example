#!/usr/bin/env python3
"""
Cryptography and HTTP Vulnerabilities Demo
Demonstrates CVE issues in cryptography, requests, and urllib3 packages.
"""

import ssl
import hashlib
import requests
import urllib3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import httplib2

# Disable SSL warnings for demonstration purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CryptographyVulnerabilityDemo:
    """
    Demonstrates various cryptographic vulnerabilities that SonarQube Advanced Security should detect
    """
    
    def __init__(self):
        pass
    
    def weak_hash_demo(self):
        """
        Demonstrates use of weak hashing algorithms
        """
        # VULNERABLE: MD5 is cryptographically broken
        data = b"sensitive data"
        md5_hash = hashlib.md5(data).hexdigest()  # SonarQube should flag this
        
        # VULNERABLE: SHA1 is considered weak
        sha1_hash = hashlib.sha1(data).hexdigest()  # SonarQube should flag this
        
        return md5_hash, sha1_hash
    
    def weak_encryption_demo(self):
        """
        CVE-2023-23931: Cryptography package vulnerability
        Demonstrates weak encryption practices
        """
        # VULNERABLE: DES is a weak cipher
        key = b'01234567'  # 8 bytes for DES
        plaintext = b'Hello World!'
        
        # This version of cryptography has known vulnerabilities
        cipher = Cipher(
            algorithms.TripleDES(key),  # VULNERABLE: TripleDES is deprecated
            modes.ECB(),  # VULNERABLE: ECB mode is insecure
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        # Pad the plaintext to be a multiple of 8 bytes
        padded = plaintext + b' ' * (8 - len(plaintext) % 8)
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        
        return ciphertext
    
    def insecure_ssl_demo(self):
        """
        Demonstrates SSL/TLS vulnerabilities
        CVE-2023-32681: Requests package vulnerability
        """
        # VULNERABLE: Disabling SSL verification
        # CVE-2023-32681 affects this version of requests
        try:
            response = requests.get(
                'https://httpbin.org/get',
                verify=False,  # VULNERABLE: SSL verification disabled
                timeout=5
            )
            return response.status_code
        except Exception as e:
            return f"Request failed: {e}"
    
    def urllib3_vulnerability_demo(self):
        """
        CVE-2023-43804: urllib3 cookie injection vulnerability
        Demonstrates vulnerable urllib3 usage
        """
        # VULNERABLE: This version of urllib3 has cookie injection issues
        http = urllib3.PoolManager()
        
        # VULNERABLE: Disabling SSL warnings and verification
        response = http.request(
            'GET',
            'https://httpbin.org/get',
            headers={'User-Agent': 'VulnerableApp/1.0'},
            timeout=5
        )
        
        return response.status
    
    def httplib2_vulnerability_demo(self):
        """
        CVE-2021-21240: httplib2 CRLF injection vulnerability
        """
        # VULNERABLE: This version of httplib2 is susceptible to CRLF injection
        h = httplib2.Http(disable_ssl_certificate_validation=True)  # VULNERABLE
        
        try:
            response, content = h.request('https://httpbin.org/get', 'GET')
            return response.status
        except Exception as e:
            return f"httplib2 request failed: {e}"

def main():
    """
    Main function to demonstrate various vulnerability types
    """
    demo = CryptographyVulnerabilityDemo()
    
    print("=== Advanced Security CVE Demonstration ===")
    print("This script uses vulnerable dependencies to test SonarQube Advanced Security")
    print()
    
    # Demonstrate weak hashing
    print("1. Testing weak hash algorithms...")
    md5, sha1 = demo.weak_hash_demo()
    print(f"MD5: {md5}")
    print(f"SHA1: {sha1}")
    print()
    
    # Demonstrate weak encryption
    print("2. Testing weak encryption...")
    encrypted = demo.weak_encryption_demo()
    print(f"Encrypted data: {encrypted.hex()}")
    print()
    
    # Demonstrate SSL vulnerabilities
    print("3. Testing SSL vulnerabilities...")
    status = demo.insecure_ssl_demo()
    print(f"Request status: {status}")
    print()
    
    # Demonstrate urllib3 vulnerabilities
    print("4. Testing urllib3 vulnerabilities...")
    urllib_status = demo.urllib3_vulnerability_demo()
    print(f"urllib3 status: {urllib_status}")
    print()
    
    # Demonstrate httplib2 vulnerabilities
    print("5. Testing httplib2 vulnerabilities...")
    httplib_status = demo.httplib2_vulnerability_demo()
    print(f"httplib2 status: {httplib_status}")

if __name__ == "__main__":
    main()