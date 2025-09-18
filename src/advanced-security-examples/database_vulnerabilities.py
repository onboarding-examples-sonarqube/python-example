#!/usr/bin/env python3
"""
Django and Database Vulnerabilities Demo
Demonstrates CVE issues in Django, SQLAlchemy and database-related packages.
"""

import sqlite3
import os
from datetime import datetime

# Simulating Django imports (would normally require Django to be installed)
# These imports will trigger dependency vulnerability scanning
try:
    from django.db import models
    from django.http import HttpResponse
    from django.shortcuts import render
    from django.contrib.auth.models import User
    from django.db.models import Q
    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False
    print("Django not installed - this is expected for dependency scanning demo")

try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    print("SQLAlchemy not installed - this is expected for dependency scanning demo")

class DatabaseVulnerabilityDemo:
    """
    Demonstrates database-related vulnerabilities for Advanced Security testing
    """
    
    def __init__(self):
        self.db_path = ":memory:"  # In-memory SQLite for demo
    
    def sql_injection_demo(self):
        """
        Demonstrates SQL injection vulnerability patterns
        CVE-2019-7164: SQLAlchemy vulnerable to SQL injection
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create a demo table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                email TEXT,
                created_at TEXT
            )
        """)
        
        # Insert demo data
        cursor.execute(
            "INSERT INTO users (username, email, created_at) VALUES (?, ?, ?)",
            ("testuser", "test@example.com", datetime.now().isoformat())
        )
        
        # VULNERABLE: SQL injection through string formatting
        # This pattern is vulnerable when combined with vulnerable SQLAlchemy versions
        user_id = "1 OR 1=1"  # Simulated malicious input
        query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE
        
        try:
            cursor.execute(query)
            results = cursor.fetchall()
        except Exception as e:
            results = f"SQL Error (expected): {e}"
        
        conn.close()
        return results
    
    def sqlalchemy_vulnerability_demo(self):
        """
        Demonstrates SQLAlchemy specific vulnerabilities
        CVE-2019-7164: Order By SQL injection
        """
        if not SQLALCHEMY_AVAILABLE:
            return "SQLAlchemy not available for demo"
        
        try:
            # Create in-memory SQLite database
            engine = create_engine('sqlite:///:memory:')
            Session = sessionmaker(bind=engine)
            session = Session()
            
            # VULNERABLE: Using text() with user input in vulnerable SQLAlchemy version
            # CVE-2019-7164 affects order by clauses
            user_order = "id DESC; DROP TABLE users; --"  # Malicious input
            
            # This pattern is vulnerable in the specified SQLAlchemy version
            query = text(f"SELECT 1 ORDER BY {user_order}")  # VULNERABLE
            
            result = session.execute(query)
            return result.fetchall()
            
        except Exception as e:
            return f"SQLAlchemy error (expected): {e}"
    
    def file_handling_vulnerability(self):
        """
        Demonstrates file handling vulnerabilities that could be exploited
        with vulnerable Pillow versions
        """
        # This simulates file upload handling that could be vulnerable
        # when combined with Pillow CVE-2023-44271, CVE-2023-50447
        
        temp_dir = "/tmp/vulnerable_uploads"
        
        try:
            os.makedirs(temp_dir, exist_ok=True)
            
            # VULNERABLE: No file type validation
            # With vulnerable Pillow, this could lead to code execution
            filename = "../../../etc/passwd"  # Path traversal attempt
            full_path = os.path.join(temp_dir, filename)  # VULNERABLE
            
            return f"Would process file at: {full_path}"
            
        except Exception as e:
            return f"File handling error: {e}"

def django_vulnerability_demo():
    """
    CVE-2023-31047: Django vulnerability demonstration
    This function shows patterns that could be vulnerable with the specified Django version
    """
    if not DJANGO_AVAILABLE:
        return "Django not available - dependency vulnerability scanning will still detect CVE"
    
    # VULNERABLE: Raw SQL query construction (Django pattern)
    # CVE-2023-31047 affects query handling in this Django version
    user_input = "admin'; DROP TABLE auth_user; --"
    
    # This pattern is vulnerable in the specified Django version
    raw_query = f"SELECT * FROM auth_user WHERE username = '{user_input}'"  # VULNERABLE
    
    return f"Generated vulnerable query: {raw_query}"

def main():
    """
    Main function to run all vulnerability demonstrations
    """
    print("=== Database and Framework CVE Demonstration ===")
    print("Testing vulnerable dependencies for SonarQube Advanced Security")
    print()
    
    demo = DatabaseVulnerabilityDemo()
    
    print("1. SQL Injection Demo:")
    sql_result = demo.sql_injection_demo()
    print(f"Result: {sql_result}")
    print()
    
    print("2. SQLAlchemy Vulnerability Demo:")
    sqlalchemy_result = demo.sqlalchemy_vulnerability_demo()
    print(f"Result: {sqlalchemy_result}")
    print()
    
    print("3. File Handling Vulnerability Demo:")
    file_result = demo.file_handling_vulnerability()
    print(f"Result: {file_result}")
    print()
    
    print("4. Django Vulnerability Demo:")
    django_result = django_vulnerability_demo()
    print(f"Result: {django_result}")
    print()
    
    print("Note: These examples use vulnerable dependency versions")
    print("SonarQube Advanced Security should detect multiple CVEs in the requirements.txt")

if __name__ == "__main__":
    main()