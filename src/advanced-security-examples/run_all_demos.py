#!/usr/bin/env python3
"""
Advanced Security Demo Runner
Executes all vulnerability demonstration scripts for SonarQube Advanced Security testing.
"""

import sys
import os
import subprocess
from pathlib import Path

def run_demo_script(script_name):
    """
    Run a demonstration script and capture output
    """
    script_path = Path(__file__).parent / script_name
    
    print(f"\n{'='*60}")
    print(f"Running: {script_name}")
    print(f"{'='*60}")
    
    try:
        if script_path.exists():
            # Run the script and capture output
            result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.stdout:
                print("STDOUT:")
                print(result.stdout)
            
            if result.stderr:
                print("STDERR:")
                print(result.stderr)
            
            if result.returncode != 0:
                print(f"Script exited with code: {result.returncode}")
                
        else:
            print(f"Script not found: {script_path}")
            
    except subprocess.TimeoutExpired:
        print("Script timed out after 30 seconds")
    except Exception as e:
        print(f"Error running script: {e}")

def list_vulnerable_dependencies():
    """
    List all vulnerable dependencies from requirements.txt
    """
    print("\n" + "="*60)
    print("VULNERABLE DEPENDENCIES ANALYSIS")
    print("="*60)
    
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    if requirements_file.exists():
        print("Reading requirements.txt...")
        with open(requirements_file, 'r') as f:
            content = f.read()
        
        print(content)
    else:
        print("requirements.txt not found")

def main():
    """
    Main function to run all Advanced Security demonstrations
    """
    print("SonarQube Advanced Security - CVE and License Demo Runner")
    print("This script demonstrates various dependency vulnerabilities")
    print("for testing SonarQube's Advanced Security features.")
    print()
    print("⚠️  WARNING: This code contains intentionally vulnerable dependencies!")
    print("   DO NOT use in production environments.")
    print()
    
    # List vulnerable dependencies
    list_vulnerable_dependencies()
    
    # Run each demo script
    demo_scripts = [
        "dependency_cve_demo.py",
        "flask_cve_demo.py", 
        "database_vulnerabilities.py",
        "xml_image_vulnerabilities.py"
    ]
    
    for script in demo_scripts:
        run_demo_script(script)
    
    print(f"\n{'='*60}")
    print("DEMO COMPLETE")
    print(f"{'='*60}")
    print()
    print("Next Steps:")
    print("1. Run SonarQube analysis on this directory")
    print("2. Check the SonarQube dashboard for detected CVEs")
    print("3. Review Security Hotspots in the Advanced Security section")
    print("4. Examine license compliance reports")
    print("5. Test remediation by updating requirements.txt to secure versions")

if __name__ == "__main__":
    main()