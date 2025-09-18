#!/usr/bin/env python3
"""
XML and Image Processing Vulnerabilities Demo
Demonstrates CVE issues in lxml, Pillow, and related packages.
"""

import xml.etree.ElementTree as ET
from io import BytesIO
import base64

try:
    from lxml import etree
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False
    print("lxml not installed - this is expected for dependency scanning demo")

try:
    from PIL import Image, ImageFile
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    print("Pillow not installed - this is expected for dependency scanning demo")

class XMLImageVulnerabilityDemo:
    """
    Demonstrates XML and image processing vulnerabilities
    """
    
    def __init__(self):
        pass
    
    def xml_external_entity_demo(self):
        """
        CVE-2022-2309: lxml XXE (XML External Entity) vulnerability
        Demonstrates XXE attack patterns
        """
        if not LXML_AVAILABLE:
            return "lxml not available - CVE scanning will still detect vulnerability"
        
        # VULNERABLE: XML with external entity reference
        malicious_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>"""
        
        try:
            # VULNERABLE: lxml parsing without disabling external entities
            # CVE-2022-2309 affects this version
            parser = etree.XMLParser()  # VULNERABLE: Default parser allows XXE
            root = etree.fromstring(malicious_xml.encode(), parser)  # VULNERABLE
            
            # Extract potentially sensitive data
            data_element = root.find('data')
            return data_element.text if data_element is not None else "No data found"
            
        except Exception as e:
            return f"XML parsing error (expected): {e}"
    
    def xml_bomb_demo(self):
        """
        Demonstrates XML bomb (billion laughs) attack
        """
        # VULNERABLE: XML bomb that can cause DoS
        xml_bomb = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>"""
        
        try:
            # VULNERABLE: Parsing XML bomb without limits
            root = ET.fromstring(xml_bomb)  # VULNERABLE
            return root.text
        except Exception as e:
            return f"XML bomb error (expected): {e}"
    
    def pillow_vulnerability_demo(self):
        """
        CVE-2023-44271, CVE-2023-50447: Pillow vulnerabilities
        Demonstrates image processing vulnerabilities
        """
        if not PILLOW_AVAILABLE:
            return "Pillow not available - CVE scanning will still detect vulnerability"
        
        # Create a small test image
        test_image_data = base64.b64decode(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=='
        )
        
        try:
            # VULNERABLE: Loading images without validation
            # CVE-2023-44271 and CVE-2023-50447 affect this Pillow version
            image = Image.open(BytesIO(test_image_data))  # VULNERABLE
            
            # VULNERABLE: Processing images without size limits
            # This could be exploited with malicious images in vulnerable Pillow versions
            processed = image.resize((1000000, 1000000))  # VULNERABLE: No size limits
            
            return f"Processed image size: {processed.size}"
            
        except Exception as e:
            return f"Image processing error: {e}"
    
    def unsafe_file_processing(self):
        """
        Demonstrates unsafe file processing patterns that could be exploited
        with vulnerable image processing libraries
        """
        # VULNERABLE: Processing files without validation
        suspicious_filename = "../../etc/passwd.jpg"  # Path traversal attempt
        
        # This pattern is dangerous when combined with vulnerable image libraries
        file_path = f"/uploads/{suspicious_filename}"  # VULNERABLE: No path sanitization
        
        try:
            # Simulate file processing that could trigger vulnerabilities
            # in vulnerable Pillow versions
            if PILLOW_AVAILABLE:
                # VULNERABLE: Opening files without validation
                with open('/dev/null', 'rb') as f:  # Safe fallback for demo
                    fake_image_data = f.read()
                
                return f"Would process file: {file_path}"
            else:
                return f"Would process file: {file_path} (Pillow not available)"
                
        except Exception as e:
            return f"File processing error: {e}"
    
    def tornado_vulnerability_demo(self):
        """
        CVE-2023-28370: Tornado vulnerability
        Demonstrates web framework vulnerabilities
        """
        # VULNERABLE: Tornado cookie handling vulnerability
        # This version has issues with cookie signature verification
        
        cookie_data = {
            'user_id': '1',
            'is_admin': 'true',
            'signature': 'fake_signature'  # VULNERABLE: Weak signature
        }
        
        # Simulate vulnerable cookie processing
        # CVE-2023-28370 affects cookie signature verification
        def vulnerable_cookie_decode(cookie_value):
            # VULNERABLE: No proper signature verification
            # This pattern is vulnerable in the specified Tornado version
            return eval(cookie_value)  # EXTREMELY VULNERABLE: eval usage
        
        try:
            # This would be vulnerable if Tornado was actually processing it
            result = f"Cookie processing simulation: {cookie_data}"
            return result
        except Exception as e:
            return f"Cookie processing error: {e}"

def main():
    """
    Main function to demonstrate XML and image processing vulnerabilities
    """
    demo = XMLImageVulnerabilityDemo()
    
    print("=== XML and Image Processing CVE Demonstration ===")
    print("Testing vulnerable dependencies for SonarQube Advanced Security")
    print()
    
    print("1. XML External Entity (XXE) Demo:")
    xxe_result = demo.xml_external_entity_demo()
    print(f"Result: {xxe_result}")
    print()
    
    print("2. XML Bomb Demo:")
    bomb_result = demo.xml_bomb_demo()
    print(f"Result: {bomb_result}")
    print()
    
    print("3. Pillow Image Processing Demo:")
    pillow_result = demo.pillow_vulnerability_demo()
    print(f"Result: {pillow_result}")
    print()
    
    print("4. Unsafe File Processing Demo:")
    file_result = demo.unsafe_file_processing()
    print(f"Result: {file_result}")
    print()
    
    print("5. Tornado Cookie Vulnerability Demo:")
    tornado_result = demo.tornado_vulnerability_demo()
    print(f"Result: {tornado_result}")
    print()
    
    print("Advanced Security should detect multiple dependency CVEs in requirements.txt")

if __name__ == "__main__":
    main()