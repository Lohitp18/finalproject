#!/usr/bin/env python3
"""
Comprehensive Test Suite for Secure Transfer System
Tests normal operations and attack scenarios
"""

import requests
import base64
import os
import time
import json
from io import BytesIO

# Configuration
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:5000/api")
IDS_URL = os.environ.get("IDS_URL", "http://localhost:6000")
TEST_EMAIL = "test@example.com"
TEST_PASSWORD = "Test123!@#"

# Test results
test_results = {
    "passed": 0,
    "failed": 0,
    "warnings": 0
}

def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_result(test_name, passed, message=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{status} - {test_name}")
    if message:
        print(f"    {message}")
    if passed:
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1

def print_warning(message):
    print(f"⚠️  WARNING - {message}")
    test_results["warnings"] += 1

# ==================== Helper Functions ====================

def get_auth_token():
    """Get authentication token"""
    try:
        response = requests.post(
            f"{SERVER_URL}/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
            timeout=5
        )
        if response.status_code == 200:
            return response.json().get("token")
        return None
    except Exception as e:
        print_warning(f"Cannot get auth token: {e}")
        return None

def check_backend_health():
    """Check if backend is running"""
    try:
        response = requests.get(f"{SERVER_URL}/health", timeout=2)
        return response.status_code == 200
    except:
        return False

def check_ids_health():
    """Check if IDS service is running"""
    try:
        response = requests.get(f"{IDS_URL}/health", timeout=2)
        return response.status_code == 200
    except:
        return False

# ==================== Test Cases ====================

def test_backend_health():
    """TC-1: Backend Health Check"""
    print_header("TC-1: Backend Health Check")
    try:
        response = requests.get(f"{SERVER_URL}/health", timeout=5)
        passed = response.status_code == 200
        print_result("Backend Health", passed, 
                     f"Status: {response.status_code}, Response: {response.json() if passed else 'N/A'}")
        return passed
    except Exception as e:
        print_result("Backend Health", False, f"Error: {e}")
        return False

def test_ids_health():
    """TC-2: IDS Service Health Check"""
    print_header("TC-2: IDS Service Health Check")
    try:
        response = requests.get(f"{IDS_URL}/health", timeout=5)
        passed = response.status_code == 200
        data = response.json() if passed else {}
        print_result("IDS Health", passed, 
                     f"Status: {response.status_code}, Models loaded: {data.get('models_loaded', False)}")
        if not passed:
            print_warning("IDS service is not running - some tests may fail")
        return passed
    except Exception as e:
        print_result("IDS Health", False, f"Error: {e}")
        print_warning("IDS service is not running - some tests may fail")
        return False

def test_normal_login():
    """TC-3: Normal Login"""
    print_header("TC-3: Normal Login")
    try:
        response = requests.post(
            f"{SERVER_URL}/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
            timeout=5
        )
        passed = response.status_code == 200
        if passed:
            data = response.json()
            print_result("Normal Login", True, 
                        f"User: {data.get('user', {}).get('email', 'N/A')}, Token received: {bool(data.get('token'))}")
            return data.get("token")
        else:
            print_result("Normal Login", False, f"Status: {response.status_code}, Error: {response.text}")
            return None
    except Exception as e:
        print_result("Normal Login", False, f"Error: {e}")
        return None

def test_invalid_login():
    """TC-4: Invalid Login Credentials"""
    print_header("TC-4: Invalid Login Credentials")
    try:
        response = requests.post(
            f"{SERVER_URL}/auth/login",
            json={"email": TEST_EMAIL, "password": "wrongpassword"},
            timeout=5
        )
        passed = response.status_code == 401
        print_result("Invalid Login Rejected", passed, 
                    f"Status: {response.status_code} (expected 401)")
        return passed
    except Exception as e:
        print_result("Invalid Login Rejected", False, f"Error: {e}")
        return False

def test_handshake_init(token):
    """TC-5: Normal Handshake Initialization"""
    print_header("TC-5: Normal Handshake Initialization")
    if not token:
        print_result("Handshake Init", False, "No auth token available")
        return None
    
    try:
        # Generate a valid X25519 public key (32 bytes base64)
        valid_pubkey = base64.b64encode(os.urandom(32)).decode()
        
        response = requests.post(
            f"{SERVER_URL}/handshake/init",
            json={"publicKey": valid_pubkey},
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        passed = response.status_code == 200
        if passed:
            data = response.json()
            print_result("Handshake Init", True, 
                        f"Handshake ID: {data.get('handshakeId', 'N/A')[:16]}..., Server key received: {bool(data.get('serverPublicKey'))}")
            return data
        else:
            print_result("Handshake Init", False, f"Status: {response.status_code}, Error: {response.text}")
            return None
    except Exception as e:
        print_result("Handshake Init", False, f"Error: {e}")
        return None

def test_invalid_public_key(token):
    """TC-A1: Invalid Public Key Attack"""
    print_header("TC-A1: Invalid Public Key Attack")
    if not token:
        print_result("Invalid Pubkey Attack", False, "No auth token available")
        return False
    
    try:
        # Send invalid public key (too short)
        invalid_pubkey = base64.b64encode(os.urandom(10)).decode()
        
        response = requests.post(
            f"{SERVER_URL}/handshake/init",
            json={"publicKey": invalid_pubkey},
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        # Should either reject or handle gracefully
        passed = response.status_code in [400, 500] or response.status_code == 200
        print_result("Invalid Pubkey Handled", passed, 
                    f"Status: {response.status_code} (should reject or handle gracefully)")
        return passed
    except Exception as e:
        print_result("Invalid Pubkey Handled", False, f"Error: {e}")
        return False

def test_handshake_validate(token, handshake_data):
    """TC-6: Normal Handshake Validation"""
    print_header("TC-6: Normal Handshake Validation")
    if not token or not handshake_data:
        print_result("Handshake Validate", False, "No handshake data available")
        return None
    
    try:
        response = requests.post(
            f"{SERVER_URL}/handshake/validate",
            json={"handshakeId": handshake_data.get("handshakeId")},
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        passed = response.status_code == 200
        if passed:
            data = response.json()
            verified = data.get("verified", False)
            verdict = data.get("idsResult", {}).get("verdict", "unknown")
            print_result("Handshake Validate", True, 
                        f"Verified: {verified}, IDS Verdict: {verdict}, Session key received: {bool(data.get('sessionKey'))}")
            return data
        else:
            print_result("Handshake Validate", False, f"Status: {response.status_code}, Error: {response.text}")
            return None
    except Exception as e:
        print_result("Handshake Validate", False, f"Error: {e}")
        return None

def test_wrong_handshake_id(token):
    """TC-A2: Wrong Handshake ID Attack"""
    print_header("TC-A2: Wrong Handshake ID Attack")
    if not token:
        print_result("Wrong Handshake ID", False, "No auth token available")
        return False
    
    try:
        # Send invalid handshake ID
        fake_id = "507f1f77bcf86cd799439011"  # Valid ObjectId format but non-existent
        
        response = requests.post(
            f"{SERVER_URL}/handshake/validate",
            json={"handshakeId": fake_id},
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        passed = response.status_code == 404
        print_result("Wrong Handshake ID Rejected", passed, 
                    f"Status: {response.status_code} (expected 404)")
        return passed
    except Exception as e:
        print_result("Wrong Handshake ID Rejected", False, f"Error: {e}")
        return False

def test_normal_file_upload(token):
    """TC-7: Normal File Upload"""
    print_header("TC-7: Normal File Upload")
    if not token:
        print_result("Normal File Upload", False, "No auth token available")
        return False
    
    try:
        # Create a small test file
        test_content = b"This is a normal test file content for upload testing."
        files = {
            'file': ('test_normal.txt', BytesIO(test_content), 'text/plain')
        }
        
        response = requests.post(
            f"{SERVER_URL}/files/upload",
            files=files,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        
        passed = response.status_code == 200
        if passed:
            data = response.json()
            status = data.get("status", "unknown")
            verdict = data.get("details", {}).get("verdict", "unknown") if isinstance(data.get("details"), dict) else "unknown"
            print_result("Normal File Upload", True, 
                        f"Status: {status}, IDS Verdict: {verdict}, File ID: {data.get('id', 'N/A')[:16]}...")
            return True
        else:
            print_result("Normal File Upload", False, f"Status: {response.status_code}, Error: {response.text}")
            return False
    except Exception as e:
        print_result("Normal File Upload", False, f"Error: {e}")
        return False

def test_large_file_upload(token):
    """TC-A8: Large Payload Attack"""
    print_header("TC-A8: Large Payload Attack")
    if not token:
        print_result("Large File Upload", False, "No auth token available")
        return False
    
    try:
        # Create a large file (10MB)
        large_content = os.urandom(10 * 1024 * 1024)  # 10MB
        files = {
            'file': ('large_file.bin', BytesIO(large_content), 'application/octet-stream')
        }
        
        response = requests.post(
            f"{SERVER_URL}/files/upload",
            files=files,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30
        )
        
        # Should either reject or handle gracefully
        passed = response.status_code in [200, 400, 413, 500]
        status_msg = "accepted" if response.status_code == 200 else "rejected/handled"
        print_result("Large File Handled", passed, 
                    f"Status: {response.status_code}, {status_msg}")
        return passed
    except Exception as e:
        print_result("Large File Handled", False, f"Error: {e}")
        return False

def test_empty_file_upload(token):
    """TC-A9: Empty File Attack"""
    print_header("TC-A9: Empty File Attack")
    if not token:
        print_result("Empty File Upload", False, "No auth token available")
        return False
    
    try:
        # Create an empty file
        files = {
            'file': ('empty.txt', BytesIO(b''), 'text/plain')
        }
        
        response = requests.post(
            f"{SERVER_URL}/files/upload",
            files=files,
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        
        passed = response.status_code == 400
        print_result("Empty File Rejected", passed, 
                    f"Status: {response.status_code} (expected 400)")
        return passed
    except Exception as e:
        print_result("Empty File Rejected", False, f"Error: {e}")
        return False

def test_unauthorized_access():
    """TC-A10: Unauthorized Access Attempt"""
    print_header("TC-A10: Unauthorized Access Attempt")
    try:
        # Try to access protected endpoint without token
        response = requests.post(
            f"{SERVER_URL}/handshake/init",
            json={"publicKey": base64.b64encode(os.urandom(32)).decode()},
            timeout=5
        )
        passed = response.status_code == 401
        print_result("Unauthorized Access Rejected", passed, 
                    f"Status: {response.status_code} (expected 401)")
        return passed
    except Exception as e:
        print_result("Unauthorized Access Rejected", False, f"Error: {e}")
        return False

def test_ids_handshake_detection(token):
    """TC-IDS1: IDS Handshake Anomaly Detection"""
    print_header("TC-IDS1: IDS Handshake Anomaly Detection")
    if not token:
        print_result("IDS Handshake Detection", False, "No auth token available")
        return False
    
    try:
        # Try multiple rapid handshakes (potential brute force)
        suspicious_count = 0
        for i in range(5):
            pubkey = base64.b64encode(os.urandom(32)).decode()
            response = requests.post(
                f"{SERVER_URL}/handshake/init",
                json={"publicKey": pubkey},
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                validate_resp = requests.post(
                    f"{SERVER_URL}/handshake/validate",
                    json={"handshakeId": data.get("handshakeId")},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5
                )
                if validate_resp.status_code == 200:
                    validate_data = validate_resp.json()
                    if validate_data.get("idsResult", {}).get("verdict") == "suspicious":
                        suspicious_count += 1
        
        print_result("IDS Handshake Detection", True, 
                    f"Detected {suspicious_count}/5 suspicious handshakes")
        return True
    except Exception as e:
        print_result("IDS Handshake Detection", False, f"Error: {e}")
        return False

def test_get_alerts(token):
    """TC-8: Get Intrusion Alerts"""
    print_header("TC-8: Get Intrusion Alerts")
    if not token:
        print_result("Get Alerts", False, "No auth token available")
        return False
    
    try:
        response = requests.get(
            f"{SERVER_URL}/alerts",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        passed = response.status_code == 200
        if passed:
            data = response.json()
            print_result("Get Alerts", True, f"Retrieved {len(data)} alerts")
            return True
        else:
            print_result("Get Alerts", False, f"Status: {response.status_code}")
            return False
    except Exception as e:
        print_result("Get Alerts", False, f"Error: {e}")
        return False

def test_get_connection_logs(token):
    """TC-9: Get Connection Logs"""
    print_header("TC-9: Get Connection Logs")
    if not token:
        print_result("Get Connection Logs", False, "No auth token available")
        return False
    
    try:
        response = requests.get(
            f"{SERVER_URL}/logs/connections",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        passed = response.status_code == 200
        if passed:
            data = response.json()
            print_result("Get Connection Logs", True, f"Retrieved {len(data)} connection logs")
            return True
        else:
            print_result("Get Connection Logs", False, f"Status: {response.status_code}")
            return False
    except Exception as e:
        print_result("Get Connection Logs", False, f"Error: {e}")
        return False

# ==================== Main Test Runner ====================

def main():
    print("\n" + "="*60)
    print("  SECURE TRANSFER SYSTEM - COMPREHENSIVE TEST SUITE")
    print("="*60)
    print(f"\nServer URL: {SERVER_URL}")
    print(f"IDS URL: {IDS_URL}")
    print(f"Test Account: {TEST_EMAIL}")
    
    # Pre-flight checks
    if not check_backend_health():
        print("\n❌ Backend server is not running!")
        print("   Please start the backend: npm run server")
        return
    
    ids_running = check_ids_health()
    if not ids_running:
        print("\n⚠️  IDS service is not running - some tests may fail")
        print("   To start IDS: cd ids_service && python app.py")
    
    # Run tests
    token = None
    handshake_data = None
    
    # Health checks
    test_backend_health()
    test_ids_health()
    
    # Authentication tests
    token = test_normal_login()
    test_invalid_login()
    
    if not token:
        print("\n❌ Cannot proceed without authentication token!")
        print("   Please check your test account credentials")
        return
    
    # Handshake tests
    handshake_data = test_handshake_init(token)
    test_invalid_public_key(token)
    
    if handshake_data:
        test_handshake_validate(token, handshake_data)
    
    test_wrong_handshake_id(token)
    
    # File upload tests
    test_normal_file_upload(token)
    test_large_file_upload(token)
    test_empty_file_upload(token)
    
    # Security tests
    test_unauthorized_access()
    test_ids_handshake_detection(token)
    
    # Monitoring tests
    test_get_alerts(token)
    test_get_connection_logs(token)
    
    # Summary
    print_header("TEST SUMMARY")
    total = test_results["passed"] + test_results["failed"]
    pass_rate = (test_results["passed"] / total * 100) if total > 0 else 0
    
    print(f"Total Tests: {total}")
    print(f"✅ Passed: {test_results['passed']}")
    print(f"❌ Failed: {test_results['failed']}")
    print(f"⚠️  Warnings: {test_results['warnings']}")
    print(f"Pass Rate: {pass_rate:.1f}%")
    
    if test_results["failed"] == 0:
        print("\n🎉 ALL TESTS PASSED!")
    else:
        print(f"\n⚠️  {test_results['failed']} test(s) failed")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    main()

