#!/usr/bin/env python3
"""
Setup and Verification Script
Checks prerequisites, creates test account, and verifies endpoints before running tests
"""

import requests
import os
import sys
import time

# Configuration
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:5000")
API_BASE = f"{SERVER_URL}/api"
TEST_EMAIL = os.environ.get("TEST_EMAIL", "test@example.com")
TEST_PASSWORD = os.environ.get("TEST_PASSWORD", "Test123!@#")
IDS_URL = os.environ.get("IDS_URL", "http://localhost:6000")

def print_header(title):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def print_check(name, passed, details=""):
    status = "✅" if passed else "❌"
    print(f"{status} {name}")
    if details:
        print(f"   {details}")

def check_server_health():
    """Check if server is running"""
    print_header("Step 1: Checking Server Health")
    
    try:
        response = requests.get(f"{API_BASE}/health", timeout=3)
        if response.status_code == 200:
            print_check("Server is running", True, f"Response: {response.json()}")
            return True
        else:
            print_check("Server is running", False, f"Status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print_check("Server is running", False, "Cannot connect - is server running on port 5000?")
        print("\n   💡 Start server with: cd server && npm start")
        return False
    except Exception as e:
        print_check("Server is running", False, f"Error: {e}")
        return False

def check_ids_health():
    """Check if IDS service is running"""
    print_header("Step 2: Checking IDS Service Health")
    
    try:
        response = requests.get(f"{IDS_URL}/health", timeout=3)
        if response.status_code == 200:
            data = response.json() if response.text else {}
            print_check("IDS service is running", True, f"Response: {data}")
            return True
        else:
            print_check("IDS service is running", False, f"Status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print_check("IDS service is running", False, "Cannot connect - is IDS running on port 6000?")
        print("\n   💡 Start IDS with: cd ids_service && python app.py")
        return False
    except Exception as e:
        print_check("IDS service is running", False, f"Error: {e}")
        return False

def check_test_account():
    """Check if test account exists and can login"""
    print_header("Step 3: Checking Test Account")
    
    try:
        response = requests.post(
            f"{API_BASE}/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("token")
            if token:
                print_check("Test account exists", True, f"Email: {TEST_EMAIL}")
                print_check("Login successful", True, f"Token received: {token[:20]}...")
                return True, token
            else:
                print_check("Login successful", False, "No token in response")
                return False, None
        elif response.status_code == 401:
            print_check("Test account exists", False, "Invalid credentials or account doesn't exist")
            print(f"\n   💡 Attempting to create test account...")
            return create_test_account()
        else:
            print_check("Test account check", False, f"Status: {response.status_code}, Response: {response.text}")
            return False, None
            
    except Exception as e:
        print_check("Test account check", False, f"Error: {e}")
        return False, None

def create_test_account():
    """Create test account if it doesn't exist"""
    print_header("Creating Test Account")
    
    try:
        # Try to register
        response = requests.post(
            f"{API_BASE}/auth/register",
            json={
                "name": "Test User",
                "email": TEST_EMAIL,
                "password": TEST_PASSWORD
            },
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("token")
            print_check("Account created", True, f"Email: {TEST_EMAIL}")
            if token:
                print_check("Login successful", True, f"Token received")
                return True, token
            return True, None
        elif response.status_code == 409:
            print_check("Account creation", False, "Email already exists (but login failed - check password)")
            return False, None
        else:
            print_check("Account creation", False, f"Status: {response.status_code}, Response: {response.text}")
            return False, None
            
    except Exception as e:
        print_check("Account creation", False, f"Error: {e}")
        return False, None

def verify_endpoints(token):
    """Verify that API endpoints are accessible"""
    print_header("Step 4: Verifying API Endpoints")
    
    if not token:
        print_check("Endpoint verification", False, "No token available")
        return False
    
    endpoints_to_check = [
        ("Handshake Init", "POST", f"{API_BASE}/handshake/init", {"publicKey": "dGVzdA=="}),
        ("File Upload", "POST", f"{API_BASE}/files/upload", None),  # Will need multipart
        ("Health", "GET", f"{API_BASE}/health", None),
    ]
    
    all_passed = True
    
    for name, method, url, data in endpoints_to_check:
        try:
            if method == "GET":
                response = requests.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=3
                )
            else:
                response = requests.post(
                    url,
                    json=data,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=3
                )
            
            # For authenticated endpoints, 401 means auth works, 400/404 means endpoint exists
            # For upload, we expect 400 (no file) not 404
            if response.status_code in [200, 400, 403, 404]:
                status_ok = response.status_code != 404  # 404 means endpoint not found
                print_check(f"{name} endpoint", status_ok, f"Status: {response.status_code}")
                if not status_ok:
                    all_passed = False
            else:
                print_check(f"{name} endpoint", True, f"Status: {response.status_code}")
                
        except Exception as e:
            print_check(f"{name} endpoint", False, f"Error: {e}")
            all_passed = False
    
    return all_passed

def check_test_files():
    """Check if test files directory exists"""
    print_header("Step 5: Checking Test Files")
    
    from pathlib import Path
    test_dir = Path("test_files")
    
    if not test_dir.exists():
        print_check("Test files directory", False, f"Directory '{test_dir}' not found")
        print(f"\n   💡 Creating directory...")
        test_dir.mkdir(exist_ok=True)
        print_check("Test files directory created", True)
        return False
    
    print_check("Test files directory", True, f"Found: {test_dir}")
    
    # Check for specific files
    expected_files = [
        "corrupted_png.png",
        "corrupted_image.jpg",
        "excessive_nulls.bin",
        "repeated_pattern.bin",
        "suspicious_encrypted.bin"
    ]
    
    found_files = []
    for filename in expected_files:
        filepath = test_dir / filename
        if filepath.exists():
            found_files.append(filename)
            print_check(f"  {filename}", True, f"Size: {filepath.stat().st_size} bytes")
        else:
            print_check(f"  {filename}", False, "Not found")
    
    if len(found_files) > 0:
        print(f"\n   ✅ Found {len(found_files)}/{len(expected_files)} test files")
        return True
    else:
        print(f"\n   ⚠️  No test files found (some tests may create them automatically)")
        return True  # Still OK, some tests create files

def main():
    """Main verification function"""
    print("\n" + "="*70)
    print("  🔍 SETUP & VERIFICATION CHECK")
    print("="*70)
    print("\nThis script checks prerequisites before running security tests.")
    print(f"\nConfiguration:")
    print(f"   Server: {SERVER_URL}")
    print(f"   IDS: {IDS_URL}")
    print(f"   Test Email: {TEST_EMAIL}")
    print()
    
    input("Press Enter to continue or Ctrl+C to cancel...")
    
    results = {
        "server": False,
        "ids": False,
        "account": False,
        "endpoints": False,
        "files": False
    }
    
    # Step 1: Check server
    results["server"] = check_server_health()
    if not results["server"]:
        print("\n❌ Server is not running. Please start it first!")
        return False
    
    # Step 2: Check IDS
    results["ids"] = check_ids_health()
    if not results["ids"]:
        print("\n⚠️  IDS service is not running. Some tests may fail.")
        print("   Tests can still run, but IDS detection will be limited.")
    
    # Step 3: Check/Create account
    account_ok, token = check_test_account()
    results["account"] = account_ok
    
    if not account_ok:
        print("\n❌ Cannot authenticate. Please:")
        print(f"   1. Create account manually at {API_BASE}/auth/register")
        print(f"   2. Or check credentials: {TEST_EMAIL}")
        return False
    
    # Step 4: Verify endpoints
    results["endpoints"] = verify_endpoints(token)
    
    # Step 5: Check test files
    results["files"] = check_test_files()
    
    # Summary
    print_header("Summary")
    
    all_critical = results["server"] and results["account"]
    all_optional = results["ids"] and results["endpoints"] and results["files"]
    
    print(f"\nCritical Checks:")
    print(f"   {'✅' if results['server'] else '❌'} Server running")
    print(f"   {'✅' if results['account'] else '❌'} Test account ready")
    
    print(f"\nOptional Checks:")
    print(f"   {'✅' if results['ids'] else '⚠️ '} IDS service")
    print(f"   {'✅' if results['endpoints'] else '⚠️ '} API endpoints")
    print(f"   {'✅' if results['files'] else '⚠️ '} Test files")
    
    if all_critical:
        print("\n" + "="*70)
        print("  ✅ READY TO RUN TESTS!")
        print("="*70)
        print("\nAll critical checks passed. You can now run:")
        print("   python run_full_security_tests.py")
        print("\nOr run individual tests:")
        print("   python client/client.py")
        print("   python attack_simulator.py")
        print("   python upload_corrupted_file.py")
        return True
    else:
        print("\n" + "="*70)
        print("  ❌ NOT READY - Fix issues above")
        print("="*70)
        return False

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

