# 🔧 Fixes Applied - Test Suite

## Overview

All test scripts have been verified and are correctly configured for your server structure. The routes match perfectly:
- ✅ Server uses `/api` prefix - tests use `http://localhost:5000/api`
- ✅ Auth endpoint: `/api/auth/login` - correctly configured
- ✅ Handshake: `/api/handshake/init` and `/api/handshake/validate` - correct
- ✅ Upload: `/api/files/upload` - correct

## New File Created

### `setup_and_verify.py`
**Purpose:** Comprehensive prerequisite checker that:
- ✅ Checks if server is running
- ✅ Checks if IDS service is running  
- ✅ Creates test account if it doesn't exist
- ✅ Verifies API endpoints are accessible
- ✅ Checks test files exist

**Usage:**
```bash
python setup_and_verify.py
```

This runs BEFORE running tests to ensure everything is ready.

---

## Quick Fix Guide

### If Tests Fail - Run This First:

```bash
# 1. Verify everything is ready
python setup_and_verify.py

# 2. If setup passes, run tests
python run_full_security_tests.py
```

---

## Common Issues & Solutions

### Issue 1: "Cannot connect to server"
**Solution:**
```bash
# Start server in one terminal
cd server
npm start

# Verify it's running
curl http://localhost:5000/api/health
```

### Issue 2: "Auth failed" or "Invalid credentials"
**Solution:**
```bash
# Run setup script - it will create account if needed
python setup_and_verify.py

# OR manually create account:
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"test@example.com","password":"Test123!@#"}'
```

### Issue 3: "IDS service error"
**Solution:**
```bash
# Start IDS service in separate terminal
cd ids_service
python app.py

# Verify it's running
curl http://localhost:6000/health

# If models missing, train them:
python enhanced_train.py
```

### Issue 4: "File not found: test_files/..."
**Solution:**
```bash
# Create test files directory if missing
mkdir test_files

# Create corrupted files (or they're created automatically)
node create_corrupted_files.js
```

---

## Updated Test Workflow

### Recommended Workflow:

1. **Start Services:**
   ```bash
   # Terminal 1: Server
   cd server && npm start
   
   # Terminal 2: IDS
   cd ids_service && python app.py
   ```

2. **Verify Setup:**
   ```bash
   # Terminal 3: Verify
   python setup_and_verify.py
   ```

3. **Run Tests:**
   ```bash
   python run_full_security_tests.py
   ```

---

## What's Already Correct

✅ **Test Scripts:**
- All use correct `/api` prefix
- All use correct authentication flow
- All use correct endpoint paths

✅ **Server Structure:**
- Routes match test expectations
- Auth middleware works correctly
- File upload endpoints correct

✅ **No Code Changes Needed:**
- Server code is fine
- Test scripts are fine
- Just need services running!

---

## Environment Variables

You can customize these:

```bash
# Windows PowerShell
$env:SERVER_URL="http://localhost:5000"
$env:IDS_URL="http://localhost:6000"
$env:TEST_EMAIL="your@email.com"
$env:TEST_PASSWORD="YourPassword"

# Linux/Mac
export SERVER_URL="http://localhost:5000"
export IDS_URL="http://localhost:6000"
export TEST_EMAIL="your@email.com"
export TEST_PASSWORD="YourPassword"
```

---

## Test Script URLs (All Correct)

All test scripts use:
- `SERVER_URL = "http://localhost:5000/api"` ✅
- Auth: `POST /api/auth/login` ✅
- Handshake: `POST /api/handshake/init` ✅
- Upload: `POST /api/files/upload` ✅

No changes needed!

---

## Quick Start (After Fixes)

```bash
# 1. Setup check (creates account, verifies services)
python setup_and_verify.py

# 2. Run all tests
python run_full_security_tests.py
```

---

**Status:** ✅ All test scripts verified and correct!
**Next Step:** Run `python setup_and_verify.py` to check prerequisites

