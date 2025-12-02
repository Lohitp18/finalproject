# 🚀 How to Run the Security Tests

## Step-by-Step Guide

### Step 1: Start Your Services

Open **3 separate terminal windows/tabs**:

#### Terminal 1: Start the Server
```bash
cd server
npm start
```
Wait until you see: `Server running on port 5000` ✅

#### Terminal 2: Start the IDS Service
```bash
cd ids_service
python app.py
```
Wait until you see: `IDS Service running on port 6000` ✅

#### Terminal 3: Run Tests (keep this ready)

---

### Step 2: Verify Services Are Running

In Terminal 3, test if services are up:

```bash
# Check server
curl http://localhost:5000/api/health

# Check IDS
curl http://localhost:6000/health
```

Both should return `{"status":"ok"}` or similar. ✅

---

### Step 3: Verify Setup (Recommended)

Run the setup verification script to check prerequisites:

```bash
python setup_and_verify.py
```

This will:
- ✅ Check if server is running
- ✅ Check if IDS service is running
- ✅ Create test account if it doesn't exist
- ✅ Verify API endpoints are accessible
- ✅ Check test files exist

**If this passes, you're ready to run tests!**

---

### Step 4: Set Test Credentials (If Needed)

If your test account uses different credentials, set environment variables:

**Windows PowerShell:**
```powershell
$env:TEST_EMAIL="test@example.com"
$env:TEST_PASSWORD="Test123!@#"
```

**Windows CMD:**
```cmd
set TEST_EMAIL=test@example.com
set TEST_PASSWORD=Test123!@#
```

**Linux/Mac:**
```bash
export TEST_EMAIL=test@example.com
export TEST_PASSWORD=Test123!@#
```

*(Or modify the scripts directly to use your credentials)*

---

### Step 5: Run the Tests

Now you have **3 options**:

---

## Option 1: Run ALL Tests (Recommended) 🎯

```bash
python run_full_security_tests.py
```

**What it does:**
- ✅ Checks prerequisites automatically
- ✅ Runs all security tests in sequence
- ✅ Shows progress for each test
- ✅ Generates final summary report
- ✅ Shows PASS/FAIL checklist

**Time:** ~2-5 minutes

**Output:** Comprehensive report with all results

---

## Option 2: Run Individual Test Scripts

### Test 1: Normal Secure Upload
```bash
python -m client.client
```
OR
```bash
python client/client.py
```

**Expected:**
- ✅ Handshake successful
- ✅ Upload succeeds (Status 200)
- ✅ IDS probability < 0.3

---

### Test 2-5: MITM Attacks
```bash
python attack_simulator.py
```

**Expected:**
- ✅ MITM attacks detected
- ✅ Server rejects attacks (Status 400/403)
- ✅ IDS probability > 0.8

---

### Test 6-8: Corrupted Files
```bash
python upload_corrupted_file.py
```

**Expected:**
- ✅ Corrupted files rejected
- ✅ Server returns 400/403
- ✅ IDS probability > 0.75

---

## Option 3: Run Tests One by One (Interactive)

1. **First, run normal upload:**
   ```bash
   python client/client.py
   ```
   Wait for it to complete.

2. **Then, run attacks:**
   ```bash
   python attack_simulator.py
   ```
   Wait for it to complete.

3. **Finally, test corrupted files:**
   ```bash
   python upload_corrupted_file.py
   ```

---

## 📊 Understanding the Results

### ✅ Good Results (PASS):

**Normal Upload:**
```
✅ Upload successful!
🔍 IDS Anomaly Score: 0.18
✅ Low IDS probability (<0.3) - normal traffic detected correctly
```

**MITM Attack:**
```
✅ Server rejected tampered file (Status 403)
🔍 IDS Anomaly Score: 0.94
✅ IDS correctly flagged attack (probability: 0.94)
```

**Corrupted File:**
```
✅ File correctly rejected
🔍 IDS Anomaly Score: 0.89
Status: 403
```

---

### ❌ Bad Results (FAIL):

**Normal Upload Flagged:**
```
❌ Upload failed
IDS Anomaly Score: 0.65  ← Too high! Should be < 0.3
```

**Attack Not Detected:**
```
✅ Upload successful  ← Should be rejected!
IDS Anomaly Score: 0.25  ← Too low! Should be > 0.8
```

---

## 🐛 Troubleshooting

### Problem: "Cannot get auth token"
**Solution:**
1. Check server is running: `curl http://localhost:5000/api/health`
2. Verify credentials match your test account
3. Create test account if missing:
   ```bash
   node create_test_account.js
   ```

### Problem: "IDS service error"
**Solution:**
1. Check IDS is running: `curl http://localhost:6000/health`
2. Verify models exist in `ids_service/models/`
3. Train models if missing:
   ```bash
   cd ids_service
   python enhanced_train.py
   ```

### Problem: "File not found: test_files/corrupted_png.png"
**Solution:**
1. Check `test_files/` directory exists
2. Create corrupted files:
   ```bash
   node create_corrupted_files.js
   ```
3. Or files will be created automatically by `upload_corrupted_file.py`

### Problem: Tests are slow
**Solution:**
- This is normal! Each test makes multiple HTTP requests
- Full test suite takes 2-5 minutes
- Be patient, tests are comprehensive

---

## 📝 Quick Reference

| Command | What It Tests | Expected Time |
|---------|---------------|---------------|
| `python run_full_security_tests.py` | Everything | 2-5 min |
| `python client/client.py` | Normal upload | 30 sec |
| `python attack_simulator.py` | MITM attacks | 1-2 min |
| `python upload_corrupted_file.py` | Corrupted files | 1 min |

---

## ✅ Success Checklist

After running tests, you should see:

- [ ] Normal upload: IDS score < 0.3, Status 200 ✅
- [ ] MITM attacks: IDS score > 0.8, Status 400/403 ✅
- [ ] Corrupted files: IDS score > 0.75, Status 400/403 ✅
- [ ] All tests in summary show "PASSED" ✅

---

## 🎯 Recommended Workflow

1. **Start services** (Terminal 1 & 2)
2. **Run full test suite** once:
   ```bash
   python run_full_security_tests.py
   ```
3. **Review the summary report**
4. **Fix any failures** if needed
5. **Run again** to verify fixes

---

## 💡 Pro Tips

- **First time?** Run the full test suite to see everything
- **Debugging?** Run individual tests to isolate issues
- **Quick check?** Run just `python client/client.py` for normal operation
- **Demo?** Use `python run_full_security_tests.py` for impressive output

---

## 📚 Need More Help?

- **Detailed docs:** See `SECURITY_TEST_DOCUMENTATION.md`
- **Quick reference:** See `QUICK_TEST_REFERENCE.md`
- **Overview:** See `TESTING_README.md`

---

**That's it! You're ready to test your IDS! 🛡️**

