# ⚡ QUICK START - Run Tests in 3 Steps

## 🚀 Fastest Way to Run Tests

### Step 1: Start Services (2 terminals)

**Terminal 1 - Server:**
```bash
cd server
npm start
```

**Terminal 2 - IDS Service:**
```bash
cd ids_service
python app.py
```

Wait for both to show "listening" messages.

---

### Step 2: Verify Setup

**Terminal 3:**
```bash
python setup_and_verify.py
```

This checks everything and creates test account if needed.

---

### Step 3: Run Tests

```bash
python run_full_security_tests.py
```

**Done!** 🎉

---

## 📋 What You'll See

### If Setup Passes:
```
✅ Server is running
✅ IDS service is running
✅ Test account ready
✅ READY TO RUN TESTS!
```

### When Tests Complete:
```
🎉 ALL SECURITY TESTS PASSED!
✅ Normal traffic: IDS < 0.3
✅ MITM attacks: IDS > 0.8
✅ Corrupted files: Rejected
```

---

## ❌ If Something Fails

### "Server not running"
→ Start server: `cd server && npm start`

### "IDS not running"  
→ Start IDS: `cd ids_service && python app.py`

### "Auth failed"
→ Run setup script: `python setup_and_verify.py` (creates account)

### "File not found"
→ Test files created automatically, or run: `node create_corrupted_files.js`

---

## 🎯 That's It!

1. Start services ✅
2. Run setup verification ✅
3. Run tests ✅

**Total time: ~5 minutes**

---

For detailed help, see `HOW_TO_RUN_TESTS.md`

