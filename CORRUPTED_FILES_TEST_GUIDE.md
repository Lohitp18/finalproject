# Corrupted Files Detection Test Guide

## Overview
This guide explains how to test the corrupted file detection system with 5 different types of corrupted/harmful files.

## 5 Test Files Created

1. **corrupted_image.jpg** - Corrupted JPEG
   - Valid JPEG header but missing end marker (0xFF 0xD9)
   - Contains null bytes and repeated patterns
   - Should be detected as corrupted

2. **suspicious_encrypted.bin** - High Entropy Random Data
   - Random bytes with very high entropy (>7.8)
   - Looks like encrypted or malicious data
   - Should be detected as suspicious

3. **corrupted_png.png** - Corrupted PNG
   - Valid PNG header but missing IEND chunk
   - Invalid structure
   - Should be detected as corrupted

4. **excessive_nulls.bin** - File with Excessive Null Bytes
   - Contains 1000 null bytes (64% of file)
   - Corruption indicator
   - Should be detected as corrupted

5. **repeated_pattern.bin** - Repeated Pattern File
   - All bytes are 0xFF (repeated pattern)
   - Suspicious padding/corruption
   - Should be detected as suspicious

## Testing Steps

### Step 1: Create Test Files
```bash
node create_corrupted_files.js
```
This creates 5 test files in the `test_files/` directory.

### Step 2: Start Backend Server
```bash
npm run server
```
Make sure the backend is running on port 5000.

### Step 3: Upload Test Files
```bash
node upload_test_files.js
```
This will:
- Upload all 5 corrupted files
- Verify they are rejected (403/400 status)
- Check that alerts are created
- Display alert summary

### Step 4: View Alerts in Dashboard

1. Open the frontend application in your browser
2. Login with test credentials:
   - Email: `test@example.com`
   - Password: `Test123!@#`
3. Navigate to **"Intrusion Alerts"** tab
4. You should see alerts for all 5 corrupted files
5. Click **"Refresh"** button if alerts don't appear immediately

## Expected Results

### File Upload Response
All 5 files should return:
- **Status**: 403 Forbidden or 400 Bad Request
- **Message**: "File rejected: [reason]"
- **Details**: List of detected issues

### Dashboard Alerts
Each rejected file should create an alert with:
- **Threat Type**: "CorruptedFile" or "SuspiciousFile"
- **Severity**: "high" or "critical"
- **Details**:
  - Filename
  - Issues detected
  - Detected file type
  - Entropy value
  - Risk score

## Alert Details Display

The dashboard now shows:
- ✅ **Filename** - Name of the rejected file
- ✅ **Issues Detected** - List of validation issues
- ✅ **Reason** - Why the file was rejected
- ✅ **Detected Type** - File type detected from magic bytes
- ✅ **Entropy** - Entropy value (indicates randomness)

## Auto-Refresh

The alerts panel now:
- Auto-refreshes every 5 seconds
- Has a manual "Refresh" button
- Shows real-time alerts via WebSocket (if enabled)

## Troubleshooting

### Files Not Being Rejected
1. Check backend server is running
2. Verify validation logic is working
3. Check server logs for validation errors
4. Ensure file validation module is loaded

### Alerts Not Appearing in Dashboard
1. Click "Refresh" button
2. Check browser console for errors
3. Verify API endpoint `/api/alerts` is working
4. Check database for created alerts

### WebSocket Not Working
- WebSocket is optional for real-time alerts
- Alerts will still appear with auto-refresh
- Check WebSocket connection in browser console

## Manual Testing

You can also manually upload files through the UI:

1. Go to **"File Transfer"** tab
2. Click or drag files to upload area
3. Upload the corrupted files from `test_files/` directory
4. Check **"Intrusion Alerts"** tab for alerts

## Files Location

All test files are in:
```
test_files/
├── corrupted_image.jpg
├── suspicious_encrypted.bin
├── corrupted_png.png
├── excessive_nulls.bin
└── repeated_pattern.bin
```

## Next Steps

After testing:
1. Review alerts in dashboard
2. Check alert details for each file
3. Verify all 5 files were rejected
4. Confirm alerts show correct information
5. Test with valid files to ensure they pass

