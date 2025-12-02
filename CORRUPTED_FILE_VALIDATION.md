# Enhanced File Validation - Corrupted File Detection

## Overview
The system now includes **strong server-side validation** that detects and rejects corrupted, tampered, or suspicious files **before** they are stored in the database.

## Key Features

### 1. Format-Specific Validation
- **Images (JPEG/PNG/GIF)**: Uses `sharp` library to parse and validate image structure
  - Detects truncated images (missing end markers)
  - Validates image dimensions
  - Catches parse errors from corrupted files
  
- **PDF Files**: Uses `pdf-parse` library to validate PDF structure
  - Attempts to read PDF pages
  - Detects corrupted PDF structure
  
- **ZIP Files**: Uses `adm-zip` library to validate ZIP archives
  - Verifies ZIP structure
  - Tests entry readability

### 2. Magic Bytes Detection
- Validates file headers match expected formats
- Detects type mismatches (extension vs. actual file type)

### 3. Entropy Analysis
- Detects extremely high entropy (>7.8) - indicates encryption or random data
- Detects very low entropy - may indicate corruption
- Rejects unknown formats with high entropy

### 4. Corruption Detection
- **Null byte detection**: Excessive null bytes in files
- **Repeated patterns**: Detects suspicious repeated byte patterns
- **File structure validation**: Checks for truncated files (missing end markers)
- **Type mismatches**: Extension doesn't match detected file type

### 5. Strict Rejection Criteria
Files are rejected if:
- `isCorrupted === true`
- `isSuspicious === true`
- `riskScore > 0.3`
- `isValid === false`
- **ANY issues found** (`issues.length > 0`)

## Implementation Details

### Files Modified
1. **`server/utils/fileValidation.js`** - Enhanced validation module
   - Added `validateImage()` - Image parsing validation
   - Added `validatePDF()` - PDF parsing validation
   - Added `validateZIP()` - ZIP parsing validation
   - Made `validateFile()` async to support format-specific parsing

2. **`server/routes/api.js`** - Updated upload handler
   - Now uses async `validateFile()`
   - Stricter rejection threshold (0.3 instead of 0.4)
   - Rejects on ANY validation issues

### Dependencies Added
```bash
npm install sharp pdf-parse adm-zip
```

- **sharp**: Image processing and validation
- **pdf-parse**: PDF parsing and validation
- **adm-zip**: ZIP file validation

## Testing

### Run Corrupted File Tests
```bash
node test_corrupted_files.js
```

This will test:
1. Corrupted JPEG (missing end marker)
2. High entropy random data
3. Corrupted PNG (missing IEND chunk)
4. Files with excessive null bytes
5. Repeated pattern files
6. Valid text file (should pass)

### Expected Results
- All corrupted files should return **403 Forbidden** or **400 Bad Request**
- Valid files should return **200 OK**

## Validation Flow

```
File Upload
    ↓
1. Basic Checks (size, empty)
    ↓
2. File Type Detection (magic bytes)
    ↓
3. Corruption Detection
   - Null bytes
   - Repeated patterns
   - Entropy analysis
    ↓
4. Format-Specific Validation
   - Images: sharp parsing
   - PDFs: pdf-parse
   - ZIPs: adm-zip
    ↓
5. Risk Scoring
    ↓
6. Reject if:
   - Corrupted
   - Suspicious
   - Risk > 0.3
   - Any issues found
    ↓
7. IDS Analysis (if passed validation)
    ↓
8. Store in Database (if safe)
```

## Rejection Response

When a file is rejected, the server returns:

```json
{
  "error": "File upload blocked",
  "status": "corrupted",
  "details": {
    "issues": ["JPEG file appears truncated", "High entropy detected"],
    "risk_score": 0.85,
    "detected_type": "image/jpeg",
    "entropy": 7.92
  },
  "message": "File rejected: JPEG file appears truncated; High entropy detected"
}
```

## Security Benefits

1. **Prevents Storage of Corrupted Files**: Corrupted files are rejected before database storage
2. **Detects Tampering**: Format-specific parsing catches tampered files
3. **High Entropy Detection**: Identifies encrypted/random data that may be malicious
4. **Type Validation**: Ensures file extension matches actual file type
5. **Structure Validation**: Detects truncated or malformed files

## Configuration

### Adjustable Thresholds

In `server/utils/fileValidation.js`:

- **Entropy threshold**: `7.8` (line ~60) - High entropy detection
- **Risk score threshold**: `0.3` (line ~280) - Rejection threshold
- **Null byte ratio**: `0.3` (30%) - Excessive null bytes
- **File size limit**: `100MB` (in `server/routes/api.js`)

## Notes

- **Encrypted Files**: If files are encrypted with AES-GCM, they should be decrypted **before** validation
- **Performance**: Format-specific parsing adds some overhead but ensures security
- **False Positives**: Very strict validation may reject some edge cases - adjust thresholds if needed

## Next Steps

1. **Restart the backend server** to apply changes:
   ```bash
   npm run server
   ```

2. **Test with corrupted files**:
   ```bash
   node test_corrupted_files.js
   ```

3. **Monitor alerts** in the dashboard to see rejected files

4. **Adjust thresholds** if needed based on your use case

