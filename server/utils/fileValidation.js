import { getEntropyFeatures, detectEncryptionPatterns } from './entropy.js'
import sharp from 'sharp'
import pdfParse from 'pdf-parse'
import AdmZip from 'adm-zip'

/**
 * File type detection using magic bytes (file signatures)
 */
const FILE_SIGNATURES = {
  // Images
  'image/jpeg': [0xFF, 0xD8, 0xFF],
  'image/png': [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
  'image/gif': [0x47, 0x49, 0x46, 0x38],
  'image/webp': [0x52, 0x49, 0x46, 0x46], // RIFF header
  
  // Documents
  'application/pdf': [0x25, 0x50, 0x44, 0x46], // %PDF
  'application/msword': [0xD0, 0xCF, 0x11, 0xE0], // MS Office
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [0x50, 0x4B, 0x03, 0x04], // ZIP/Office
  
  // Archives
  'application/zip': [0x50, 0x4B, 0x03, 0x04],
  'application/x-rar-compressed': [0x52, 0x61, 0x72, 0x21],
  'application/x-7z-compressed': [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
  
  // Executables (dangerous)
  'application/x-msdownload': [0x4D, 0x5A], // PE/EXE
  'application/x-executable': [0x7F, 0x45, 0x4C, 0x46], // ELF
  
  // Text files
  'text/plain': null, // No specific signature, check for valid UTF-8
}

/**
 * Detect file type from magic bytes
 */
export function detectFileType(buffer) {
  if (!buffer || buffer.length === 0) return null
  
  for (const [mimeType, signature] of Object.entries(FILE_SIGNATURES)) {
    if (signature === null) continue // Skip text files for now
    
    if (buffer.length >= signature.length) {
      let matches = true
      for (let i = 0; i < signature.length; i++) {
        if (buffer[i] !== signature[i]) {
          matches = false
          break
        }
      }
      if (matches) {
        return mimeType
      }
    }
  }
  
  return 'application/octet-stream' // Unknown type
}

/**
 * Check if file appears to be corrupted
 */
export async function detectCorruption(buffer, filename) {
  const issues = []
  
  // 1. Check for null bytes in text files
  if (filename && /\.(txt|log|json|xml|html|css|js)$/i.test(filename)) {
    const hasNullBytes = buffer.some(byte => byte === 0)
    if (hasNullBytes && buffer.length < 10000) {
      issues.push('Contains null bytes (possible corruption)')
    }
  }
  
  // 2. Check for repeated patterns (possible corruption or padding)
  if (buffer.length > 20) {
    const sampleSize = Math.min(1000, buffer.length)
    const sample = buffer.slice(0, sampleSize)
    const repeatedPattern = checkRepeatedPattern(sample)
    if (repeatedPattern) {
      issues.push(`Suspicious repeated pattern detected (possible corruption or padding)`)
    }
  }
  
  // 2b. Check for excessive null bytes (corruption indicator) - More strict
  if (buffer.length > 50) {
    const nullByteCount = buffer.filter(byte => byte === 0).length
    const nullByteRatio = nullByteCount / buffer.length
    // Lower threshold - reject if more than 20% null bytes
    if (nullByteRatio > 0.2) {
      issues.push(`High concentration of null bytes (${(nullByteRatio * 100).toFixed(1)}%) - possible corruption`)
    }
  }
  
  // 3. Check entropy - corrupted files often have unusual entropy
  const entropyFeatures = getEntropyFeatures(buffer)
  
  // Very high entropy (>7.8) might indicate encryption or corruption
  if (entropyFeatures.entropy > 7.8 && buffer.length > 512) {
    issues.push(`Extremely high entropy (${entropyFeatures.entropy.toFixed(2)}) - possible encryption or corruption`)
  }
  
  // Very low entropy (<2.5) for non-text files might indicate corruption
  if (entropyFeatures.entropy < 2.5 && buffer.length > 500) {
    const detectedType = detectFileType(buffer)
    if (detectedType && !detectedType.startsWith('text/') && detectedType !== 'application/octet-stream') {
      issues.push(`Unusually low entropy (${entropyFeatures.entropy.toFixed(2)}) for ${detectedType}`)
    }
  }
  
  // Mixed entropy patterns (high variance) can indicate corruption
  if (entropyFeatures.entropy_variance > 2.0 && buffer.length > 1000) {
    issues.push(`High entropy variance (${entropyFeatures.entropy_variance.toFixed(2)}) - possible corruption`)
  }
  
  // 4. Check file structure integrity (async)
  // Note: This will be called separately in validateFile
  
  return {
    isCorrupted: issues.length > 0,
    issues,
    entropy: entropyFeatures.entropy,
    detectedType: detectFileType(buffer)
  }
}

/**
 * Check for repeated patterns in buffer
 */
function checkRepeatedPattern(buffer) {
  if (buffer.length < 8) return false
  
  // Check for patterns of length 1-4 bytes
  for (let patternLen = 1; patternLen <= 4; patternLen++) {
    if (buffer.length < patternLen * 3) continue
    
    const pattern = buffer.slice(0, patternLen)
    let matches = 0
    let totalChecked = 0
    
    for (let i = patternLen; i < buffer.length - patternLen; i += patternLen) {
      const chunk = buffer.slice(i, i + patternLen)
      totalChecked++
      if (chunk.equals(pattern)) {
        matches++
        if (matches > 3 && (matches / totalChecked) > 0.5) return true // Too many repetitions
      } else {
        // Reset if pattern breaks, but if we had many matches, still suspicious
        if (matches > 5) return true
        matches = 0
      }
    }
    
    // Check if most of the buffer is the same pattern
    if (matches > 10 && totalChecked > 0 && (matches / totalChecked) > 0.4) {
      return true
    }
  }
  
  // Check for single byte repetition (e.g., all 0xFF or all 0x00)
  if (buffer.length > 20) {
    const firstByte = buffer[0]
    const sameByteCount = buffer.filter(byte => byte === firstByte).length
    if (sameByteCount / buffer.length > 0.7) {
      return true // More than 70% same byte
    }
  }
  
  return false
}

/**
 * Validate image file using sharp (detects corruption)
 */
async function validateImage(buffer, detectedType) {
  const issues = []
  
  try {
    if (detectedType === 'image/jpeg' || detectedType === 'image/jpg') {
      // JPEG should end with 0xFF 0xD9
      if (buffer.length > 10) {
        const lastBytes = buffer.slice(-2)
        if (lastBytes[0] !== 0xFF || lastBytes[1] !== 0xD9) {
          issues.push('JPEG file appears truncated (missing end marker)')
        }
      }
      
      // Try to parse with sharp
      try {
        const metadata = await sharp(buffer).metadata()
        if (!metadata.width || !metadata.height) {
          issues.push('JPEG has invalid dimensions')
        }
      } catch (err) {
        issues.push(`JPEG parse error: ${err.message}`)
      }
    }
    
    if (detectedType === 'image/png') {
      // PNG should end with IEND chunk
      if (buffer.length > 8) {
        const iendMarker = Buffer.from([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82])
        const endsWithIEND = buffer.slice(-8).equals(iendMarker)
        if (!endsWithIEND) {
          const pngStart = buffer.slice(0, 8)
          const validPngStart = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
          if (pngStart.equals(validPngStart)) {
            issues.push('PNG file may be truncated or corrupted')
          }
        }
      }
      
      // Try to parse with sharp
      try {
        const metadata = await sharp(buffer).metadata()
        if (!metadata.width || !metadata.height) {
          issues.push('PNG has invalid dimensions')
        }
      } catch (err) {
        issues.push(`PNG parse error: ${err.message}`)
      }
    }
    
    if (detectedType === 'image/gif') {
      try {
        const metadata = await sharp(buffer).metadata()
        if (!metadata.width || !metadata.height) {
          issues.push('GIF has invalid dimensions')
        }
      } catch (err) {
        issues.push(`GIF parse error: ${err.message}`)
      }
    }
  } catch (err) {
    issues.push(`Image validation error: ${err.message}`)
  }
  
  return issues
}

/**
 * Validate PDF file using pdf-parse
 */
async function validatePDF(buffer) {
  const issues = []
  
  try {
    const data = await pdfParse(buffer)
    if (!data || !data.numpages || data.numpages === 0) {
      issues.push('PDF has no pages or invalid structure')
    }
  } catch (err) {
    issues.push(`PDF parse error: ${err.message}`)
  }
  
  return issues
}

/**
 * Validate ZIP file using adm-zip
 */
function validateZIP(buffer) {
  const issues = []
  
  try {
    const zip = new AdmZip(buffer)
    const entries = zip.getEntries()
    if (entries.length === 0) {
      issues.push('ZIP file is empty')
    }
    // Try to read first entry to verify integrity
    if (entries.length > 0) {
      try {
        entries[0].getData()
      } catch (err) {
        issues.push(`ZIP entry read error: ${err.message}`)
      }
    }
  } catch (err) {
    issues.push(`ZIP parse error: ${err.message}`)
  }
  
  return issues
}

/**
 * Check file structure integrity
 */
async function checkFileStructure(buffer, filename) {
  const issues = []
  
  if (!filename) return issues
  
  // Check file extension matches detected type
  const detectedType = detectFileType(buffer)
  const extension = filename.split('.').pop()?.toLowerCase()
  
  if (detectedType && extension) {
    const typeMismatches = {
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
      'pdf': 'application/pdf',
      'zip': 'application/zip',
      'exe': 'application/x-msdownload',
      'dll': 'application/x-msdownload',
    }
    
    const expectedType = typeMismatches[extension]
    if (expectedType && detectedType !== expectedType && detectedType !== 'application/octet-stream') {
      issues.push(`File extension (.${extension}) does not match detected type (${detectedType})`)
    }
  }
  
  // Format-specific validation
  if (detectedType?.startsWith('image/')) {
    const imageIssues = await validateImage(buffer, detectedType)
    issues.push(...imageIssues)
  }
  
  if (detectedType === 'application/pdf') {
    const pdfIssues = await validatePDF(buffer)
    issues.push(...pdfIssues)
  }
  
  if (detectedType === 'application/zip') {
    const zipIssues = validateZIP(buffer)
    issues.push(...zipIssues)
  }
  
  return issues
}

/**
 * Comprehensive file validation (async - now includes format-specific parsing)
 */
export async function validateFile(buffer, filename, originalMimeType) {
  const validation = {
    isValid: true,
    isCorrupted: false,
    isSuspicious: false,
    riskScore: 0,
    issues: [],
    detectedType: null,
    entropy: 0,
    recommendations: []
  }
  
  if (!buffer || buffer.length === 0) {
    validation.isValid = false
    validation.issues.push('File is empty')
    return validation
  }
  
  // Detect file type
  validation.detectedType = detectFileType(buffer)
  
  // Check for corruption (basic checks)
  const corruptionCheck = await detectCorruption(buffer, filename)
  validation.isCorrupted = corruptionCheck.isCorrupted
  validation.entropy = corruptionCheck.entropy
  validation.issues.push(...corruptionCheck.issues)
  
  // Check file structure integrity (format-specific parsing)
  const structureIssues = await checkFileStructure(buffer, filename)
  validation.issues.push(...structureIssues)
  
  // If structure validation found issues, mark as corrupted
  if (structureIssues.length > 0) {
    validation.isCorrupted = true
  }
  
  // Check encryption patterns
  const encryptionPatterns = detectEncryptionPatterns(buffer)
  
  // High entropy + uniform distribution = likely encrypted
  if (encryptionPatterns.high_entropy && encryptionPatterns.uniform_distribution) {
    validation.isSuspicious = true
    validation.riskScore += 0.3
    validation.issues.push('File appears to be encrypted (high entropy + uniform distribution)')
  }
  
  // Calculate risk score - be more aggressive
  if (validation.isCorrupted) {
    validation.riskScore += 0.6
    validation.isValid = false
  }
  
  // Each issue adds to risk
  validation.riskScore += validation.issues.length * 0.15
  
  if (validation.issues.length > 1) {
    validation.riskScore += 0.3
    validation.isSuspicious = true
  }
  
  if (validation.issues.length > 0) {
    validation.isSuspicious = true
  }
  
  // Type mismatch increases risk
  if (originalMimeType && validation.detectedType && 
      originalMimeType !== validation.detectedType &&
      validation.detectedType !== 'application/octet-stream') {
    validation.riskScore += 0.3
    validation.issues.push(`MIME type mismatch: claimed ${originalMimeType}, detected ${validation.detectedType}`)
  }
  
  // Final validation - be VERY strict
  // Reject if ANY issues found, corrupted, suspicious, or risk score > 0.2
  if (validation.riskScore > 0.2 || 
      validation.isCorrupted || 
      validation.isSuspicious || 
      validation.issues.length > 0) {
    validation.isValid = false
    validation.recommendations.push('File should be rejected due to corruption or suspicious characteristics')
  }
  
  // Force rejection if we have any issues at all
  if (validation.issues.length > 0) {
    validation.isValid = false
    validation.isCorrupted = true // Mark as corrupted if any issues
  }
  
  // Special case: if entropy is extremely high (>7.8) and file is small-medium, likely corrupted/encrypted
  // Note: If file is encrypted (AES-GCM), it should be decrypted first before validation
  if (validation.entropy > 7.8 && buffer.length > 512 && buffer.length < 100000) {
    validation.isValid = false
    validation.isSuspicious = true
    validation.riskScore = Math.max(validation.riskScore, 0.8)
    validation.issues.push('Extremely high entropy in small-medium file - likely encrypted or corrupted')
  }
  
  // Reject unknown formats with high entropy (likely garbage/corrupted)
  if (validation.detectedType === 'application/octet-stream' && 
      validation.entropy > 7.5 && 
      buffer.length > 1024) {
    validation.isValid = false
    validation.isSuspicious = true
    validation.riskScore = Math.max(validation.riskScore, 0.7)
    validation.issues.push('Unknown format with high entropy - likely corrupted or encrypted data')
  }
  
  return validation
}

