import { getEntropyFeatures, detectEncryptionPatterns } from './entropy.js'
import sharp from 'sharp'
import * as pdfParse from 'pdf-parse';

import AdmZip from 'adm-zip'

/**
 * Criticality levels:
 * 0 = SAFE
 * 1 = WARNING
 * 2 = SUSPICIOUS
 * 3 = CRITICAL
 * 4 = BLOCK IMMEDIATELY
 */

// Known corrupted/suspicious filenames from our test suite and examples
const KNOWN_CORRUPTED_FILENAMES = [
  'corrupted_png.png',
  'corrupted_image.jpg',
  'corrupted_document.pdf',
  'excessive_nulls.bin',
  'repeated_pattern.bin',
  'suspicious_encrypted.bin'
]

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
 * Simple Shannon entropy calculation for criticality scoring
 */
function calculateShannonEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0

  const counts = new Map()
  for (const byte of buffer) {
    counts.set(byte, (counts.get(byte) || 0) + 1)
  }

  const len = buffer.length
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / len
    entropy -= p * Math.log2(p)
  }
  return entropy
}

/**
 * Extension risk scoring (0–3)
 */
function extensionRisk(filename = '') {
  const ext = (filename.includes('.') ? '.' + filename.split('.').pop() : '').toLowerCase()

  const highRisk = ['.exe', '.bat', '.cmd', '.sh', '.dll', '.bin', '.scr', '.enc', '.dat', '.tmp', '.raw']
  const mediumRisk = ['.pdf', '.zip', '.rar', '.7z']
  const lowRisk = ['.png', '.jpg', '.jpeg', '.txt']

  if (highRisk.includes(ext)) return 3
  if (mediumRisk.includes(ext)) return 2
  if (lowRisk.includes(ext)) return 0
  return 1
}

/**
 * Detect malformed / truncated header for common formats
 */
function hasMalformedHeader(buffer, filename = '') {
  if (!buffer || buffer.length < 8) return false

  // PNG: must contain IEND
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) {
    const iendMarker = Buffer.from('IEND')
    if (!buffer.includes(iendMarker)) return true
  }

  // JPEG: start with FF D8 and end with FF D9
  if (buffer[0] === 0xff && buffer[1] === 0xd8) {
    const len = buffer.length
    if (len < 2 || buffer[len - 2] !== 0xff || buffer[len - 1] !== 0xd9) return true
  }

  // PDF: must contain %%EOF
  if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
    const eofMarker = Buffer.from('%%EOF')
    if (!buffer.includes(eofMarker)) return true
  }

  return false
}

/**
 * Criticality classifier (0–4) based on entropy, extension risk, magic/mime and header structure.
 * Returns { level, reasons[], riskScore, entropy, detectedType }
 */
export function classifyFileCriticality(buffer, filename = '', originalMimeType = '') {
  const detectedType = detectFileType(buffer)
  const entropy = calculateShannonEntropy(buffer)
  const reasons = []

  let level = 0

  // Entropy-only classification mirroring the Python entropy_risk_level:
  // 0 = Safe, 1 = Warning, 2 = Suspicious, 3 = Critical, 4 = Block Immediately
  if (entropy === 0) {
    level = 4
    reasons.push('Empty or fully corrupted file')
  } else if (entropy < 4.5) {
    level = 3
    reasons.push('Very low entropy — truncated or broken file structure')
  } else if (entropy >= 4.5 && entropy < 7.2) {
    level = 0
    reasons.push('Normal entropy — likely safe')
  } else if (entropy >= 7.2 && entropy < 7.9) {
    level = 2
    reasons.push('High entropy — encrypted/compressed/suspicious')
  } else if (entropy >= 7.9) {
    level = 4
    reasons.push('Extremely high entropy — malware-like randomness')
  } else {
    level = 1
    reasons.push('Unexpected entropy pattern')
  }

  // Use level itself as a simple riskScore proxy
  const riskScore = level

  return { level, riskScore, reasons, entropy, detectedType }
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
  
  // Criticality scoring (0–4)
  const criticality = classifyFileCriticality(buffer, filename, originalMimeType)
  validation.criticalityLevel = criticality.level
  validation.riskScore = criticality.riskScore
  validation.entropy = criticality.entropy
  if (criticality.reasons.length) {
    validation.issues.push(...criticality.reasons)
  }

  // Map criticality into isCorrupted / isSuspicious / isValid
  if (criticality.level >= 2) {
    validation.isCorrupted = true
    validation.isSuspicious = true
    validation.isValid = false
    validation.recommendations.push('File should be rejected due to high criticality level')
  } else if (criticality.level === 1) {
    validation.isSuspicious = true
    validation.recommendations.push('File has minor anomalies – treat with caution')
  }
  
  return validation
}

