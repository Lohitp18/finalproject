/**
 * Create 5 different corrupted/harmful test files
 */

import { writeFileSync } from 'fs'
import { randomBytes } from 'crypto'

// 1. Corrupted JPEG - Valid header but missing end marker and corrupted data
const corruptedJpeg = Buffer.concat([
  Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]), // Valid JPEG header
  Buffer.alloc(200, 0x00), // Null bytes (corruption)
  Buffer.alloc(100, 0xFF), // Repeated pattern
  // Missing 0xFF 0xD9 end marker
])
writeFileSync('test_files/corrupted_image.jpg', corruptedJpeg)
console.log('✅ Created: corrupted_image.jpg (Corrupted JPEG - missing end marker)')

// 2. High Entropy Random Data (Encrypted/Malicious looking)
const highEntropyData = randomBytes(2048) // Random bytes = very high entropy
writeFileSync('test_files/suspicious_encrypted.bin', highEntropyData)
console.log('✅ Created: suspicious_encrypted.bin (High entropy random data)')

// 3. Corrupted PNG - Valid header but invalid structure
const corruptedPng = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), // Valid PNG header
  Buffer.from('IHDR'), // PNG chunk type
  Buffer.alloc(100, 0x00), // Corrupted chunk data
  // Missing IEND chunk
])
writeFileSync('test_files/corrupted_png.png', corruptedPng)
console.log('✅ Created: corrupted_png.png (Corrupted PNG - missing IEND)')

// 4. File with Excessive Null Bytes (Corruption indicator)
const nullByteFile = Buffer.concat([
  Buffer.from('VALID_FILE_START'),
  Buffer.alloc(1000, 0x00), // 1000 null bytes (64% of file)
  Buffer.from('VALID_FILE_END')
])
writeFileSync('test_files/excessive_nulls.bin', nullByteFile)
console.log('✅ Created: excessive_nulls.bin (File with excessive null bytes)')

// 5. Repeated Pattern File (Suspicious padding/corruption)
const repeatedPattern = Buffer.alloc(2000, 0xFF) // All bytes are 0xFF
writeFileSync('test_files/repeated_pattern.bin', repeatedPattern)
console.log('✅ Created: repeated_pattern.bin (Repeated pattern - all 0xFF)')

console.log('\n📁 All 5 corrupted/harmful test files created in test_files/ directory')
console.log('   You can now upload these files to test detection')

