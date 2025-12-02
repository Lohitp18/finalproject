/**
 * Test script to verify corrupted file rejection
 * Run: node test_corrupted_files.js
 */

import axios from 'axios'
import FormData from 'form-data'
import { randomBytes } from 'crypto'

const SERVER_URL = 'http://localhost:5000/api'
const TEST_EMAIL = 'test@example.com'
const TEST_PASSWORD = 'Test123!@#'

async function getToken() {
  const response = await axios.post(`${SERVER_URL}/auth/login`, {
    email: TEST_EMAIL,
    password: TEST_PASSWORD
  })
  return response.data.token
}

async function testCorruptedFile(token, fileBuffer, filename, description) {
  try {
    const formData = new FormData()
    formData.append('file', fileBuffer, {
      filename: filename,
      contentType: 'application/octet-stream'
    })
    
    const response = await axios.post(
      `${SERVER_URL}/files/upload`,
      formData,
      {
        headers: {
          ...formData.getHeaders(),
          Authorization: `Bearer ${token}`
        },
        timeout: 10000,
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
        validateStatus: () => true // Don't throw on any status
      }
    )
    
    const passed = response.status === 403 || response.status === 400
    console.log(`${passed ? '✅' : '❌'} ${description}`)
    console.log(`   Status: ${response.status}`)
    if (response.data?.message) {
      console.log(`   Message: ${response.data.message.substring(0, 80)}...`)
    }
    if (response.data?.details?.issues) {
      console.log(`   Issues: ${response.data.details.issues.join(', ')}`)
    }
    console.log()
    return passed
  } catch (error) {
    console.log(`❌ ${description}`)
    console.log(`   Error: ${error.message}`)
    console.log()
    return false
  }
}

async function main() {
  console.log('Testing Corrupted File Rejection\n')
  console.log('='.repeat(60))
  
  const token = await getToken()
  if (!token) {
    console.log('❌ Failed to get auth token')
    return
  }
  
  let passed = 0
  let failed = 0
  
  // Test 1: Corrupted JPEG (valid header, corrupted data, missing end marker)
  const corruptedJpeg = Buffer.concat([
    Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), // Valid JPEG header
    Buffer.alloc(100, 0x00), // Null bytes (corruption)
    Buffer.alloc(50, 0xFF) // Repeated pattern
    // Missing 0xFF 0xD9 end marker
  ])
  if (await testCorruptedFile(token, corruptedJpeg, 'corrupted.jpg', 'Corrupted JPEG (missing end marker)')) {
    passed++
  } else {
    failed++
  }
  
  // Test 2: High entropy random data (encrypted/corrupted)
  const highEntropyData = randomBytes(2048)
  if (await testCorruptedFile(token, highEntropyData, 'encrypted_data.bin', 'High entropy random data')) {
    passed++
  } else {
    failed++
  }
  
  // Test 3: Corrupted PNG (valid header, but invalid structure)
  const corruptedPng = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), // Valid PNG header
    Buffer.alloc(200, 0x00), // Corrupted data
    // Missing IEND chunk
  ])
  if (await testCorruptedFile(token, corruptedPng, 'corrupted.png', 'Corrupted PNG (missing IEND)')) {
    passed++
  } else {
    failed++
  }
  
  // Test 4: File with excessive null bytes
  const nullByteFile = Buffer.concat([
    Buffer.from('VALID_START'),
    Buffer.alloc(500, 0x00), // 500 null bytes
    Buffer.from('VALID_END')
  ])
  if (await testCorruptedFile(token, nullByteFile, 'null_bytes.bin', 'File with excessive null bytes')) {
    passed++
  } else {
    failed++
  }
  
  // Test 5: Repeated pattern (suspicious)
  const repeatedPattern = Buffer.alloc(1000, 0xFF) // All 0xFF
  if (await testCorruptedFile(token, repeatedPattern, 'pattern.bin', 'Repeated pattern file')) {
    passed++
  } else {
    failed++
  }
  
  // Test 6: Valid small text file (should pass)
  try {
    const validText = Buffer.from('This is a valid text file for testing.')
    const formData = new FormData()
    formData.append('file', validText, {
      filename: 'valid.txt',
      contentType: 'text/plain'
    })
    
    const response = await axios.post(
      `${SERVER_URL}/files/upload`,
      formData,
      {
        headers: {
          ...formData.getHeaders(),
          Authorization: `Bearer ${token}`
        },
        timeout: 10000,
        validateStatus: () => true
      }
    )
    
    const validPassed = response.status === 200
    console.log(`${validPassed ? '✅' : '❌'} Valid text file (should pass)`)
    console.log(`   Status: ${response.status}`)
    console.log()
    
    if (validPassed) passed++
    else failed++
  } catch (error) {
    console.log('❌ Valid text file (should pass)')
    console.log(`   Error: ${error.message}`)
    console.log()
    failed++
  }
  
  // Summary
  console.log('='.repeat(60))
  console.log(`\nTest Summary:`)
  console.log(`✅ Passed: ${passed}`)
  console.log(`❌ Failed: ${failed}`)
  console.log(`Total: ${passed + failed}`)
  
  if (failed === 0) {
    console.log('\n🎉 All corrupted files were properly rejected!')
  } else {
    console.log(`\n⚠️  ${failed} test(s) failed - corrupted files may still be accepted`)
  }
}

main().catch(console.error)

