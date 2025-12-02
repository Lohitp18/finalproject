#!/usr/bin/env node
/**
 * Comprehensive Test Suite for Secure Transfer System
 * Tests normal operations and attack scenarios
 */

import axios from 'axios'
import FormData from 'form-data'
import { randomBytes } from 'crypto'

// Configuration
const SERVER_URL = process.env.SERVER_URL || 'http://localhost:5000/api'
const IDS_URL = process.env.IDS_URL || 'http://localhost:6000'
const TEST_EMAIL = 'test@example.com'
const TEST_PASSWORD = 'Test123!@#'

// Test results
const testResults = {
  passed: 0,
  failed: 0,
  warnings: 0
}

function printHeader(title) {
  console.log(`\n${'='.repeat(60)}`)
  console.log(`  ${title}`)
  console.log('='.repeat(60))
}

function printResult(testName, passed, message = '') {
  const status = passed ? '✅ PASS' : '❌ FAIL'
  console.log(`${status} - ${testName}`)
  if (message) {
    console.log(`    ${message}`)
  }
  if (passed) {
    testResults.passed++
  } else {
    testResults.failed++
  }
}

function printWarning(message) {
  console.log(`⚠️  WARNING - ${message}`)
  testResults.warnings++
}

// ==================== Helper Functions ====================

async function getAuthToken() {
  try {
    const response = await axios.post(`${SERVER_URL}/auth/login`, {
      email: TEST_EMAIL,
      password: TEST_PASSWORD
    }, { timeout: 5000 })
    if (response.status === 200) {
      return response.data.token
    }
    return null
  } catch (error) {
    printWarning(`Cannot get auth token: ${error.message}`)
    return null
  }
}

async function checkBackendHealth() {
  try {
    const response = await axios.get(`${SERVER_URL}/health`, { timeout: 2000 })
    return response.status === 200
  } catch {
    return false
  }
}

async function checkIDSHealth() {
  try {
    const response = await axios.get(`${IDS_URL}/health`, { timeout: 2000 })
    return response.status === 200
  } catch {
    return false
  }
}

// ==================== Test Cases ====================

async function testBackendHealth() {
  printHeader('TC-1: Backend Health Check')
  try {
    const response = await axios.get(`${SERVER_URL}/health`, { timeout: 5000 })
    const passed = response.status === 200
    printResult('Backend Health', passed, 
      `Status: ${response.status}, Response: ${JSON.stringify(response.data)}`)
    return passed
  } catch (error) {
    printResult('Backend Health', false, `Error: ${error.message}`)
    return false
  }
}

async function testIDSHealth() {
  printHeader('TC-2: IDS Service Health Check')
  try {
    const response = await axios.get(`${IDS_URL}/health`, { timeout: 5000 })
    const passed = response.status === 200
    const data = response.data || {}
    printResult('IDS Health', passed, 
      `Status: ${response.status}, Models loaded: ${data.models_loaded || false}`)
    if (!passed) {
      printWarning('IDS service is not running - some tests may fail')
    }
    return passed
  } catch (error) {
    printResult('IDS Health', false, `Error: ${error.message}`)
    printWarning('IDS service is not running - some tests may fail')
    return false
  }
}

async function testNormalLogin() {
  printHeader('TC-3: Normal Login')
  try {
    const response = await axios.post(`${SERVER_URL}/auth/login`, {
      email: TEST_EMAIL,
      password: TEST_PASSWORD
    }, { timeout: 5000 })
    const passed = response.status === 200
    if (passed) {
      const data = response.data
      printResult('Normal Login', true, 
        `User: ${data.user?.email || 'N/A'}, Token received: ${!!data.token}`)
      return data.token
    } else {
      printResult('Normal Login', false, `Status: ${response.status}`)
      return null
    }
  } catch (error) {
    printResult('Normal Login', false, `Error: ${error.response?.data?.error || error.message}`)
    return null
  }
}

async function testInvalidLogin() {
  printHeader('TC-4: Invalid Login Credentials')
  try {
    await axios.post(`${SERVER_URL}/auth/login`, {
      email: TEST_EMAIL,
      password: 'wrongpassword'
    }, { timeout: 5000 })
    printResult('Invalid Login Rejected', false, 'Should have returned 401')
    return false
  } catch (error) {
    const passed = error.response?.status === 401
    printResult('Invalid Login Rejected', passed, 
      `Status: ${error.response?.status || 'N/A'} (expected 401)`)
    return passed
  }
}

async function testHandshakeInit(token) {
  printHeader('TC-5: Normal Handshake Initialization')
  if (!token) {
    printResult('Handshake Init', false, 'No auth token available')
    return null
  }
  
  try {
    // Generate a valid X25519 public key (32 bytes base64)
    const validPubkey = randomBytes(32).toString('base64')
    
    const response = await axios.post(
      `${SERVER_URL}/handshake/init`,
      { publicKey: validPubkey },
      {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 5000
      }
    )
    const passed = response.status === 200
    if (passed) {
      const data = response.data
      printResult('Handshake Init', true, 
        `Handshake ID: ${data.handshakeId?.substring(0, 16)}..., Server key received: ${!!data.serverPublicKey}`)
      return data
    } else {
      printResult('Handshake Init', false, `Status: ${response.status}`)
      return null
    }
  } catch (error) {
    printResult('Handshake Init', false, `Error: ${error.response?.data?.error || error.message}`)
    return null
  }
}

async function testInvalidPublicKey(token) {
  printHeader('TC-A1: Invalid Public Key Attack')
  if (!token) {
    printResult('Invalid Pubkey Attack', false, 'No auth token available')
    return false
  }
  
  try {
    // Send invalid public key (too short)
    const invalidPubkey = randomBytes(10).toString('base64')
    
    const response = await axios.post(
      `${SERVER_URL}/handshake/init`,
      { publicKey: invalidPubkey },
      {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 5000
      }
    )
    // Should either reject or handle gracefully
    const passed = [400, 500, 200].includes(response.status)
    printResult('Invalid Pubkey Handled', passed, 
      `Status: ${response.status} (should reject or handle gracefully)`)
    return passed
  } catch (error) {
    const status = error.response?.status
    const passed = status === 400 || status === 500
    printResult('Invalid Pubkey Handled', passed, 
      `Status: ${status || 'N/A'} (should reject or handle gracefully)`)
    return passed
  }
}

async function testHandshakeValidate(token, handshakeData) {
  printHeader('TC-6: Normal Handshake Validation')
  if (!token || !handshakeData) {
    printResult('Handshake Validate', false, 'No handshake data available')
    return null
  }
  
  try {
    const response = await axios.post(
      `${SERVER_URL}/handshake/validate`,
      { handshakeId: handshakeData.handshakeId },
      {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 5000
      }
    )
    const passed = response.status === 200
    if (passed) {
      const data = response.data
      const verified = data.verified || false
      const verdict = data.idsResult?.verdict || 'unknown'
      printResult('Handshake Validate', true, 
        `Verified: ${verified}, IDS Verdict: ${verdict}, Session key received: ${!!data.sessionKey}`)
      return data
    } else {
      printResult('Handshake Validate', false, `Status: ${response.status}`)
      return null
    }
  } catch (error) {
    printResult('Handshake Validate', false, `Error: ${error.response?.data?.error || error.message}`)
    return null
  }
}

async function testWrongHandshakeId(token) {
  printHeader('TC-A2: Wrong Handshake ID Attack')
  if (!token) {
    printResult('Wrong Handshake ID', false, 'No auth token available')
    return false
  }
  
  try {
    // Send invalid handshake ID
    const fakeId = '507f1f77bcf86cd799439011' // Valid ObjectId format but non-existent
    
    await axios.post(
      `${SERVER_URL}/handshake/validate`,
      { handshakeId: fakeId },
      {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 5000
      }
    )
    printResult('Wrong Handshake ID Rejected', false, 'Should have returned 404')
    return false
  } catch (error) {
    const passed = error.response?.status === 404
    printResult('Wrong Handshake ID Rejected', passed, 
      `Status: ${error.response?.status || 'N/A'} (expected 404)`)
    return passed
  }
}

async function testNormalFileUpload(token) {
  printHeader('TC-7: Normal File Upload')
  if (!token) {
    printResult('Normal File Upload', false, 'No auth token available')
    return false
  }
  
  try {
    // Create a small test file
    const testContent = Buffer.from('This is a normal test file content for upload testing.')
    const formData = new FormData()
    formData.append('file', testContent, {
      filename: 'test_normal.txt',
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
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      }
    )
    
    const passed = response.status === 200
    if (passed) {
      const data = response.data
      const status = data.status || 'unknown'
      const verdict = data.details?.verdict || 'unknown'
      printResult('Normal File Upload', true, 
        `Status: ${status}, IDS Verdict: ${verdict}, File ID: ${data.id?.substring(0, 16)}...`)
      return true
    } else {
      printResult('Normal File Upload', false, `Status: ${response.status}`)
      return false
    }
  } catch (error) {
    printResult('Normal File Upload', false, 
      `Error: ${error.response?.data?.error || error.message}`)
    return false
  }
}

async function testLargeFileUpload(token) {
  printHeader('TC-A8: Large Payload Attack')
  if (!token) {
    printResult('Large File Upload', false, 'No auth token available')
    return false
  }
  
  try {
    // Create a large file (5MB - smaller for testing)
    const largeContent = randomBytes(5 * 1024 * 1024) // 5MB
    const formData = new FormData()
    formData.append('file', largeContent, {
      filename: 'large_file.bin',
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
        timeout: 30000,
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      }
    )
    
    // Should either reject or handle gracefully
    const passed = [200, 400, 413, 500].includes(response.status)
    const statusMsg = response.status === 200 ? 'accepted' : 'rejected/handled'
    printResult('Large File Handled', passed, 
      `Status: ${response.status}, ${statusMsg}`)
    return passed
  } catch (error) {
    const status = error.response?.status
    const passed = status === 400 || status === 413 || status === 500
    printResult('Large File Handled', passed, 
      `Status: ${status || 'N/A'}, ${status ? 'rejected/handled' : 'error'}`)
    return passed
  }
}

async function testEmptyFileUpload(token) {
  printHeader('TC-A9: Empty File Attack')
  if (!token) {
    printResult('Empty File Upload', false, 'No auth token available')
    return false
  }
  
  try {
    const formData = new FormData()
    formData.append('file', Buffer.from(''), {
      filename: 'empty.txt',
      contentType: 'text/plain'
    })
    
    await axios.post(
      `${SERVER_URL}/files/upload`,
      formData,
      {
        headers: {
          ...formData.getHeaders(),
          Authorization: `Bearer ${token}`
        },
        timeout: 5000
      }
    )
    printResult('Empty File Rejected', false, 'Should have returned 400')
    return false
  } catch (error) {
    const passed = error.response?.status === 400
    printResult('Empty File Rejected', passed, 
      `Status: ${error.response?.status || 'N/A'} (expected 400)`)
    return passed
  }
}

async function testCorruptedFileUpload(token) {
  printHeader('TC-A11: Corrupted File Attack')
  if (!token) {
    printResult('Corrupted File Upload', false, 'No auth token available')
    return false
  }
  
  try {
    // Create a corrupted JPEG (valid header but corrupted data)
    const corruptedJpeg = Buffer.concat([
      Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), // Valid JPEG header
      Buffer.alloc(100, 0x00), // Null bytes (corruption)
      Buffer.alloc(50, 0xFF) // Repeated pattern (suspicious)
    ])
    
    const formData = new FormData()
    formData.append('file', corruptedJpeg, {
      filename: 'corrupted_image.jpg',
      contentType: 'image/jpeg'
    })
    
    await axios.post(
      `${SERVER_URL}/files/upload`,
      formData,
      {
        headers: {
          ...formData.getHeaders(),
          Authorization: `Bearer ${token}`
        },
        timeout: 5000,
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      }
    )
    printResult('Corrupted File Rejected', false, 'Should have returned 403')
    return false
  } catch (error) {
    const passed = error.response?.status === 403
    const status = error.response?.status
    const data = error.response?.data
    const message = data?.message || data?.error || 'N/A'
    printResult('Corrupted File Rejected', passed, 
      `Status: ${status || 'N/A'} (expected 403), Message: ${message.substring(0, 50)}...`)
    return passed
  }
}

async function testHighEntropyFile(token) {
  printHeader('TC-A12: High Entropy File (Encrypted/Corrupted)')
  if (!token) {
    printResult('High Entropy File', false, 'No auth token available')
    return false
  }
  
  try {
    // Create a file with very high entropy (like encrypted data)
    const highEntropyData = randomBytes(1024) // Random bytes = high entropy
    
    const formData = new FormData()
    formData.append('file', highEntropyData, {
      filename: 'encrypted_data.bin',
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
        maxBodyLength: Infinity
      }
    )
    
    // High entropy files might be accepted if IDS says normal, but should be flagged
    const status = response.data?.status
    const verdict = response.data?.details?.verdict || response.data?.details?.ids?.verdict
    const passed = status === 'suspicious' || verdict === 'suspicious' || response.status === 403
    printResult('High Entropy File Handled', passed, 
      `Status: ${response.status}, File Status: ${status}, IDS Verdict: ${verdict || 'N/A'}`)
    return passed
  } catch (error) {
    const status = error.response?.status
    const passed = status === 403 // Should be rejected
    printResult('High Entropy File Handled', passed, 
      `Status: ${status || 'N/A'} (should be 403 if suspicious)`)
    return passed
  }
}

async function testUnauthorizedAccess() {
  printHeader('TC-A10: Unauthorized Access Attempt')
  try {
    await axios.post(
      `${SERVER_URL}/handshake/init`,
      { publicKey: randomBytes(32).toString('base64') },
      { timeout: 5000 }
    )
    printResult('Unauthorized Access Rejected', false, 'Should have returned 401')
    return false
  } catch (error) {
    const passed = error.response?.status === 401
    printResult('Unauthorized Access Rejected', passed, 
      `Status: ${error.response?.status || 'N/A'} (expected 401)`)
    return passed
  }
}

async function testGetAlerts(token) {
  printHeader('TC-8: Get Intrusion Alerts')
  if (!token) {
    printResult('Get Alerts', false, 'No auth token available')
    return false
  }
  
  try {
    const response = await axios.get(
      `${SERVER_URL}/alerts`,
      {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 5000
      }
    )
    const passed = response.status === 200
    if (passed) {
      printResult('Get Alerts', true, `Retrieved ${response.data.length} alerts`)
      return true
    } else {
      printResult('Get Alerts', false, `Status: ${response.status}`)
      return false
    }
  } catch (error) {
    printResult('Get Alerts', false, `Error: ${error.response?.data?.error || error.message}`)
    return false
  }
}

async function testGetConnectionLogs(token) {
  printHeader('TC-9: Get Connection Logs')
  if (!token) {
    printResult('Get Connection Logs', false, 'No auth token available')
    return false
  }
  
  try {
    const response = await axios.get(
      `${SERVER_URL}/logs/connections`,
      {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 5000
      }
    )
    const passed = response.status === 200
    if (passed) {
      printResult('Get Connection Logs', true, `Retrieved ${response.data.length} connection logs`)
      return true
    } else {
      printResult('Get Connection Logs', false, `Status: ${response.status}`)
      return false
    }
  } catch (error) {
    printResult('Get Connection Logs', false, `Error: ${error.response?.data?.error || error.message}`)
    return false
  }
}

// ==================== Main Test Runner ====================

async function main() {
  console.log('\n' + '='.repeat(60))
  console.log('  SECURE TRANSFER SYSTEM - COMPREHENSIVE TEST SUITE')
  console.log('='.repeat(60))
  console.log(`\nServer URL: ${SERVER_URL}`)
  console.log(`IDS URL: ${IDS_URL}`)
  console.log(`Test Account: ${TEST_EMAIL}`)
  
  // Pre-flight checks
  if (!(await checkBackendHealth())) {
    console.log('\n❌ Backend server is not running!')
    console.log('   Please start the backend: npm run server')
    return
  }
  
  const idsRunning = await checkIDSHealth()
  if (!idsRunning) {
    console.log('\n⚠️  IDS service is not running - some tests may fail')
    console.log('   To start IDS: cd ids_service && python app.py')
  }
  
  // Run tests
  let token = null
  let handshakeData = null
  
  // Health checks
  await testBackendHealth()
  await testIDSHealth()
  
  // Authentication tests
  token = await testNormalLogin()
  await testInvalidLogin()
  
  if (!token) {
    console.log('\n❌ Cannot proceed without authentication token!')
    console.log('   Please check your test account credentials')
    return
  }
  
  // Handshake tests
  handshakeData = await testHandshakeInit(token)
  await testInvalidPublicKey(token)
  
  if (handshakeData) {
    await testHandshakeValidate(token, handshakeData)
  }
  
  await testWrongHandshakeId(token)
  
  // File upload tests
  await testNormalFileUpload(token)
  await testLargeFileUpload(token)
  await testEmptyFileUpload(token)
  await testCorruptedFileUpload(token)
  await testHighEntropyFile(token)
  
  // Security tests
  await testUnauthorizedAccess()
  
  // Monitoring tests
  await testGetAlerts(token)
  await testGetConnectionLogs(token)
  
  // Summary
  printHeader('TEST SUMMARY')
  const total = testResults.passed + testResults.failed
  const passRate = total > 0 ? (testResults.passed / total * 100) : 0
  
  console.log(`Total Tests: ${total}`)
  console.log(`✅ Passed: ${testResults.passed}`)
  console.log(`❌ Failed: ${testResults.failed}`)
  console.log(`⚠️  Warnings: ${testResults.warnings}`)
  console.log(`Pass Rate: ${passRate.toFixed(1)}%`)
  
  if (testResults.failed === 0) {
    console.log('\n🎉 ALL TESTS PASSED!')
  } else {
    console.log(`\n⚠️  ${testResults.failed} test(s) failed`)
  }
  
  console.log('\n' + '='.repeat(60))
}

main().catch(console.error)

