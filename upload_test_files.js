/**
 * Upload the 5 corrupted test files and verify they are detected
 */

import axios from 'axios'
import FormData from 'form-data'
import { readFileSync } from 'fs'
import { join } from 'path'

const SERVER_URL = 'http://localhost:5000/api'
const TEST_EMAIL = 'test@example.com'
const TEST_PASSWORD = 'Test123!@#'

const testFiles = [
  { path: 'test_files/corrupted_image.jpg', name: 'corrupted_image.jpg', description: 'Corrupted JPEG (missing end marker)' },
  { path: 'test_files/suspicious_encrypted.bin', name: 'suspicious_encrypted.bin', description: 'High entropy random data' },
  { path: 'test_files/corrupted_png.png', name: 'corrupted_png.png', description: 'Corrupted PNG (missing IEND)' },
  { path: 'test_files/excessive_nulls.bin', name: 'excessive_nulls.bin', description: 'File with excessive null bytes' },
  { path: 'test_files/repeated_pattern.bin', name: 'repeated_pattern.bin', description: 'Repeated pattern file' }
]

async function getToken() {
  try {
    const response = await axios.post(`${SERVER_URL}/auth/login`, {
      email: TEST_EMAIL,
      password: TEST_PASSWORD
    })
    return response.data.token
  } catch (error) {
    console.error('Failed to login:', error.message)
    return null
  }
}

async function uploadFile(token, filePath, filename, description) {
  try {
    const fileBuffer = readFileSync(filePath)
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
    
    const rejected = response.status === 403 || response.status === 400
    const statusIcon = rejected ? '✅' : '❌'
    
    console.log(`${statusIcon} ${description}`)
    console.log(`   Status: ${response.status}`)
    
    if (rejected) {
      console.log(`   ✅ File REJECTED (as expected)`)
      if (response.data?.message) {
        console.log(`   Reason: ${response.data.message.substring(0, 60)}...`)
      }
      if (response.data?.details?.issues) {
        console.log(`   Issues: ${response.data.details.issues.slice(0, 2).join(', ')}`)
      }
    } else {
      console.log(`   ❌ File ACCEPTED (should have been rejected!)`)
    }
    console.log()
    
    return rejected
  } catch (error) {
    console.log(`❌ ${description}`)
    console.log(`   Error: ${error.message}`)
    console.log()
    return false
  }
}

async function checkAlerts(token) {
  try {
    const response = await axios.get(
      `${SERVER_URL}/alerts`,
      {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 5000
      }
    )
    
    const alerts = response.data || []
    const corruptedAlerts = alerts.filter(a => 
      a.threat_type === 'CorruptedFile' || a.threat_type === 'SuspiciousFile'
    )
    
    console.log('\n📊 Alert Summary:')
    console.log(`   Total Alerts: ${alerts.length}`)
    console.log(`   Corrupted/Suspicious File Alerts: ${corruptedAlerts.length}`)
    
    if (corruptedAlerts.length > 0) {
      console.log('\n   Recent Corrupted File Alerts:')
      corruptedAlerts.slice(0, 5).forEach((alert, idx) => {
        console.log(`   ${idx + 1}. ${alert.threat_type} - ${alert.details?.filename || 'Unknown'}`)
        console.log(`      Severity: ${alert.severity}, Confidence: ${(alert.confidence * 100).toFixed(1)}%`)
        if (alert.details?.issues) {
          console.log(`      Issues: ${alert.details.issues.slice(0, 2).join(', ')}`)
        }
      })
    }
    
    return corruptedAlerts.length
  } catch (error) {
    console.error('Failed to check alerts:', error.message)
    return 0
  }
}

async function main() {
  console.log('='.repeat(60))
  console.log('  UPLOADING 5 CORRUPTED/HARMFUL FILES')
  console.log('='.repeat(60))
  console.log()
  
  const token = await getToken()
  if (!token) {
    console.log('❌ Failed to get auth token. Make sure backend is running and test account exists.')
    return
  }
  
  console.log('✅ Authenticated successfully\n')
  
  let rejectedCount = 0
  let acceptedCount = 0
  
  // Upload each test file
  for (const testFile of testFiles) {
    const rejected = await uploadFile(token, testFile.path, testFile.name, testFile.description)
    if (rejected) {
      rejectedCount++
    } else {
      acceptedCount++
    }
    
    // Small delay between uploads
    await new Promise(resolve => setTimeout(resolve, 1000))
  }
  
  // Wait a moment for alerts to be created
  console.log('Waiting for alerts to be created...\n')
  await new Promise(resolve => setTimeout(resolve, 2000))
  
  // Check alerts in dashboard
  const alertCount = await checkAlerts(token)
  
  // Summary
  console.log('\n' + '='.repeat(60))
  console.log('  TEST SUMMARY')
  console.log('='.repeat(60))
  console.log(`✅ Files Rejected: ${rejectedCount}/5`)
  console.log(`❌ Files Accepted: ${acceptedCount}/5`)
  console.log(`📊 Alerts Created: ${alertCount}`)
  console.log()
  
  if (rejectedCount === 5 && alertCount >= 5) {
    console.log('🎉 SUCCESS! All corrupted files were rejected and alerts created!')
    console.log('   Check the Intrusion Alerts panel in the dashboard to see the alerts.')
  } else if (rejectedCount === 5) {
    console.log('⚠️  Files were rejected but some alerts may be missing.')
    console.log('   Check the Intrusion Alerts panel in the dashboard.')
  } else {
    console.log('❌ Some files were accepted when they should have been rejected!')
    console.log('   Check the validation logic.')
  }
  
  console.log('\n💡 Next Steps:')
  console.log('   1. Open the dashboard in your browser')
  console.log('   2. Go to "Intrusion Alerts" tab')
  console.log('   3. You should see alerts for the 5 corrupted files')
  console.log('   4. Click "Refresh" if alerts don\'t appear immediately')
}

main().catch(console.error)

