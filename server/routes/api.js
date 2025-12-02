import express from 'express'
import multer from 'multer'
import { requireAuth } from '../middleware/auth.js'
import { initHandshake } from '../Handshakes/initHandshake.js'
import { validateHandshake } from '../Handshakes/validateHandshake.js'
import { getEntropyFeatures } from '../utils/entropy.js'
import { callIDS } from '../utils/ids.js'
import { validateFile } from '../utils/fileValidation.js'
import Handshake from '../models/Handshake.js'
import Alert from '../models/Alert.js'
import Transfer from '../models/Transfer.js'
import ConnectionLog from '../models/ConnectionLog.js'

const router = express.Router()
const upload = multer({ storage: multer.memoryStorage() })

// Alerts
router.get('/alerts', requireAuth, async (req, res) => {
  const alerts = await Alert.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(100)
  res.json(alerts.map(a => ({
    id: a._id.toString(),
    user_id: a.userId?.toString(),
    severity: a.severity,
    threat_type: a.threat_type,
    confidence: a.confidence,
    source_ip: a.source_ip,
    created_at: a.createdAt,
    resolved: a.resolved,
    ml_score: a.ml_score,
    details: a.details,
  })))
})

router.get('/alerts/:id', requireAuth, async (req, res) => {
  const a = await Alert.findOne({ _id: req.params.id, userId: req.user.id })
  if (!a) return res.status(404).json({ error: 'Not found' })
  res.json({
    id: a._id.toString(),
    user_id: a.userId?.toString(),
    severity: a.severity,
    threat_type: a.threat_type,
    confidence: a.confidence,
    source_ip: a.source_ip,
    created_at: a.createdAt,
    resolved: a.resolved,
    ml_score: a.ml_score,
    details: a.details,
  })
})

router.patch('/alerts/:id/resolve', requireAuth, async (req, res) => {
  await Alert.updateOne({ _id: req.params.id, userId: req.user.id }, { $set: { resolved: true } })
  res.json({ ok: true })
})

// Connection logs
router.get('/logs/connections', requireAuth, async (req, res) => {
  const logs = await ConnectionLog.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(100)
  res.json(logs.map(l => ({
    id: l._id.toString(),
    user_id: l.userId?.toString(),
    status: l.status,
    handshake_type: l.handshake_type,
    created_at: l.createdAt,
    details: l.details,
  })))
})

// Transfer logs
router.get('/logs/transfers', requireAuth, async (req, res) => {
  const transfers = await Transfer.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(100)
  res.json(transfers.map(t => ({
    id: t._id.toString(),
    user_id: t.userId?.toString(),
    filename: t.filename,
    size: t.size,
    status: t.status,
    progress: t.progress,
    encryption_method: t.encryption_method,
    created_at: t.createdAt,
  })))
})

// File upload with IDS analysis (persist only if safe)
const uploadHandler = async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file provided' })
  
  // Validate file exists and has content
  if (!req.file.buffer || req.file.buffer.length === 0) {
    return res.status(400).json({ error: 'File is empty or invalid' })
  }

  // Validate file size (max 100MB)
  const maxSize = 100 * 1024 * 1024 // 100MB
  if (req.file.size > maxSize) {
    return res.status(400).json({ error: 'File size exceeds 100MB limit' })
  }

  try {
    // Comprehensive file validation (corruption detection, file type, etc.)
    // Now includes format-specific parsing (images, PDFs, ZIPs)
    const fileValidation = await validateFile(
      req.file.buffer,
      req.file.originalname,
      req.file.mimetype
    )
    
    // Decide based on entropy-based criticality level:
    // level 0 = SAFE, 1 = WARNING, 2 = SUSPICIOUS, 3 = CRITICAL, 4 = BLOCK IMMEDIATELY
    // Block only when level >= 2 (suspicious or worse).
    const criticalityLevel = fileValidation.criticalityLevel ?? 0
    const shouldReject = criticalityLevel >= 2
    
    // Debug logging
    if (shouldReject) {
      console.log(`[FILE REJECTION] ${req.file.originalname}:`, {
        isCorrupted: fileValidation.isCorrupted,
        isSuspicious: fileValidation.isSuspicious,
        riskScore: fileValidation.riskScore,
        isValid: fileValidation.isValid,
        issuesCount: fileValidation.issues.length,
        issues: fileValidation.issues
      })
    }
    
    if (shouldReject) {
      console.log(`[FILE VALIDATION] Rejecting file: ${req.file.originalname}`, {
        isCorrupted: fileValidation.isCorrupted,
        isSuspicious: fileValidation.isSuspicious,
        riskScore: fileValidation.riskScore,
        isValid: fileValidation.isValid,
        issues: fileValidation.issues
      })
      
      // Create alert for corrupted/suspicious file
      const alert = await Alert.create({
        userId: req.user.id,
        severity: fileValidation.riskScore > 0.7 ? 'critical' : 'high',
        threat_type: fileValidation.isCorrupted ? 'CorruptedFile' : 'SuspiciousFile',
        confidence: Math.min(fileValidation.riskScore, 1.0),
        source_ip: req.ip || req.connection?.remoteAddress || 'unknown',
        ml_score: Math.min(fileValidation.riskScore, 1.0),
        details: {
          filename: req.file.originalname,
          file_size: req.file.size,
          issues: fileValidation.issues,
          detected_type: fileValidation.detectedType,
          entropy: fileValidation.entropy,
          risk_score: fileValidation.riskScore,
          blocked: true,
          reason: fileValidation.isCorrupted ? 'File appears corrupted' : 'File has suspicious characteristics',
          validation_result: {
            isCorrupted: fileValidation.isCorrupted,
            isSuspicious: fileValidation.isSuspicious,
            isValid: fileValidation.isValid
          }
        }
      })
      
      // Emit WebSocket alert if available
      try {
        const wss = req.app.get('wss')
        if (wss) {
          wss.clients.forEach((client) => {
            if (client.readyState === 1) { // WebSocket.OPEN
              client.send(JSON.stringify({
                type: 'intrusion_alert',
                payload: {
                  id: alert._id.toString(),
                  user_id: alert.userId?.toString(),
                  severity: alert.severity,
                  threat_type: alert.threat_type,
                  confidence: alert.confidence,
                  source_ip: alert.source_ip,
                  created_at: alert.createdAt,
                  resolved: alert.resolved,
                  ml_score: alert.ml_score,
                  details: alert.details
                }
              }))
            }
          })
        }
      } catch (wsError) {
        console.warn('WebSocket alert failed:', wsError.message)
      }
      
      return res.status(403).json({
        error: 'File upload blocked',
        status: 'corrupted',
        details: {
          issues: fileValidation.issues,
          risk_score: fileValidation.riskScore,
          detected_type: fileValidation.detectedType,
          entropy: fileValidation.entropy
        },
        message: `File rejected: ${fileValidation.issues.join('; ')}`
      })
    }
    
    const entropyFeatures = getEntropyFeatures(req.file.buffer)
    
    // Adjust file_type_risk based on validation
    let fileTypeRisk = 0.2
    if (fileValidation.isSuspicious) fileTypeRisk = 0.6
    if (fileValidation.riskScore > 0.3) fileTypeRisk = 0.8
    
    const fileFeatures = {
      file_size: req.file.size,
      file_entropy: entropyFeatures.entropy,
      file_type_risk: fileTypeRisk,
      encryption_strength: 256,
      upload_duration: 1.0,
      compression_ratio: entropyFeatures.entropy_ratio,
      metadata_anomaly: entropyFeatures.entropy_variance + (fileValidation.riskScore * 10),
      transfer_speed: req.file.size / 1000,
      packet_loss: 0.0,
      concurrent_uploads: 1
    }
    
    // Run IDS analysis first
    let idsResult = { anomaly_score: 0.1, verdict: 'normal' }
    try {
      idsResult = await callIDS('/predict/file', fileFeatures)
      
      // Combine validation risk with IDS score
      if (fileValidation.riskScore > 0.3) {
        idsResult.anomaly_score = Math.max(idsResult.anomaly_score, fileValidation.riskScore)
        if (idsResult.anomaly_score > 0.5) {
          idsResult.verdict = 'suspicious'
        }
      }
    } catch (idsError) {
      console.warn('IDS file analysis failed:', idsError.message)
      // If IDS is unavailable but file has issues, mark as suspicious
      if (fileValidation.riskScore > 0.3) {
        idsResult = { 
          anomaly_score: fileValidation.riskScore, 
          verdict: 'suspicious', 
          error: 'IDS service unavailable but file validation detected issues' 
        }
      } else {
        idsResult = { anomaly_score: 0.8, verdict: 'suspicious', error: 'IDS service unavailable' }
      }
    }

    // Only store in database if file is NOT suspicious or corrupted
    if (idsResult.verdict === 'suspicious' || fileValidation.isCorrupted || fileValidation.riskScore > 0.5) {
      // Create alert but DO NOT store the file
      await Alert.create({
        userId: req.user.id,
        severity: 'high',
        threat_type: fileValidation.isCorrupted ? 'CorruptedFile' : 'SuspiciousFile',
        confidence: Math.max(idsResult.anomaly_score || 0, fileValidation.riskScore),
        source_ip: req.ip,
        ml_score: Math.max(idsResult.anomaly_score || 0, fileValidation.riskScore),
        details: { 
          ids: idsResult,
          validation: {
            isCorrupted: fileValidation.isCorrupted,
            isSuspicious: fileValidation.isSuspicious,
            riskScore: fileValidation.riskScore,
            issues: fileValidation.issues,
            detectedType: fileValidation.detectedType
          },
          filename: req.file.originalname,
          file_size: req.file.size,
          blocked: true,
          reason: fileValidation.isCorrupted 
            ? 'File appears corrupted' 
            : 'File flagged as suspicious by IDS and validation'
        }
      })

      return res.status(403).json({
        error: 'File upload blocked',
        status: fileValidation.isCorrupted ? 'corrupted' : 'suspicious',
        details: {
          ids: idsResult,
          validation: {
            issues: fileValidation.issues,
            risk_score: fileValidation.riskScore,
            detected_type: fileValidation.detectedType
          }
        },
        message: fileValidation.isCorrupted
          ? `File rejected: ${fileValidation.issues.join('; ')}`
          : 'File was flagged as suspicious by intrusion detection system and was not stored'
      })
    }

    // File is safe - store in database
    const doc = await Transfer.create({
      userId: req.user.id,
      filename: req.file.originalname,
      size: req.file.size,
      status: 'completed',
      progress: 100,
      encryption_method: 'AES-GCM',
      entropy_features: entropyFeatures,
      ids_result: idsResult,
    })

    res.json({
      id: doc._id.toString(),
      user_id: doc.userId?.toString(),
      filename: doc.filename,
      size: doc.size,
      status: 'normal',
      details: idsResult,
      progress: 100,
      encryption_method: 'AES-GCM',
      created_at: doc.createdAt,
    })
  } catch (error) {
    console.error('File upload error:', error)
    res.status(500).json({ error: 'File upload failed', message: error.message })
  }
}

router.post('/files/upload', requireAuth, upload.single('file'), uploadHandler)
router.post('/upload', requireAuth, upload.single('file'), uploadHandler)

// Handshake endpoints (also log connections)
router.post('/handshake/init', requireAuth, async (req, res, next) => {
  try {
    await ConnectionLog.create({ userId: req.user.id, status: 'pending', handshake_type: 'X25519', details: 'Handshake initialization' })
  } catch (err) {
    console.error('Failed to create connection log:', err)
  }
  return initHandshake(req, res, next)
})

router.post('/handshake/validate', requireAuth, async (req, res) => {
  try {
    await validateHandshake(req, res)
    // Log will be created inside validateHandshake after successful validation
  } catch (error) {
    // Create failed log on error
    try {
      await ConnectionLog.create({ 
        userId: req.user.id, 
        status: 'failed', 
        handshake_type: 'X25519', 
        details: 'Handshake validation error: ' + error.message 
      })
    } catch (logErr) {
      console.error('Failed to create connection log:', logErr)
    }
  }
})

// Legacy endpoints for backward compatibility
router.post('/handshake', requireAuth, initHandshake)
router.post('/handshake/verify', requireAuth, validateHandshake)

export default router
