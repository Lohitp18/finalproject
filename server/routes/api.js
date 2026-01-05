import express from 'express'
import multer from 'multer'
import { requireAuth } from '../middleware/auth.js'
import { initHandshake } from '../Handshakes/initHandshake.js'
import { validateHandshake } from '../Handshakes/validateHandshake.js'
import { calculateFileEntropy, getEntropyFeatures } from '../utils/entropy.js'
import { callIDS } from '../utils/ids.js'
import Handshake from '../models/Handshake.js'

const router = express.Router()
const upload = multer({ storage: multer.memoryStorage() })

// Protected demo data endpoints
router.get('/alerts', requireAuth, (req, res) => {
  const sample = [
    { id: 'a1', user_id: req.user.id, severity: 'high', threat_type: 'Brute Force', confidence: 0.92, source_ip: '203.0.113.1', created_at: new Date().toISOString(), resolved: false, ml_score: 0.92 },
  ]
  res.json(sample)
})

router.get('/alerts/:id', requireAuth, (req, res) => {
  const { id } = req.params
  const sample = {
    id,
    user_id: req.user.id,
    severity: id === 'a1' ? 'high' : 'medium',
    threat_type: 'Brute Force',
    confidence: 0.92,
    source_ip: '203.0.113.1',
    created_at: new Date().toISOString(),
    resolved: false,
    ml_score: 0.92,
    details: {
      description: 'Multiple failed login attempts detected',
      actions: ['IP temporarily blocked', 'User notified'],
    },
  }
  res.json(sample)
})

router.get('/logs/connections', requireAuth, (req, res) => {
  const sample = [
    { id: 'c1', user_id: req.user.id, status: 'success', handshake_type: 'ECDH', created_at: new Date().toISOString(), details: 'Connection established' },
  ]
  res.json(sample)
})

router.get('/logs/transfers', requireAuth, (req, res) => {
  const sample = [
    { id: 't1', user_id: req.user.id, filename: 'report.pdf', size: 1024 * 1024 * 5, status: 'completed', progress: 100, encryption_method: 'AES-GCM', created_at: new Date().toISOString() },
  ]
  res.json(sample)
})

router.patch('/alerts/:id/resolve', requireAuth, (req, res) => {
  res.json({ ok: true })
})

// File upload with IDS analysis
const uploadHandler = async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file provided' })
  
  try {
    const entropyFeatures = getEntropyFeatures(req.file.buffer)
    const fileFeatures = {
      file_size: req.file.size,
      file_entropy: entropyFeatures.entropy,
      file_type_risk: 0.2,
      encryption_strength: 256,
      upload_duration: 1.0,
      compression_ratio: entropyFeatures.entropy_ratio,
      metadata_anomaly: entropyFeatures.entropy_variance,
      transfer_speed: req.file.size / 1000,
      packet_loss: 0.0,
      concurrent_uploads: 1
    }
    let idsResult = { anomaly_score: 0.1, verdict: 'normal' }
    try {
      idsResult = await callIDS('/predict/file', fileFeatures)
    } catch (idsError) {
      console.warn('IDS file analysis failed:', idsError.message)
    }
    const transfer = {
      id: `t_${Date.now()}`,
      user_id: req.user.id,
      filename: req.file.originalname,
      size: req.file.size,
      status: idsResult.verdict === 'suspicious' ? 'suspicious' : 'normal',
      details: idsResult,
      progress: 100,
      encryption_method: 'AES-GCM',
      created_at: new Date().toISOString(),
      entropy_features: entropyFeatures,
      ids_result: idsResult
    }
    res.json(transfer)
  } catch (error) {
    console.error('File upload error:', error)
    res.status(500).json({ error: 'File upload failed' })
  }
}

router.post('/files/upload', requireAuth, upload.single('file'), uploadHandler)
router.post('/upload', requireAuth, upload.single('file'), uploadHandler)

// Handshake endpoints
router.post('/handshake/init', requireAuth, initHandshake)
router.post('/handshake/validate', requireAuth, validateHandshake)

// Legacy endpoints for backward compatibility
router.post('/handshake', requireAuth, initHandshake)
router.post('/handshake/verify', requireAuth, validateHandshake)

export default router
