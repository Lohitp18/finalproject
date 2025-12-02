import React, { useState, useEffect } from 'react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Progress } from '@/components/ui/Progress'
import { Shield, Key, CheckCircle, XCircle, Clock, Lock } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { api, CryptoUtils, HandshakeStep } from '@/lib/api'
import { toast } from 'react-hot-toast'
import apiClient from '@/api/client'
import { AdvancedCrypto } from '@/lib/api'

export function HandshakePanel() {
  const [isConnecting, setIsConnecting] = useState(false)
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'connecting' | 'connected' | 'failed' | 'backend_unavailable'>('idle')
  const [handshakeSteps, setHandshakeSteps] = useState<HandshakeStep[]>([])
  const [progress, setProgress] = useState(0)
  const [sessionInfo, setSessionInfo] = useState<{
    handshakeId: string
    sessionKey: string
    publicKey: string
  } | null>(null)
  const [clientSecretKey, setClientSecretKey] = useState<Uint8Array | null>(null)
  const [backendStatus, setBackendStatus] = useState<'checking' | 'online' | 'offline'>('checking')
  const [statusMessage, setStatusMessage] = useState<string>('')

  // Check backend health on mount and periodically
  useEffect(() => {
    const checkBackend = async () => {
      setBackendStatus('checking')
      try {
        const health = await apiClient.checkHealth()
        if (health.ok) {
          setBackendStatus('online')
          setStatusMessage('Backend is online')
        } else {
          setBackendStatus('offline')
          setStatusMessage('Backend is unavailable')
          setConnectionStatus('backend_unavailable')
        }
      } catch (error) {
        setBackendStatus('offline')
        setStatusMessage('Cannot connect to backend')
        setConnectionStatus('backend_unavailable')
      }
    }

    checkBackend()
    const interval = setInterval(checkBackend, 10000) // Check every 10 seconds
    return () => clearInterval(interval)
  }, [])

  // Restore session on refresh
  useEffect(() => {
    try {
      const storedKey = localStorage.getItem('session_key')
      const storedHs = localStorage.getItem('handshake_id')
      const storedPub = localStorage.getItem('server_pubkey')
      if (storedKey && storedHs && storedPub && backendStatus === 'online') {
        setSessionInfo({ handshakeId: storedHs, sessionKey: storedKey, publicKey: storedPub })
        setConnectionStatus('connected')
      }
    } catch {}
  }, [backendStatus])

  const steps = [
    { id: 'key_generation', name: 'Generate ECDH Key Pair', icon: Key },
    { id: 'key_exchange', name: 'Exchange Public Keys', icon: Shield },
    { id: 'signature_verification', name: 'Verify Digital Signatures', icon: CheckCircle },
    { id: 'session_establishment', name: 'Establish Secure Session', icon: Lock },
  ]

  const initiateHandshake = async () => {
    // Check backend health first
    setStatusMessage('Checking backend connection...')
    const health = await apiClient.checkHealth()
    if (!health.ok) {
      setBackendStatus('offline')
      setConnectionStatus('backend_unavailable')
      setStatusMessage('Backend is not running. Please start the backend server.')
      toast.error('Backend server is not available. Please start the server.')
      return
    }

    setIsConnecting(true)
    setConnectionStatus('connecting')
    setProgress(0)
    setHandshakeSteps([])
    setStatusMessage('Initiating secure connection...')

    try {
      // Step 1: Generate X25519 Key Pair
      setStatusMessage('Generating cryptographic keys...')
      updateStep('key_generation', 'in_progress', 'Generating X25519 key pair...')
      setProgress(25)

      const { publicKeyB64, secretKey } = await AdvancedCrypto.generateX25519KeyPair()
      setClientSecretKey(secretKey)
      await new Promise(resolve => setTimeout(resolve, 300))

      updateStep('key_generation', 'completed', 'Key pair generated successfully')

      // Step 2: Exchange Public Keys (init)
      setStatusMessage('Exchanging keys with server...')
      updateStep('key_exchange', 'in_progress', 'Exchanging public keys with server...')
      setProgress(50)

      const initResp = await apiClient.initHandshake({ publicKey: publicKeyB64 })
      await new Promise(resolve => setTimeout(resolve, 300))

      updateStep('key_exchange', 'completed', 'Public keys exchanged successfully')

      // Step 3: Validate handshake (server derives session key and runs IDS)
      setStatusMessage('Validating connection security...')
      updateStep('signature_verification', 'in_progress', 'Validating handshake with server...')
      setProgress(75)

      const validateResp = await apiClient.validateHandshake({ handshakeId: initResp.handshakeId })
      await new Promise(resolve => setTimeout(resolve, 300))

      if (validateResp.status !== 'secure') {
        throw new Error('IDS marked connection as suspicious')
      }

      updateStep('signature_verification', 'completed', 'Handshake validated successfully')

      // Step 4: Establish Secure Session
      setStatusMessage('Establishing secure session...')
      updateStep('session_establishment', 'in_progress', 'Establishing secure session...')
      setProgress(100)

      await new Promise(resolve => setTimeout(resolve, 300))

      updateStep('session_establishment', 'completed', 'Secure session established')

      setSessionInfo({
        handshakeId: initResp.handshakeId,
        sessionKey: validateResp.sessionKey,
        publicKey: initResp.serverPublicKey,
      })

      // Persist session key and metadata for reuse after refresh
      try {
        localStorage.setItem('session_key', validateResp.sessionKey)
        localStorage.setItem('handshake_id', initResp.handshakeId)
        localStorage.setItem('server_pubkey', initResp.serverPublicKey)
      } catch {}

      setConnectionStatus('connected')
      setStatusMessage('Secure connection established successfully!')
      toast.success('Secure connection established successfully!')

    } catch (error) {
      console.error('Handshake failed:', error)
      setConnectionStatus('failed')
      const errorMsg = error instanceof Error ? error.message : 'Unknown error'
      setStatusMessage(`Connection failed: ${errorMsg}`)

      const currentStep = handshakeSteps.find(step => step.status === 'in_progress')
      if (currentStep) {
        updateStep(currentStep.step as any, 'failed', `Failed: ${errorMsg}`)
      }

      // Check if it's a backend connection error
      if (errorMsg.includes('Network') || errorMsg.includes('ECONNREFUSED') || errorMsg.includes('timeout')) {
        setBackendStatus('offline')
        setConnectionStatus('backend_unavailable')
        setStatusMessage('Backend server is not responding')
      }

      toast.error(`Failed to establish secure connection: ${errorMsg}`)
    } finally {
      setIsConnecting(false)
    }
  }

  const disconnect = () => {
    try {
      localStorage.removeItem('session_key')
      localStorage.removeItem('handshake_id')
      localStorage.removeItem('server_pubkey')
    } catch {}
    setSessionInfo(null)
    setConnectionStatus('idle')
    setHandshakeSteps([])
    setProgress(0)
    toast.success('Disconnected')
  }

  const updateStep = (stepId: HandshakeStep['step'], status: HandshakeStep['status'], details: string) => {
    setHandshakeSteps(prev => {
      const existing = prev.find(s => s.step === stepId)
      if (existing) {
        return prev.map(s => s.step === stepId ? { ...s, status, details, timestamp: new Date() } : s)
      } else {
        return [...prev, { id: stepId, step: stepId, status, details, timestamp: new Date() }]
      }
    })
  }

  const getStepStatus = (stepId: string) => {
    const step = handshakeSteps.find(s => s.step === stepId)
    return step?.status || 'pending'
  }

  const getStepIcon = (stepId: string, IconComponent: React.ComponentType<{ className?: string }>) => {
    const status = getStepStatus(stepId)
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-green-500" />
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-500" />
      case 'in_progress':
        return <Clock className="h-5 w-5 text-blue-500 animate-spin" />
      default:
        return <IconComponent className="h-5 w-5 text-gray-400" />
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Secure Connection</h1>
          <p className="text-gray-400">Establish encrypted communication channel</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge 
            variant={
              backendStatus === 'offline' ? 'destructive' :
              connectionStatus === 'connected' ? 'success' :
              connectionStatus === 'failed' ? 'destructive' : 
              connectionStatus === 'connecting' ? 'default' : 'secondary'
            }
            className="text-sm"
          >
            {backendStatus === 'offline' ? '⚠️ Backend Offline' :
             backendStatus === 'checking' ? '🔄 Checking...' :
             connectionStatus === 'connected' ? '🔒 Secure' :
             connectionStatus === 'connecting' ? '🔄 Connecting...' :
             connectionStatus === 'failed' ? '❌ Failed' : '⏸️ Idle'}
          </Badge>
          {connectionStatus === 'connected' && (
            <Button size="sm" variant="ghost" onClick={disconnect}>Disconnect</Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Handshake Control */}
        <Card className="bg-gray-800/50 border-gray-700">
          <CardHeader>
            <CardTitle className="text-white">ECDH Handshake</CardTitle>
            <CardDescription className="text-gray-400">
              Initiate secure key exchange protocol
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="text-center">
              <motion.div
                animate={{
                  scale: connectionStatus === 'connected' ? [1, 1.1, 1] : 1,
                  rotate: isConnecting ? 360 : 0
                }}
                transition={{
                  scale: { duration: 0.5, repeat: connectionStatus === 'connected' ? Infinity : 0, repeatDelay: 2 },
                  rotate: { duration: 2, repeat: isConnecting ? Infinity : 0, ease: 'linear' }
                }}
                className="inline-block"
              >
                <Shield className={`h-16 w-16 ${
                  connectionStatus === 'connected' ? 'text-green-500' :
                  connectionStatus === 'failed' ? 'text-red-500' : 'text-blue-500'
                }`} />
              </motion.div>
            </div>

            {isConnecting && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-400">Progress</span>
                  <span className="text-white">{progress}%</span>
                </div>
                <Progress value={progress} className="bg-gray-700" />
              </div>
            )}

            {statusMessage && (
              <div className={`p-3 rounded-lg text-sm ${
                backendStatus === 'offline' || connectionStatus === 'failed' 
                  ? 'bg-red-600/20 border border-red-500/30 text-red-300' 
                  : connectionStatus === 'connecting'
                  ? 'bg-blue-600/20 border border-blue-500/30 text-blue-300'
                  : connectionStatus === 'connected'
                  ? 'bg-green-600/20 border border-green-500/30 text-green-300'
                  : 'bg-gray-700/50 border border-gray-600/30 text-gray-300'
              }`}>
                {statusMessage}
              </div>
            )}

            <Button
              onClick={initiateHandshake}
              disabled={isConnecting || connectionStatus === 'connected' || backendStatus === 'offline'}
              loading={isConnecting || backendStatus === 'checking'}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
            >
              {backendStatus === 'offline' ? 'Backend Offline - Cannot Connect' :
               connectionStatus === 'connected' ? 'Connected' : 
               isConnecting ? 'Connecting...' : 'Establish Secure Connection'}
            </Button>

            {connectionStatus === 'connected' && sessionInfo && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="p-4 bg-green-600/20 border border-green-500/30 rounded-lg"
              >
                <h4 className="font-medium text-green-400 mb-2">Connection Established</h4>
                <div className="space-y-1 text-xs">
                  <p className="text-gray-300">
                    <span className="text-gray-400">Session ID:</span> {sessionInfo.handshakeId.slice(0, 16)}...
                  </p>
                  <p className="text-gray-300">
                    <span className="text-gray-400">Key Algorithm:</span> X25519 + AES-256-GCM
                  </p>
                </div>
              </motion.div>
            )}
          </CardContent>
        </Card>

        {/* Handshake Steps */}
        <Card className="bg-gray-800/50 border-gray-700">
          <CardHeader>
            <CardTitle className="text-white">Handshake Timeline</CardTitle>
            <CardDescription className="text-gray-400">
              Step-by-step connection establishment process
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {steps.map((step, index) => {
                const stepData = handshakeSteps.find(s => s.step === step.id)
                const status = getStepStatus(step.id)
                
                return (
                  <motion.div
                    key={step.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-start space-x-3"
                  >
                    <div className="flex-shrink-0 mt-1">
                      {getStepIcon(step.id, step.icon)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-sm font-medium ${
                        status === 'completed' ? 'text-green-400' :
                        status === 'failed' ? 'text-red-400' :
                        status === 'in_progress' ? 'text-blue-400' : 'text-gray-400'
                      }`}>
                        {step.name}
                      </p>
                      <AnimatePresence>
                        {stepData && (
                          <motion.p
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className={`text-xs mt-1 ${
                              status === 'failed' ? 'text-red-400' : 'text-gray-500'
                            }`}
                          >
                            {stepData.details}
                          </motion.p>
                        )}
                      </AnimatePresence>
                      {stepData && (
                        <p className="text-xs text-gray-600 mt-1">
                          {stepData.timestamp.toLocaleTimeString()}
                        </p>
                      )}
                    </div>
                  </motion.div>
                )
              })}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}