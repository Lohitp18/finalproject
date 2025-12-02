import React, { useState, useCallback, useEffect } from 'react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Progress } from '@/components/ui/Progress'
import { Upload, File, CheckCircle, XCircle, Lock, AlertCircle } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { api, CryptoUtils, FileTransfer } from '@/lib/api'
import apiClient from '@/api/client'
import { formatBytes, generateRandomId } from '@/lib/utils'
import { toast } from 'react-hot-toast'

interface UploadingFile extends FileTransfer {
  file: File
  encrypted?: boolean
  nonce?: string
  tag?: string
  verdict?: 'normal' | 'suspicious'
}

export function FileTransferPanel() {
  const [dragActive, setDragActive] = useState(false)
  const [uploadQueue, setUploadQueue] = useState<UploadingFile[]>([])

  const hasSession = !!(typeof window !== 'undefined' && localStorage.getItem('session_key'))
  const [backendStatus, setBackendStatus] = useState<'checking' | 'online' | 'offline'>('checking')

  // Check backend health on mount
  useEffect(() => {
    const checkBackend = async () => {
      setBackendStatus('checking')
      try {
        const health = await apiClient.checkHealth()
        setBackendStatus(health.ok ? 'online' : 'offline')
      } catch (error) {
        setBackendStatus('offline')
      }
    }

    checkBackend()
    const interval = setInterval(checkBackend, 10000) // Check every 10 seconds
    return () => clearInterval(interval)
  }, [])

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (!hasSession) {
      toast.error('Establish a secure connection first')
      return
    }

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFiles(Array.from(e.dataTransfer.files))
    }
  }, [hasSession])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!hasSession) {
      toast.error('Establish a secure connection first')
      return
    }
    if (e.target.files) {
      handleFiles(Array.from(e.target.files))
    }
  }

  const handleFiles = async (files: File[]) => {
    // Check backend availability first
    if (backendStatus === 'offline') {
      toast.error('Backend server is not available. Please start the server.')
      return
    }

    // Validate files before adding to queue
    const validFiles: File[] = []
    const invalidFiles: string[] = []

    files.forEach(file => {
      // Check if file exists and has content
      if (!file || file.size === 0) {
        invalidFiles.push(file?.name || 'Unknown file')
        toast.error(`${file?.name || 'File'}: File is empty or invalid`)
        return
      }

      // Check file size (max 100MB)
      const maxSize = 100 * 1024 * 1024 // 100MB
      if (file.size > maxSize) {
        invalidFiles.push(file.name)
        toast.error(`${file.name}: File size exceeds 100MB limit`)
        return
      }

      // Check if file has a valid name
      if (!file.name || file.name.trim().length === 0) {
        invalidFiles.push('Unnamed file')
        toast.error('File must have a valid name')
        return
      }

      validFiles.push(file)
    })

    if (validFiles.length === 0) {
      toast.error('No valid files to upload')
      return
    }

    const newUploads: UploadingFile[] = validFiles.map(file => ({
      id: generateRandomId(),
      user_id: 'current-user', // This would come from auth context
      filename: file.name,
      size: file.size,
      status: 'queued' as const,
      progress: 0,
      encryption_method: 'AES-256-GCM',
      created_at: new Date().toISOString(),
      file,
      encrypted: false,
    }))

    setUploadQueue(prev => [...prev, ...newUploads])
    newUploads.forEach(upload => processUpload(upload))
  }

  const processUpload = async (upload: UploadingFile) => {
    try {
      // Check backend availability
      if (backendStatus === 'offline') {
        updateUploadStatus(upload.id, 'failed', 0)
        toast.error(`${upload.filename}: Backend server is not available`)
        return
      }

      // Validate file again before processing
      if (!upload.file || upload.file.size === 0) {
        updateUploadStatus(upload.id, 'failed', 0)
        toast.error(`${upload.filename}: File is empty or invalid`)
        return
      }

      // Step 1: Start encryption
      updateUploadStatus(upload.id, 'encrypting', 10)
      await new Promise(resolve => setTimeout(resolve, 300))

      // Step 2: Encrypt file (client-side)
      const sessionKey = localStorage.getItem('session_key')
      if (!sessionKey) {
        updateUploadStatus(upload.id, 'failed', 0)
        toast.error(`${upload.filename}: No secure session established`)
        return
      }

      const { encrypted, nonce, tag } = await CryptoUtils.encryptFile(upload.file, sessionKey)
      
      updateUpload(upload.id, {
        status: 'encrypting',
        progress: 30,
        encrypted: true,
        aes_nonce: btoa(String.fromCharCode(...nonce)),
        verification_tag: btoa(String.fromCharCode(...tag)),
      })

      await new Promise(resolve => setTimeout(resolve, 300))

      // Step 3: Upload encrypted file
      updateUploadStatus(upload.id, 'uploading', 40)

      const formData = new FormData()
      const encryptedBlob = new Blob([encrypted], { type: 'application/octet-stream' })
      formData.append('file', encryptedBlob, upload.filename + '.encrypted')
      formData.append('original_name', upload.filename)
      formData.append('encryption_method', upload.encryption_method)
      formData.append('nonce', upload.aes_nonce || '')
      formData.append('tag', upload.verification_tag || '')

      let response
      try {
        response = await apiClient.uploadFile(formData, (progress) => {
          updateUploadStatus(upload.id, 'uploading', 40 + (progress * 0.6))
        })
      } catch (uploadError: any) {
        // Handle 403 (blocked) and other errors
        if (uploadError?.response?.status === 403) {
          const errorData = uploadError.response.data
          const verdict = errorData?.details?.verdict || 'suspicious'
          updateUpload(upload.id, { status: 'failed', progress: 100, verdict: 'suspicious' })
          toast.error(`${upload.filename}: ${errorData?.message || 'File blocked by IDS'} - Not stored in database`)
          return
        }
        throw uploadError // Re-throw other errors
      }

      // Step 4: Verify upload via IDS verdict
      const verdict = response.status || (response.details as any)?.verdict || 'normal'
      const isSuspicious = verdict === 'suspicious' || response.status === 'suspicious'
      
      if (isSuspicious) {
        updateUpload(upload.id, { status: 'failed', progress: 100, verdict: 'suspicious' })
        toast.error(`${upload.filename}: File flagged as suspicious by IDS - Upload blocked and not stored`)
      } else {
        updateUpload(upload.id, { status: 'completed', progress: 100, verdict: 'normal' })
        toast.success(`${upload.filename} uploaded and stored successfully in database`)
      }

    } catch (error: any) {
      console.error('Upload failed:', error)
      updateUploadStatus(upload.id, 'failed', 0)
      const errorMsg = error?.response?.data?.error || error?.response?.data?.message || error?.message || 'Unknown error'
      toast.error(`Failed to upload ${upload.filename}: ${errorMsg}`)
    }
  }

  const updateUpload = (id: string, updates: Partial<UploadingFile>) => {
    setUploadQueue(prev => prev.map(upload => 
      upload.id === id ? { ...upload, ...updates } : upload
    ))
  }

  const updateUploadStatus = (id: string, status: FileTransfer['status'], progress: number) => {
    updateUpload(id, { status, progress })
  }

  const removeUpload = (id: string) => {
    setUploadQueue(prev => prev.filter(upload => upload.id !== id))
  }

  const getStatusIcon = (status: FileTransfer['status']) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />
      case 'encrypting':
        return <Lock className="h-4 w-4 text-blue-500 animate-pulse" />
      case 'uploading':
        return <Upload className="h-4 w-4 text-blue-500 animate-bounce" />
      default:
        return <File className="h-4 w-4 text-gray-400" />
    }
  }

  const getStatusColor = (status: FileTransfer['status']) => {
    switch (status) {
      case 'completed': return 'success'
      case 'failed': return 'destructive'
      case 'uploading': return 'default'
      case 'encrypting': return 'secondary'
      default: return 'secondary'
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Secure File Transfer</h1>
          <p className="text-gray-400">Upload files with end-to-end encryption</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={hasSession ? 'success' : 'destructive'} className="text-sm">
            {hasSession ? 'Session: Active' : 'Session: Not established'}
          </Badge>
          <Badge 
            variant={backendStatus === 'online' ? 'success' : backendStatus === 'checking' ? 'default' : 'destructive'} 
            className="text-sm"
          >
            {backendStatus === 'online' ? 'Backend: Online' : 
             backendStatus === 'checking' ? 'Backend: Checking...' : 'Backend: Offline'}
          </Badge>
        </div>
      </div>

      {/* Upload Area */}
      <Card className="bg-gray-800/50 border-gray-700">
        <CardContent className="p-8">
          <div
            className={`relative border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
              dragActive 
                ? 'border-blue-500 bg-blue-500/10' 
                : 'border-gray-600 hover:border-gray-500'
            } ${!hasSession || backendStatus === 'offline' ? 'opacity-50 pointer-events-none' : ''}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              type="file"
              multiple
              onChange={handleFileSelect}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              disabled={!hasSession || backendStatus === 'offline'}
            />
            
            <motion.div
              animate={{ y: dragActive ? -10 : 0 }}
              transition={{ type: 'spring', stiffness: 300, damping: 20 }}
            >
              <Upload className={`mx-auto h-12 w-12 mb-4 ${
                dragActive ? 'text-blue-500' : 'text-gray-400'
              }`} />
              <h3 className={`text-lg font-medium mb-2 ${
                dragActive ? 'text-blue-400' : 'text-white'
              }`}>
                {!hasSession ? 'Establish a secure connection first' :
                 backendStatus === 'offline' ? 'Backend server is offline' :
                 dragActive ? 'Drop files here' : 'Upload Files'}
              </h3>
              <p className="text-gray-400 mb-4">
                Drag and drop files here, or click to browse
              </p>
              <div className="flex items-center justify-center space-x-4 text-xs text-gray-500">
                <div className="flex items-center">
                  <Lock className="h-3 w-3 mr-1" />
                  AES-256-GCM
                </div>
                <div className="flex items-center">
                  <CheckCircle className="h-3 w-3 mr-1" />
                  End-to-End Encrypted
                </div>
              </div>
            </motion.div>
          </div>
        </CardContent>
      </Card>

      {/* Upload Queue */}
      {uploadQueue.length > 0 && (
        <Card className="bg-gray-800/50 border-gray-700">
          <CardHeader>
            <CardTitle className="text-white">Upload Queue</CardTitle>
            <CardDescription className="text-gray-400">
              Files being processed and uploaded
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <AnimatePresence>
                {uploadQueue.map((upload) => (
                  <motion.div
                    key={upload.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    className="p-4 bg-gray-700/30 rounded-lg border border-gray-600/30"
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        {getStatusIcon(upload.status)}
                        <div>
                          <p className="text-sm font-medium text-white">{upload.filename}</p>
                          <p className="text-xs text-gray-400">{formatBytes(upload.size)}</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge variant={getStatusColor(upload.status) as any}>
                          {upload.status}
                        </Badge>
                        {upload.encrypted && (
                          <Badge variant="success" className="text-xs">
                            🔒 Encrypted
                          </Badge>
                        )}
                      </div>
                    </div>

                    {(upload.status === 'uploading' || upload.status === 'encrypting') && (
                      <div className="space-y-2">
                        <div className="flex justify-between text-xs">
                          <span className="text-gray-400">
                            {upload.status === 'encrypting' ? 'Encrypting...' : 'Uploading...'}
                          </span>
                          <span className="text-white">{Math.round(upload.progress)}%</span>
                        </div>
                        <Progress value={upload.progress} className="bg-gray-600" />
                      </div>
                    )}

                    {upload.verdict && (
                      <div className={`mt-3 p-3 rounded-lg text-xs ${upload.verdict === 'suspicious' ? 'bg-red-600/20 border border-red-500/30 text-red-300' : 'bg-green-600/20 border border-green-500/30 text-green-300'}`}>
                        IDS verdict: {upload.verdict}
                      </div>
                    )}

                    {upload.status === 'failed' && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="mt-3 p-3 bg-red-600/20 border border-red-500/30 rounded-lg"
                      >
                        <div className="flex items-center text-red-400 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />
                          Upload failed or flagged by IDS.
                        </div>
                      </motion.div>
                    )}
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}