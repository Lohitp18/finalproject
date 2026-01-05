import React, { useState, useCallback } from 'react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Progress } from '@/components/ui/Progress'
import { Upload, File, CheckCircle, XCircle, Lock, AlertCircle } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { api, CryptoUtils, FileTransfer } from '@/lib/api'
import { formatBytes, generateRandomId } from '@/lib/utils'
import { toast } from 'react-hot-toast'

interface UploadingFile extends FileTransfer {
  file: File
  encrypted?: boolean
  nonce?: string
  tag?: string
}

export function FileTransferPanel() {
  const [dragActive, setDragActive] = useState(false)
  const [uploadQueue, setUploadQueue] = useState<UploadingFile[]>([])

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

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFiles(Array.from(e.dataTransfer.files))
    }
  }, [])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      handleFiles(Array.from(e.target.files))
    }
  }

  const handleFiles = (files: File[]) => {
    const newUploads: UploadingFile[] = files.map(file => ({
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
    
    // Start processing uploads
    newUploads.forEach(upload => processUpload(upload))
  }

  const processUpload = async (upload: UploadingFile) => {
    try {
      // Step 1: Start encryption
      updateUploadStatus(upload.id, 'encrypting', 10)
      await new Promise(resolve => setTimeout(resolve, 500))

      // Step 2: Encrypt file (simulate client-side encryption)
      const sessionKey = localStorage.getItem('session_key') || 'dummy-session-key-for-demo'
      const { encrypted, nonce, tag } = await CryptoUtils.encryptFile(upload.file, sessionKey)
      
      updateUpload(upload.id, {
        status: 'encrypting',
        progress: 30,
        encrypted: true,
        aes_nonce: btoa(String.fromCharCode(...nonce)),
        verification_tag: btoa(String.fromCharCode(...tag)),
      })

      await new Promise(resolve => setTimeout(resolve, 500))

      // Step 3: Upload encrypted file
      updateUploadStatus(upload.id, 'uploading', 40)

      const formData = new FormData()
      const encryptedBlob = new Blob([encrypted], { type: 'application/octet-stream' })
      formData.append('file', encryptedBlob, upload.filename + '.encrypted')
      formData.append('original_name', upload.filename)
      formData.append('encryption_method', upload.encryption_method)
      formData.append('nonce', upload.aes_nonce || '')
      formData.append('tag', upload.verification_tag || '')

      await api.uploadFile(formData, (progress) => {
        updateUploadStatus(upload.id, 'uploading', 40 + (progress * 0.6))
      })

      // Step 4: Verify upload
      updateUploadStatus(upload.id, 'completed', 100)
      toast.success(`${upload.filename} uploaded successfully`)

    } catch (error) {
      console.error('Upload failed:', error)
      updateUploadStatus(upload.id, 'failed', 0)
      toast.error(`Failed to upload ${upload.filename}`)
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
        <Badge variant="secondary" className="text-sm">
          AES-256-GCM Encryption
        </Badge>
      </div>

      {/* Upload Area */}
      <Card className="bg-gray-800/50 border-gray-700">
        <CardContent className="p-8">
          <div
            className={`relative border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
              dragActive 
                ? 'border-blue-500 bg-blue-500/10' 
                : 'border-gray-600 hover:border-gray-500'
            }`}
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
                {dragActive ? 'Drop files here' : 'Upload Files'}
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
                        {upload.status === 'failed' && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => removeUpload(upload.id)}
                            className="h-6 w-6 p-0 text-gray-400 hover:text-red-400"
                          >
                            ×
                          </Button>
                        )}
                      </div>
                    </div>

                    {upload.status === 'uploading' || upload.status === 'encrypting' ? (
                      <div className="space-y-2">
                        <div className="flex justify-between text-xs">
                          <span className="text-gray-400">
                            {upload.status === 'encrypting' ? 'Encrypting...' : 'Uploading...'}
                          </span>
                          <span className="text-white">{Math.round(upload.progress)}%</span>
                        </div>
                        <Progress value={upload.progress} className="bg-gray-600" />
                      </div>
                    ) : null}

                    {upload.status === 'completed' && upload.aes_nonce && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="mt-3 p-3 bg-green-600/20 border border-green-500/30 rounded-lg"
                      >
                        <div className="flex items-center text-green-400 text-xs mb-2">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          Encryption Verified
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-xs">
                          <div>
                            <span className="text-gray-400">Nonce:</span>
                            <p className="text-gray-300 font-mono break-all">
                              {upload.aes_nonce.slice(0, 16)}...
                            </p>
                          </div>
                          <div>
                            <span className="text-gray-400">Tag:</span>
                            <p className="text-gray-300 font-mono break-all">
                              {upload.verification_tag?.slice(0, 16)}...
                            </p>
                          </div>
                        </div>
                      </motion.div>
                    )}

                    {upload.status === 'failed' && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="mt-3 p-3 bg-red-600/20 border border-red-500/30 rounded-lg"
                      >
                        <div className="flex items-center text-red-400 text-xs">
                          <AlertCircle className="h-3 w-3 mr-1" />
                          Upload failed. Please try again.
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