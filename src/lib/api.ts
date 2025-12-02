import { generateRandomId } from './utils'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api'

export interface AuthUser {
  id: string
  email: string
  name: string
  created_at: string
}

export interface ConnectionLog {
  id: string
  user_id: string
  status: 'success' | 'failed' | 'pending'
  handshake_type: 'ECDH' | 'RSA'
  created_at: string
  details: string
  public_key?: string
  signature?: string
}

export interface IntrusionAlert {
  id: string
  user_id: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  threat_type: string
  confidence: number
  source_ip: string
  created_at: string
  resolved: boolean
  ml_score: number
  attack_vector?: string
}

export interface FileTransfer {
  id: string
  user_id: string
  filename: string
  size: number
  status: 'uploading' | 'completed' | 'failed' | 'encrypting' | 'queued'
  progress: number
  encryption_method: string
  created_at: string
  aes_nonce?: string
  verification_tag?: string
}

export interface HandshakeStep {
  id: string
  step: 'key_generation' | 'key_exchange' | 'signature_verification' | 'session_establishment'
  status: 'pending' | 'in_progress' | 'completed' | 'failed'
  timestamp: Date
  details: string
}

class ApiClient {
  private token: string | null = null

  constructor() {
    this.token = localStorage.getItem('auth_token')
  }

  private async request(endpoint: string, options: RequestInit = {}) {
    const url = `${API_BASE_URL}${endpoint}`
    const headers = {
      'Content-Type': 'application/json',
      ...(this.token && { Authorization: `Bearer ${this.token}` }),
      ...options.headers,
    }

    const response = await fetch(url, {
      ...options,
      headers,
    })

    if (!response.ok) {
      let errorMessage = `API Error: ${response.statusText}`
      try {
        const errorData = await response.json()
        errorMessage = errorData.error || errorData.message || errorMessage
      } catch {
        // If response is not JSON, use status text
      }
      throw new Error(errorMessage)
    }

    return response.json()
  }

  // Authentication
  async login(email: string, password: string): Promise<{ user: AuthUser; token: string }> {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })
    this.token = response.token
    localStorage.setItem('auth_token', response.token)
    return response
  }

  async register(name: string, email: string, password: string): Promise<{ user: AuthUser; token: string }> {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password }),
    })
    this.token = response.token
    localStorage.setItem('auth_token', response.token)
    return response
  }

  async logout() {
    this.token = null
    localStorage.removeItem('auth_token')
  }

  // Handshake Operations
  async initiateHandshake(publicKey: string): Promise<{ handshakeId: string; serverPublicKey: string }> {
    return this.request('/handshake', {
      method: 'POST',
      body: JSON.stringify({ publicKey, type: 'ECDH' }),
    })
  }

  async verifySignature(handshakeId: string, signature: string): Promise<{ verified: boolean; sessionKey: string }> {
    return this.request('/handshake/verify', {
      method: 'POST',
      body: JSON.stringify({ handshakeId, signature }),
    })
  }

  // File Transfer
  async uploadFile(formData: FormData, onProgress?: (progress: number) => void): Promise<FileTransfer> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      
      xhr.upload.addEventListener('progress', (event) => {
        if (event.lengthComputable && onProgress) {
          const progress = (event.loaded / event.total) * 100
          onProgress(progress)
        }
      })

      xhr.addEventListener('load', () => {
        if (xhr.status === 200) {
          resolve(JSON.parse(xhr.responseText))
        } else {
          reject(new Error('Upload failed'))
        }
      })

      xhr.addEventListener('error', () => reject(new Error('Upload failed')))

      xhr.open('POST', `${API_BASE_URL}/upload`)
      xhr.setRequestHeader('Authorization', `Bearer ${this.token}`)
      xhr.send(formData)
    })
  }

  // Alerts and Logs
  async getIntrusionAlerts(): Promise<IntrusionAlert[]> {
    return this.request('/alerts')
  }

  async getConnectionLogs(): Promise<ConnectionLog[]> {
    return this.request('/logs/connections')
  }

  async getFileTransfers(): Promise<FileTransfer[]> {
    return this.request('/logs/transfers')
  }

  async resolveAlert(alertId: string): Promise<void> {
    await this.request(`/alerts/${alertId}/resolve`, { method: 'PATCH' })
  }

  // WebSocket connection for real-time alerts
  connectWebSocket(onAlert: (alert: IntrusionAlert) => void): WebSocket {
    const ws = new WebSocket(`${API_BASE_URL.replace('http', 'ws')}/ws`)
    
    ws.addEventListener('message', (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.type === 'intrusion_alert') {
          onAlert(data.payload)
        }
      } catch (error) {
        console.error('WebSocket message parsing error:', error)
      }
    })

    return ws
  }
}

export const api = new ApiClient()

// Crypto utilities for client-side operations
export class CryptoUtils {
  static async generateECDHKeyPair(): Promise<{ publicKey: string; privateKey: CryptoKey }> {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      false,
      ['deriveKey']
    )

    const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey)
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)))

    return {
      publicKey: publicKeyBase64,
      privateKey: keyPair.privateKey,
    }
  }

  static async encryptFile(file: File, key: string): Promise<{ encrypted: ArrayBuffer; nonce: Uint8Array; tag: Uint8Array }> {
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const keyBuffer = Uint8Array.from(atob(key), c => c.charCodeAt(0))
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    )

    const fileBuffer = await file.arrayBuffer()
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      cryptoKey,
      fileBuffer
    )

    // Extract authentication tag (last 16 bytes)
    const encryptedArray = new Uint8Array(encrypted)
    const tag = encryptedArray.slice(-16)
    const ciphertext = encryptedArray.slice(0, -16)

    return { encrypted: ciphertext, nonce, tag }
  }

  static async signData(data: string, privateKey: CryptoKey): Promise<string> {
    const encoder = new TextEncoder()
    const dataBuffer = encoder.encode(data)
    
    const signature = await crypto.subtle.sign('ECDSA', privateKey, dataBuffer)
    return btoa(String.fromCharCode(...new Uint8Array(signature)))
  }
}

// Extended crypto helpers (X25519 + HKDF + AES-256)
// These use tweetnacl for X25519 and WebCrypto for HKDF
// We keep them separate to avoid breaking existing demo logic
export namespace AdvancedCrypto {
  // Lazy import to avoid bundling when unused
  async function nacl() {
    const mod = await import('tweetnacl')
    return mod.default || mod
  }

  export async function generateX25519KeyPair(): Promise<{ publicKeyB64: string; secretKey: Uint8Array }> {
    const n = await nacl()
    const kp = n.box.keyPair()
    const pubB64 = btoa(String.fromCharCode(...kp.publicKey))
    return { publicKeyB64: pubB64, secretKey: kp.secretKey }
  }

  export async function deriveSessionKeyHKDF(clientSecretKey: Uint8Array, serverPublicKeyB64: string): Promise<string> {
    const n = await nacl()
    const serverPub = Uint8Array.from(atob(serverPublicKeyB64), c => c.charCodeAt(0))
    const shared = n.box.before(serverPub, clientSecretKey)
    const ikm = shared
    const salt = new Uint8Array([])
    const info = new TextEncoder().encode('secure-transfer-session')

    const keyMaterial = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
    const derivedBits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, keyMaterial, 256)
    const sessionKey = new Uint8Array(derivedBits)
    return btoa(String.fromCharCode(...sessionKey))
  }
}