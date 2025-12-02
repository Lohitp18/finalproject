import React, { useState, useEffect } from 'react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Alert } from '@/components/ui/Alert'
import { AlertTriangle, Shield, Eye, EyeOff, CheckCircle, Clock, Filter } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { api, IntrusionAlert } from '@/lib/api'
import { toast } from 'react-hot-toast'

export function IntrusionAlertsPanel() {
  const [alerts, setAlerts] = useState<IntrusionAlert[]>([])
  const [filteredAlerts, setFilteredAlerts] = useState<IntrusionAlert[]>([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({
    severity: 'all',
    status: 'all',
    threat_type: 'all'
  })
  const [liveMode, setLiveMode] = useState(true)

  useEffect(() => {
    loadAlerts()
    
    // Auto-refresh alerts every 5 seconds
    const refreshInterval = setInterval(() => {
      loadAlerts()
    }, 5000)
    
    if (liveMode) {
      // Connect to WebSocket for real-time alerts
      const ws = api.connectWebSocket((newAlert) => {
        setAlerts(prev => [newAlert, ...prev])
        
        // Show toast notification for high/critical alerts
        if (newAlert.severity === 'high' || newAlert.severity === 'critical') {
          toast.error(`🚨 ${newAlert.severity.toUpperCase()}: ${newAlert.threat_type}`, {
            duration: 5000,
          })
        }
      })

      return () => {
        clearInterval(refreshInterval)
        ws.close()
      }
    }
    
    return () => clearInterval(refreshInterval)
  }, [liveMode])

  useEffect(() => {
    // Apply filters
    let filtered = [...alerts]

    if (filters.severity !== 'all') {
      filtered = filtered.filter(alert => alert.severity === filters.severity)
    }

    if (filters.status !== 'all') {
      filtered = filtered.filter(alert => 
        filters.status === 'resolved' ? alert.resolved : !alert.resolved
      )
    }

    if (filters.threat_type !== 'all') {
      filtered = filtered.filter(alert => alert.threat_type === filters.threat_type)
    }

    setFilteredAlerts(filtered)
  }, [alerts, filters])

  const loadAlerts = async () => {
    try {
      const alertsData = await api.getIntrusionAlerts()
      setAlerts(alertsData)
    } catch (error) {
      console.error('Failed to load alerts:', error)
      toast.error('Failed to load intrusion alerts')
    } finally {
      setLoading(false)
    }
  }

  const resolveAlert = async (alertId: string) => {
    try {
      await api.resolveAlert(alertId)
      setAlerts(prev => prev.map(alert => 
        alert.id === alertId ? { ...alert, resolved: true } : alert
      ))
      toast.success('Alert marked as resolved')
    } catch (error) {
      console.error('Failed to resolve alert:', error)
      toast.error('Failed to resolve alert')
    }
  }

  const getSeverityColor = (severity: IntrusionAlert['severity']) => {
    switch (severity) {
      case 'critical': return 'destructive'
      case 'high': return 'warning'
      case 'medium': return 'secondary'
      case 'low': return 'default'
      default: return 'default'
    }
  }

  const getSeverityIcon = (severity: IntrusionAlert['severity']) => {
    switch (severity) {
      case 'critical':
        return '🔴'
      case 'high':
        return '🟠'
      case 'medium':
        return '🟡'
      case 'low':
        return '🟢'
      default:
        return '⚪'
    }
  }

  const uniqueThreatTypes = [...new Set(alerts.map(alert => alert.threat_type))]

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Intrusion Detection Alerts</h1>
          <p className="text-gray-400">Real-time threat monitoring and analysis</p>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            onClick={loadAlerts}
            className="flex items-center"
          >
            <Clock className="h-4 w-4 mr-1" />
            Refresh
          </Button>
          <Button
            variant={liveMode ? 'default' : 'outline'}
            size="sm"
            onClick={() => setLiveMode(!liveMode)}
            className="flex items-center"
          >
            {liveMode ? <Eye className="h-4 w-4 mr-1" /> : <EyeOff className="h-4 w-4 mr-1" />}
            Live Mode
          </Button>
          <Badge variant="secondary" className="text-sm">
            {alerts.filter(a => !a.resolved).length} Unresolved
          </Badge>
        </div>
      </div>

      {/* Real-time Status */}
      {liveMode && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <Alert variant="default">
            <Shield className="h-4 w-4" />
            <div>
              <h4 className="font-medium">Live Monitoring Active</h4>
              <p className="text-sm text-gray-600">
                Real-time intrusion detection is enabled. New threats will appear automatically.
              </p>
            </div>
          </Alert>
        </motion.div>
      )}

      {/* Filters */}
      <Card className="bg-gray-800/50 border-gray-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center">
            <Filter className="mr-2 h-5 w-5" />
            Filters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Severity</label>
              <select
                value={filters.severity}
                onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Status</label>
              <select
                value={filters.status}
                onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Statuses</option>
                <option value="unresolved">Unresolved</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Threat Type</label>
              <select
                value={filters.threat_type}
                onChange={(e) => setFilters(prev => ({ ...prev, threat_type: e.target.value }))}
                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Types</option>
                {uniqueThreatTypes.map(type => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Alerts List */}
      <Card className="bg-gray-800/50 border-gray-700">
        <CardHeader>
          <CardTitle className="text-white">Active Threats</CardTitle>
          <CardDescription className="text-gray-400">
            {filteredAlerts.length} alerts found
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
            </div>
          ) : filteredAlerts.length === 0 ? (
            <div className="text-center py-8">
              <Shield className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-400">No alerts match your current filters</p>
            </div>
          ) : (
            <div className="space-y-4">
              <AnimatePresence>
                {filteredAlerts.map((alert, index) => (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ delay: index * 0.05 }}
                    className={`p-4 rounded-lg border transition-all ${
                      alert.resolved 
                        ? 'bg-gray-700/30 border-gray-600/30 opacity-60' 
                        : 'bg-red-900/20 border-red-500/30'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3">
                        <span className="text-2xl">{getSeverityIcon(alert.severity)}</span>
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-2">
                            <h4 className="font-medium text-white">{alert.threat_type}</h4>
                            <Badge variant={getSeverityColor(alert.severity) as any}>
                              {alert.severity}
                            </Badge>
                            {alert.resolved && (
                              <Badge variant="success" className="text-xs">
                                Resolved
                              </Badge>
                            )}
                          </div>
                          
                          <div className="grid grid-cols-2 gap-4 text-sm">
                            <div>
                              <span className="text-gray-400">Source IP:</span>
                              <p className="text-white font-mono">{alert.source_ip}</p>
                            </div>
                            <div>
                              <span className="text-gray-400">ML Confidence:</span>
                              <p className="text-white">{(alert.confidence * 100).toFixed(1)}%</p>
                            </div>
                            <div>
                              <span className="text-gray-400">ML Score:</span>
                              <p className="text-white">{alert.ml_score.toFixed(3)}</p>
                            </div>
                            <div>
                              <span className="text-gray-400">Detected:</span>
                              <p className="text-white">
                                {new Date(alert.created_at).toLocaleString()}
                              </p>
                            </div>
                          </div>

                          {alert.details && (
                            <div className="mt-3 p-3 bg-gray-700/50 rounded text-xs space-y-2">
                              {alert.details.filename && (
                                <div>
                                  <span className="text-gray-400">Filename:</span>
                                  <p className="text-gray-300 font-mono">{alert.details.filename}</p>
                                </div>
                              )}
                              {alert.details.issues && Array.isArray(alert.details.issues) && alert.details.issues.length > 0 && (
                                <div>
                                  <span className="text-gray-400">Issues Detected:</span>
                                  <ul className="list-disc list-inside text-red-300 mt-1">
                                    {alert.details.issues.map((issue, idx) => (
                                      <li key={idx}>{issue}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                              {alert.details.reason && (
                                <div>
                                  <span className="text-gray-400">Reason:</span>
                                  <p className="text-yellow-300 mt-1">{alert.details.reason}</p>
                                </div>
                              )}
                              {alert.details.detected_type && (
                                <div>
                                  <span className="text-gray-400">Detected Type:</span>
                                  <p className="text-gray-300">{alert.details.detected_type}</p>
                                </div>
                              )}
                              {alert.details.entropy !== undefined && (
                                <div>
                                  <span className="text-gray-400">Entropy:</span>
                                  <p className="text-gray-300">{alert.details.entropy.toFixed(2)}</p>
                                </div>
                              )}
                              {alert.attack_vector && (
                                <div>
                                  <span className="text-gray-400">Attack Vector:</span>
                                  <p className="text-gray-300 mt-1">{alert.attack_vector}</p>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center space-x-2">
                        {alert.resolved ? (
                          <div className="flex items-center text-green-400 text-sm">
                            <CheckCircle className="h-4 w-4 mr-1" />
                            Resolved
                          </div>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => resolveAlert(alert.id)}
                            className="text-xs"
                          >
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Resolve
                          </Button>
                        )}
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}