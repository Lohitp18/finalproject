from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np
import os
from inference import predict_handshake, predict_file

app = Flask(__name__)

# Load models
HANDSHAKE_FEATURES = ['handshake_duration','key_size','signature_valid','client_entropy',
                      'server_entropy','retry_count','timestamp_hour','ip_reputation',
                      'geolocation_risk','protocol_version']

FILE_FEATURES = ['file_size','file_entropy','file_type_risk','encryption_strength',
                 'upload_duration','compression_ratio','metadata_anomaly',
                 'transfer_speed','packet_loss','concurrent_uploads']

handshake_model = None
file_model = None

def load_models():
    global handshake_model, file_model
    handshake_model = joblib.load('models/handshake_model.pkl')
    file_model = joblib.load('models/file_model.pkl')
    print("Models loaded successfully")

# Health check
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "models_loaded": handshake_model is not None})

# Predict handshake
@app.route('/predict/handshake', methods=['POST'])
def predict_handshake_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Use enhanced inference function
        anomaly_score, verdict = predict_handshake(data, handshake_model)
        
        return jsonify({
            "anomaly_score": float(anomaly_score),
            "verdict": verdict,
            "confidence": float(anomaly_score)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Predict file
@app.route('/predict/file', methods=['POST'])
def predict_file_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Use enhanced inference function
        anomaly_score, verdict = predict_file(data, file_model)
        
        return jsonify({
            "anomaly_score": float(anomaly_score),
            "verdict": verdict,
            "confidence": float(anomaly_score)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    load_models()
    app.run(host='0.0.0.0', port=6000, debug=True)
