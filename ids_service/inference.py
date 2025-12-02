import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

def extract_enhanced_handshake_features(features):
    """Extract enhanced features from handshake data"""
    enhanced = features.copy()
    
    # Derived features
    enhanced['entropy_diff'] = abs(enhanced.get('client_entropy', 0) - enhanced.get('server_entropy', 0))
    enhanced['entropy_ratio'] = enhanced.get('client_entropy', 0) / (enhanced.get('server_entropy', 0) + 1e-10)
    enhanced['duration_per_byte'] = enhanced.get('handshake_duration', 0) / (enhanced.get('key_size', 256) + 1)
    enhanced['risk_composite'] = (enhanced.get('ip_reputation', 0.5) + enhanced.get('geolocation_risk', 0.2)) / 2
    enhanced['retry_ratio'] = enhanced.get('retry_count', 0) / (enhanced.get('handshake_duration', 0) + 1)
    
    return enhanced

def extract_enhanced_file_features(features):
    """Extract enhanced features from file data"""
    enhanced = features.copy()
    
    # Derived features
    import math
    enhanced['size_log'] = math.log1p(enhanced.get('file_size', 0))
    enhanced['entropy_per_byte'] = enhanced.get('file_entropy', 0) / (enhanced.get('file_size', 1) + 1)
    
    file_size_mb = enhanced.get('file_size', 0) / (1024 * 1024)
    enhanced['speed_per_mb'] = enhanced.get('transfer_speed', 1000) / (file_size_mb + 1)
    
    enhanced['risk_score'] = (
        enhanced.get('file_type_risk', 0.2) * 0.3 +
        (enhanced.get('file_entropy', 0) / 8.0) * 0.3 +
        (enhanced.get('metadata_anomaly', 0) / 10.0) * 0.2 +
        min(enhanced.get('packet_loss', 0), 1.0) * 0.2
    )
    
    enhanced['suspicious_ratio'] = (
        enhanced.get('file_entropy', 0) / 8.0 +
        enhanced.get('metadata_anomaly', 0) / 10.0
    ) / 2
    
    # Flags
    enhanced['high_entropy'] = int(enhanced.get('file_entropy', 0) > 7.5)
    enhanced['low_entropy'] = int(enhanced.get('file_entropy', 0) < 3.0)
    enhanced['suspicious_size'] = int(enhanced.get('file_size', 0) > 50 * 1024 * 1024)
    
    return enhanced

def predict_handshake(features, model):
    """
    Predict handshake anomaly using trained model with enhanced features
    
    Args:
        features: dict of handshake features
        model: trained ML model
    
    Returns:
        tuple: (anomaly_score, verdict)
    """
    try:
        # Extract enhanced features
        enhanced_features = extract_enhanced_handshake_features(features)
        
        # Convert to DataFrame with all expected columns
        expected_cols = [
            'handshake_duration', 'key_size', 'signature_valid', 'client_entropy',
            'server_entropy', 'retry_count', 'timestamp_hour', 'ip_reputation',
            'geolocation_risk', 'protocol_version', 'entropy_diff', 'entropy_ratio',
            'duration_per_byte', 'risk_composite', 'retry_ratio'
        ]
        
        # Create DataFrame with all expected columns
        feature_dict = {}
        for col in expected_cols:
            feature_dict[col] = enhanced_features.get(col, 0)
        
        feature_df = pd.DataFrame([feature_dict])
        
        # Get prediction probability
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(feature_df)
            anomaly_score = probabilities[0][1] if len(probabilities[0]) > 1 else probabilities[0][0]
        else:
            anomaly_score = model.predict(feature_df)[0]
        
        # Adaptive threshold based on risk indicators
        base_threshold = 0.35
        if enhanced_features.get('signature_valid', True) == False:
            base_threshold = 0.25  # Lower threshold if signature invalid
        if enhanced_features.get('ip_reputation', 0.5) < 0.3:
            base_threshold = 0.25  # Lower threshold for low reputation
        
        verdict = "suspicious" if anomaly_score > base_threshold else "normal"
        
        return float(anomaly_score), verdict
    
    except Exception as e:
        print(f"Error in handshake prediction: {e}")
        # Return safe defaults
        return 0.1, "normal"

def predict_file(features, model):
    """
    Predict file transfer anomaly using trained model with enhanced features
    
    Args:
        features: dict of file features
        model: trained ML model
    
    Returns:
        tuple: (anomaly_score, verdict)
    """
    try:
        # Extract enhanced features
        enhanced_features = extract_enhanced_file_features(features)
        
        # Convert to DataFrame with all expected columns
        expected_cols = [
            'file_size', 'file_entropy', 'file_type_risk', 'encryption_strength',
            'upload_duration', 'compression_ratio', 'metadata_anomaly',
            'transfer_speed', 'packet_loss', 'concurrent_uploads',
            'size_log', 'entropy_per_byte', 'speed_per_mb', 'risk_score',
            'suspicious_ratio', 'high_entropy', 'low_entropy', 'suspicious_size'
        ]
        
        # Create DataFrame with all expected columns
        feature_dict = {}
        for col in expected_cols:
            feature_dict[col] = enhanced_features.get(col, 0)
        
        feature_df = pd.DataFrame([feature_dict])
        
        # Get prediction probability
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(feature_df)
            anomaly_score = probabilities[0][1] if len(probabilities[0]) > 1 else probabilities[0][0]
        else:
            anomaly_score = model.predict(feature_df)[0]
        
        # Adaptive threshold based on risk indicators
        base_threshold = 0.35
        if enhanced_features.get('file_entropy', 0) > 7.8:
            base_threshold = 0.25  # Lower threshold for high entropy
        if enhanced_features.get('file_type_risk', 0.2) > 0.7:
            base_threshold = 0.25  # Lower threshold for high type risk
        if enhanced_features.get('metadata_anomaly', 0) > 5.0:
            base_threshold = 0.25  # Lower threshold for high metadata anomaly
        
        verdict = "suspicious" if anomaly_score > base_threshold else "normal"
        
        return float(anomaly_score), verdict
    
    except Exception as e:
        print(f"Error in file prediction: {e}")
        # Return safe defaults
        return 0.1, "normal"

def create_dummy_models():
    """
    Create dummy models for development/testing
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.datasets import make_classification
    
    # Create dummy handshake model
    X_handshake, y_handshake = make_classification(n_samples=1000, n_features=10, random_state=42)
    handshake_model = RandomForestClassifier(n_estimators=10, random_state=42)
    handshake_model.fit(X_handshake, y_handshake)
    
    # Create dummy file model
    X_file, y_file = make_classification(n_samples=1000, n_features=10, random_state=42)
    file_model = RandomForestClassifier(n_estimators=10, random_state=42)
    file_model.fit(X_file, y_file)
    
    return handshake_model, file_model
