import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

def predict_handshake(features, model):
    """
    Predict handshake anomaly using trained model
    
    Args:
        features: dict of handshake features
        model: trained ML model
    
    Returns:
        tuple: (anomaly_score, verdict)
    """
    try:
        # Convert features to DataFrame
        feature_df = pd.DataFrame([features])
        
        # Normalize features (assuming model expects normalized data)
        scaler = StandardScaler()
        normalized_features = scaler.fit_transform(feature_df)
        
        # Get prediction probability
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(normalized_features)
            anomaly_score = probabilities[0][1] if len(probabilities[0]) > 1 else probabilities[0][0]
        else:
            anomaly_score = model.predict(normalized_features)[0]
        
        # Determine verdict
        threshold = 0.5
        verdict = "suspicious" if anomaly_score > threshold else "normal"
        
        return anomaly_score, verdict
    
    except Exception as e:
        print(f"Error in handshake prediction: {e}")
        # Return safe defaults
        return 0.1, "normal"

def predict_file(features, model):
    """
    Predict file transfer anomaly using trained model
    
    Args:
        features: dict of file features
        model: trained ML model
    
    Returns:
        tuple: (anomaly_score, verdict)
    """
    try:
        # Convert features to DataFrame
        feature_df = pd.DataFrame([features])
        
        # Normalize features
        scaler = StandardScaler()
        normalized_features = scaler.fit_transform(feature_df)
        
        # Get prediction probability
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(normalized_features)
            anomaly_score = probabilities[0][1] if len(probabilities[0]) > 1 else probabilities[0][0]
        else:
            anomaly_score = model.predict(normalized_features)[0]
        
        # Determine verdict
        threshold = 0.4
        verdict = "suspicious" if anomaly_score > threshold else "normal"
        
        return anomaly_score, verdict
    
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
