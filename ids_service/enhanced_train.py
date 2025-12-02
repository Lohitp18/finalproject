"""
Enhanced ML Training Script with Comprehensive Feature Engineering
Trains robust models for handshake and file anomaly detection
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    roc_auc_score, classification_report, confusion_matrix,
    precision_recall_curve, roc_curve, accuracy_score
)
import joblib
import os
from pathlib import Path

# Feature engineering functions
def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if len(data) == 0:
        return 0.0
    value_counts = pd.Series(data).value_counts()
    probabilities = value_counts / len(data)
    entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
    return entropy

def extract_handshake_features(row):
    """Extract comprehensive handshake features"""
    features = {
        'handshake_duration': row.get('handshake_duration', 0),
        'key_size': row.get('key_size', 256),
        'signature_valid': int(row.get('signature_valid', True)),
        'client_entropy': row.get('client_entropy', 0),
        'server_entropy': row.get('server_entropy', 0),
        'retry_count': row.get('retry_count', 0),
        'timestamp_hour': row.get('timestamp_hour', 12),
        'ip_reputation': row.get('ip_reputation', 0.5),
        'geolocation_risk': row.get('geolocation_risk', 0.2),
        'protocol_version': row.get('protocol_version', 1.0),
    }
    
    # Derived features
    features['entropy_diff'] = abs(features['client_entropy'] - features['server_entropy'])
    features['entropy_ratio'] = features['client_entropy'] / (features['server_entropy'] + 1e-10)
    features['duration_per_byte'] = features['handshake_duration'] / (features['key_size'] + 1)
    features['risk_composite'] = (features['ip_reputation'] + features['geolocation_risk']) / 2
    features['retry_ratio'] = features['retry_count'] / (features['handshake_duration'] + 1)
    
    return features

def extract_file_features(row):
    """Extract comprehensive file features"""
    features = {
        'file_size': row.get('file_size', 0),
        'file_entropy': row.get('file_entropy', 0),
        'file_type_risk': row.get('file_type_risk', 0.2),
        'encryption_strength': row.get('encryption_strength', 256),
        'upload_duration': row.get('upload_duration', 1.0),
        'compression_ratio': row.get('compression_ratio', 1.0),
        'metadata_anomaly': row.get('metadata_anomaly', 0),
        'transfer_speed': row.get('transfer_speed', 1000),
        'packet_loss': row.get('packet_loss', 0.0),
        'concurrent_uploads': row.get('concurrent_uploads', 1),
    }
    
    # Derived features
    features['size_log'] = np.log1p(features['file_size'])
    features['entropy_per_byte'] = features['file_entropy'] / (features['file_size'] + 1)
    features['speed_per_mb'] = features['transfer_speed'] / ((features['file_size'] / 1024 / 1024) + 1)
    features['risk_score'] = (
        features['file_type_risk'] * 0.3 +
        (features['file_entropy'] / 8.0) * 0.3 +
        (features['metadata_anomaly'] / 10.0) * 0.2 +
        min(features['packet_loss'], 1.0) * 0.2
    )
    features['suspicious_ratio'] = (
        features['file_entropy'] / 8.0 +
        features['metadata_anomaly'] / 10.0
    ) / 2
    
    # High entropy flag
    features['high_entropy'] = int(features['file_entropy'] > 7.5)
    features['low_entropy'] = int(features['file_entropy'] < 3.0)
    features['suspicious_size'] = int(features['file_size'] > 50 * 1024 * 1024)  # >50MB
    
    return features

def generate_synthetic_handshake_data(n_samples=2000, malicious_ratio=0.3):
    """Generate synthetic handshake data for training"""
    np.random.seed(42)
    data = []
    
    # Normal handshakes
    n_normal = int(n_samples * (1 - malicious_ratio))
    for _ in range(n_normal):
        data.append({
            'handshake_duration': np.random.normal(150, 30),
            'key_size': 256,
            'signature_valid': True,
            'client_entropy': np.random.normal(7.2, 0.3),
            'server_entropy': np.random.normal(7.2, 0.3),
            'retry_count': np.random.poisson(0.5),
            'timestamp_hour': np.random.randint(0, 24),
            'ip_reputation': np.random.uniform(0.7, 1.0),
            'geolocation_risk': np.random.uniform(0.0, 0.3),
            'protocol_version': 1.0,
            'label': 0  # Normal
        })
    
    # Malicious handshakes
    n_malicious = n_samples - n_normal
    for _ in range(n_malicious):
        data.append({
            'handshake_duration': np.random.normal(300, 100),  # Longer
            'key_size': np.random.choice([128, 256, 512]),
            'signature_valid': np.random.choice([True, False], p=[0.3, 0.7]),  # Often invalid
            'client_entropy': np.random.normal(6.0, 1.0),  # Lower or higher
            'server_entropy': np.random.normal(7.5, 0.5),
            'retry_count': np.random.poisson(3),  # More retries
            'timestamp_hour': np.random.randint(0, 24),
            'ip_reputation': np.random.uniform(0.0, 0.5),  # Lower reputation
            'geolocation_risk': np.random.uniform(0.5, 1.0),  # Higher risk
            'protocol_version': np.random.choice([0.9, 1.0, 1.1]),
            'label': 1  # Malicious
        })
    
    return pd.DataFrame(data)

def generate_synthetic_file_data(n_samples=2000, malicious_ratio=0.3):
    """Generate synthetic file data for training"""
    np.random.seed(42)
    data = []
    
    # Normal files
    n_normal = int(n_samples * (1 - malicious_ratio))
    for _ in range(n_normal):
        size = np.random.lognormal(12, 1.5)  # Realistic file sizes
        data.append({
            'file_size': size,
            'file_entropy': np.random.normal(5.5, 1.0),  # Normal entropy
            'file_type_risk': np.random.uniform(0.0, 0.3),
            'encryption_strength': 256,
            'upload_duration': size / np.random.uniform(50000, 200000),
            'compression_ratio': np.random.uniform(0.8, 1.2),
            'metadata_anomaly': np.random.uniform(0.0, 2.0),
            'transfer_speed': np.random.uniform(50000, 200000),
            'packet_loss': np.random.uniform(0.0, 0.05),
            'concurrent_uploads': np.random.randint(1, 3),
            'label': 0  # Normal
        })
    
    # Malicious files (corrupted, encrypted, suspicious)
    n_malicious = n_samples - n_normal
    for _ in range(n_malicious):
        size = np.random.lognormal(13, 2)
        malicious_type = np.random.choice(['high_entropy', 'corrupted', 'suspicious'])
        
        if malicious_type == 'high_entropy':
            entropy = np.random.uniform(7.5, 8.0)  # Very high entropy
            type_risk = np.random.uniform(0.6, 1.0)
        elif malicious_type == 'corrupted':
            entropy = np.random.uniform(1.0, 3.0)  # Very low entropy
            type_risk = np.random.uniform(0.7, 1.0)
        else:  # suspicious
            entropy = np.random.uniform(6.5, 7.5)
            type_risk = np.random.uniform(0.5, 0.9)
        
        data.append({
            'file_size': size,
            'file_entropy': entropy,
            'file_type_risk': type_risk,
            'encryption_strength': np.random.choice([128, 256, 512]),
            'upload_duration': size / np.random.uniform(10000, 50000),  # Slower
            'compression_ratio': np.random.uniform(0.3, 0.8),  # Odd compression
            'metadata_anomaly': np.random.uniform(5.0, 10.0),  # High anomaly
            'transfer_speed': np.random.uniform(10000, 50000),  # Slower
            'packet_loss': np.random.uniform(0.1, 0.5),  # Higher packet loss
            'concurrent_uploads': np.random.randint(3, 10),  # More concurrent
            'label': 1  # Malicious
        })
    
    return pd.DataFrame(data)

def train_handshake_model():
    """Train handshake anomaly detection model"""
    print("=" * 60)
    print("Training Handshake Anomaly Detection Model")
    print("=" * 60)
    
    # Generate training data
    print("\n1. Generating synthetic training data...")
    df = generate_synthetic_handshake_data(n_samples=5000, malicious_ratio=0.3)
    print(f"   Generated {len(df)} samples ({df['label'].sum()} malicious, {len(df) - df['label'].sum()} normal)")
    
    # Extract features
    print("\n2. Extracting features...")
    features_list = []
    for _, row in df.iterrows():
        feat = extract_handshake_features(row)
        feat['label'] = row['label']
        features_list.append(feat)
    
    feature_df = pd.DataFrame(features_list)
    print(f"   Extracted {len(feature_df.columns) - 1} features")
    
    # Prepare data
    X = feature_df.drop(columns=['label'])
    y = feature_df['label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"\n3. Data split: Train={len(X_train)}, Test={len(X_test)}")
    
    # Train model
    print("\n4. Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\n5. Evaluating model...")
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_pred_proba)
    
    print(f"\n   Accuracy: {accuracy:.4f}")
    print(f"   ROC-AUC: {auc:.4f}")
    print("\n   Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Malicious']))
    
    # Cross-validation
    print("\n6. Cross-validation...")
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='roc_auc')
    print(f"   CV ROC-AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Save model
    os.makedirs('models', exist_ok=True)
    model_path = 'models/handshake_model.pkl'
    joblib.dump(model, model_path)
    print(f"\n7. Model saved to {model_path}")
    
    # Feature importance
    print("\n8. Top 10 Feature Importances:")
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    print(feature_importance.head(10).to_string(index=False))
    
    return model

def train_file_model():
    """Train file anomaly detection model"""
    print("\n" + "=" * 60)
    print("Training File Anomaly Detection Model")
    print("=" * 60)
    
    # Generate training data
    print("\n1. Generating synthetic training data...")
    df = generate_synthetic_file_data(n_samples=5000, malicious_ratio=0.3)
    print(f"   Generated {len(df)} samples ({df['label'].sum()} malicious, {len(df) - df['label'].sum()} normal)")
    
    # Extract features
    print("\n2. Extracting features...")
    features_list = []
    for _, row in df.iterrows():
        feat = extract_file_features(row)
        feat['label'] = row['label']
        features_list.append(feat)
    
    feature_df = pd.DataFrame(features_list)
    print(f"   Extracted {len(feature_df.columns) - 1} features")
    
    # Prepare data
    X = feature_df.drop(columns=['label'])
    y = feature_df['label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"\n3. Data split: Train={len(X_train)}, Test={len(X_test)}")
    
    # Train model
    print("\n4. Training Gradient Boosting model...")
    model = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=10,
        learning_rate=0.1,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\n5. Evaluating model...")
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_pred_proba)
    
    print(f"\n   Accuracy: {accuracy:.4f}")
    print(f"   ROC-AUC: {auc:.4f}")
    print("\n   Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Malicious']))
    
    # Cross-validation
    print("\n6. Cross-validation...")
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='roc_auc')
    print(f"   CV ROC-AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Save model
    os.makedirs('models', exist_ok=True)
    model_path = 'models/file_model.pkl'
    joblib.dump(model, model_path)
    print(f"\n7. Model saved to {model_path}")
    
    # Feature importance
    print("\n8. Top 10 Feature Importances:")
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    print(feature_importance.head(10).to_string(index=False))
    
    return model

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("ENHANCED ML MODEL TRAINING")
    print("=" * 60)
    
    # Train both models
    handshake_model = train_handshake_model()
    file_model = train_file_model()
    
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE!")
    print("=" * 60)
    print("\nModels are ready for deployment.")
    print("Restart the IDS service to load the new models.")

