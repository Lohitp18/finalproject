# Enhanced ML Model Training Guide

## Overview
This guide explains how to train robust ML models for detecting corrupted and suspicious files using comprehensive feature engineering and advanced training techniques.

## Enhanced Training Script

The `enhanced_train.py` script provides:

### 1. **Comprehensive Feature Engineering**

#### Handshake Features (15 features):
- **Base Features**: handshake_duration, key_size, signature_valid, client_entropy, server_entropy, retry_count, timestamp_hour, ip_reputation, geolocation_risk, protocol_version
- **Derived Features**:
  - `entropy_diff`: Absolute difference between client and server entropy
  - `entropy_ratio`: Ratio of client to server entropy
  - `duration_per_byte`: Duration normalized by key size
  - `risk_composite`: Combined IP reputation and geolocation risk
  - `retry_ratio`: Retry count normalized by duration

#### File Features (18 features):
- **Base Features**: file_size, file_entropy, file_type_risk, encryption_strength, upload_duration, compression_ratio, metadata_anomaly, transfer_speed, packet_loss, concurrent_uploads
- **Derived Features**:
  - `size_log`: Logarithm of file size
  - `entropy_per_byte`: Entropy normalized by file size
  - `speed_per_mb`: Transfer speed per megabyte
  - `risk_score`: Composite risk score
  - `suspicious_ratio`: Combined entropy and metadata anomaly
  - `high_entropy`: Flag for entropy > 7.5
  - `low_entropy`: Flag for entropy < 3.0
  - `suspicious_size`: Flag for files > 50MB

### 2. **Advanced Model Training**

- **Random Forest** for handshake detection (300 trees, max_depth=15)
- **Gradient Boosting** for file detection (200 trees, learning_rate=0.1)
- **Class balancing** to handle imbalanced datasets
- **Cross-validation** (5-fold) for robust evaluation
- **Stratified splitting** to maintain class distribution

### 3. **Synthetic Data Generation**

Generates realistic training data with:
- **Normal patterns**: Realistic distributions for legitimate traffic
- **Malicious patterns**: Various attack scenarios
  - High entropy (encrypted/corrupted)
  - Low entropy (corrupted)
  - Suspicious metadata
  - Invalid signatures
  - Low IP reputation

## Training the Models

### Prerequisites

```bash
cd ids_service
pip install scikit-learn pandas numpy joblib
```

### Run Training

```bash
python enhanced_train.py
```

This will:
1. Generate 5,000 synthetic samples for each model
2. Extract comprehensive features
3. Train models with cross-validation
4. Evaluate performance (Accuracy, ROC-AUC)
5. Save models to `models/handshake_model.pkl` and `models/file_model.pkl`
6. Display feature importances

### Expected Output

```
============================================================
ENHANCED ML MODEL TRAINING
============================================================

============================================================
Training Handshake Anomaly Detection Model
============================================================

1. Generating synthetic training data...
   Generated 5000 samples (1500 malicious, 3500 normal)

2. Extracting features...
   Extracted 15 features

3. Data split: Train=4000, Test=1000

4. Training Random Forest model...

5. Evaluating model...
   Accuracy: 0.95XX
   ROC-AUC: 0.98XX

6. Cross-validation...
   CV ROC-AUC: 0.97XX (+/- 0.01XX)

7. Model saved to models/handshake_model.pkl

8. Top 10 Feature Importances:
   [Feature importance table]
```

## Model Performance Metrics

### Handshake Model
- **Target Accuracy**: > 95%
- **Target ROC-AUC**: > 0.97
- **False Positive Rate**: < 3%

### File Model
- **Target Accuracy**: > 94%
- **Target ROC-AUC**: > 0.96
- **False Positive Rate**: < 4%

## Adaptive Thresholds

The enhanced inference uses **adaptive thresholds** based on risk indicators:

### Handshake Detection
- **Base threshold**: 0.35
- **Lowered to 0.25** if:
  - Signature is invalid
  - IP reputation < 0.3

### File Detection
- **Base threshold**: 0.35
- **Lowered to 0.25** if:
  - File entropy > 7.8
  - File type risk > 0.7
  - Metadata anomaly > 5.0

## Feature Importance Analysis

After training, review feature importances to understand what the model learns:

### Top Handshake Features (typically):
1. `signature_valid` - Most important
2. `ip_reputation` - High importance
3. `entropy_diff` - Derived feature importance
4. `retry_count` - Attack indicator
5. `geolocation_risk` - Risk assessment

### Top File Features (typically):
1. `file_entropy` - Most important
2. `file_type_risk` - High importance
3. `metadata_anomaly` - Suspicious patterns
4. `risk_score` - Composite risk
5. `suspicious_ratio` - Derived feature

## Improving Model Performance

### 1. **Increase Training Data**
```python
# In enhanced_train.py, change:
df = generate_synthetic_handshake_data(n_samples=10000, malicious_ratio=0.3)
```

### 2. **Add More Features**
- Network-level features (packet timing, jitter)
- Behavioral features (upload patterns, time of day)
- Contextual features (user history, device fingerprint)

### 3. **Hyperparameter Tuning**
```python
from sklearn.model_selection import GridSearchCV

param_grid = {
    'n_estimators': [200, 300, 400],
    'max_depth': [10, 15, 20],
    'min_samples_split': [2, 5, 10]
}
```

### 4. **Ensemble Methods**
Combine multiple models:
- Random Forest + Gradient Boosting
- Voting classifier
- Stacking

## Deployment

After training:

1. **Models are saved** to `ids_service/models/`
2. **Restart IDS service** to load new models:
   ```bash
   cd ids_service
   python app.py
   ```
3. **Verify models loaded**:
   ```bash
   curl http://localhost:6000/health
   ```

## Testing the Models

Use the test suite:
```bash
node run_all_tests.js
```

The models should now:
- ✅ Detect corrupted files more accurately
- ✅ Have lower false positive rates
- ✅ Use adaptive thresholds for better detection
- ✅ Provide detailed risk scores

## Continuous Improvement

1. **Collect real-world data** from your system
2. **Label samples** (normal vs suspicious)
3. **Retrain periodically** with new data
4. **Monitor performance** metrics
5. **Adjust thresholds** based on false positive/negative rates

## Next Steps

1. Train the models: `python enhanced_train.py`
2. Restart IDS service
3. Test with corrupted files
4. Monitor detection rates
5. Fine-tune thresholds if needed

