# Quick Training Instructions

## Step 1: Install Dependencies

```bash
cd ids_service
pip install scikit-learn pandas numpy joblib
```

## Step 2: Train Models

```bash
python enhanced_train.py
```

This will:
- Generate 5,000 training samples
- Train both handshake and file models
- Save models to `models/` directory
- Display performance metrics

## Step 3: Restart IDS Service

```bash
python app.py
```

## Step 4: Verify

```bash
curl http://localhost:6000/health
```

Should return: `{"status": "healthy", "models_loaded": true}`

## Expected Training Time

- Handshake model: ~30-60 seconds
- File model: ~45-90 seconds
- Total: ~2-3 minutes

## Model Files

After training, you'll have:
- `models/handshake_model.pkl` - Handshake anomaly detection
- `models/file_model.pkl` - File anomaly detection

## Performance Targets

- **Accuracy**: > 95%
- **ROC-AUC**: > 0.97
- **False Positive Rate**: < 3%

