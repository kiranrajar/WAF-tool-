from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import os
import numpy as np

app = FastAPI()

# Load the model
model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
if os.path.exists(model_path):
    model = joblib.load(model_path)
else:
    model = None
    print("Warning: model.pkl not found. Run train.py first.")

class Features(BaseModel):
    features: list

@app.post("/score")
def score(data: Features):
    if model is None:
        return {"risk": 0.5, "anomaly": 0, "message": "Model not loaded"}
    
    # Isolation Forest: decision_function returns the anomaly score.
    s = model.decision_function([data.features])[0]
    
    # Map the score to a 0-1 risk scale
    # Normal scores are around 0.1, anomalies move toward -0.3
    risk = 1.0 - (s + 0.3) / 0.4 
    risk = max(0, min(1, risk))
    
    prediction = model.predict([data.features])[0]
    
    return {
        "risk": float(risk),
        "is_anomaly": bool(prediction == -1),
        "score": float(s)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
