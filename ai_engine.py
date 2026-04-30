from sklearn.ensemble import IsolationForest
import numpy as np

# Simple anomaly detector
class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)

    def fit(self, data):
            self.model.fit(data)

    def predict(self, data):
            return self.model.predict(data) # -1 = anomaly, 1 = normal
        
# Convert logs into numeric features
def extract_features(logs):
    features = []

    for log in logs:
        # Simple feature extraction based on log length and presence of keywords
        length = len(log)
        num_digits = sum(c.isdigit() for c in log)
        num_special = sum(not c.isalnum() and not c.isspace() for c in log)

        features.append([length,num_digits, num_special])
    return np.array(features)