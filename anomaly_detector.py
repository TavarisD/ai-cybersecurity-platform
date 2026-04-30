from sklearn.ensemble import IsolationForest

model = IsolationForest(contamination=0.1, random_state=42)

# Only numeric values, and every row must have same number of columns
training_data = [
    [0, 0],
    [0, 0],
    [1, 0],
    [0, 1],
    [1, 1],
    [0,0]
]

model.fit(training_data)

def detect_anomaly(features):
    data = [[
        int(features.get("failed_login", 0)),
        int(features.get("sql_injection", 0))
    ]]

    prediction = model.predict(data)
    return "anomaly" if prediction[0] == -1 else "normal"

