import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Load dataset
data = pd.read_csv("phishing_site_urls.csv")

# Use the original feature columns
feature_columns = [
    'Having_@_symbol', 'Having_IP', 'Path', 'Prefix_suffix_separation',
    'Protocol', 'Redirection_//_symbol', 'Sub_domains', 'URL_Length',
    'age_domain', 'dns_record', 'domain_registration_length', 'http_tokens',
    'statistical_report', 'tiny_url', 'web_traffic'
]

# Encode object features if necessary
label_encoder = LabelEncoder()
for col in feature_columns:
    if data[col].dtype == 'object':
        data[col] = label_encoder.fit_transform(data[col])

# Final feature list (15)
X = data[feature_columns]
y = data['label']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save the model
os.makedirs("data", exist_ok=True)
joblib.dump(model, "data/phishing_model.pkl")

print("✅ Model retrained and saved with original features.")
