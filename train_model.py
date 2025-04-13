import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import pickle

# Load dataset
data = pd.read_csv("phishing_site_urls.csv")  # replace with actual filename

# Drop unused text columns if not needed, or encode them
if 'Domain' in data.columns:
    data = data.drop(columns=['Domain'])  # not useful for training

# Encode string columns
label_encoders = {}
for column in data.columns:
    if data[column].dtype == 'object':
        le = LabelEncoder()
        data[column] = le.fit_transform(data[column])
        label_encoders[column] = le  # Save encoder if needed later

# Separate features and label
X = data.drop(columns=['label'])
y = data['label']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save the model
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model retrained and saved successfully.")
