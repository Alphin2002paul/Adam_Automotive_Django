import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

def train_model():
    # Load the data
    data = pd.read_csv('car_reviews_with_feedback.csv')

    # Prepare the features and target
    X = data.drop(['would_recommend'], axis=1)
    y = data['would_recommend']

    # Encode categorical variables
    le = LabelEncoder()
    X['manufacturer'] = le.fit_transform(X['manufacturer'])
    X['model'] = le.fit_transform(X['model'])

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train the model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate the model
    accuracy = model.score(X_test, y_test)
    print(f"Model accuracy: {accuracy}")

    # Save the model
    joblib.dump(model, 'feedback_model.joblib')

def make_prediction(manufacturer, model, year, comfort, performance, fuel_efficiency, safety, technology):
    # Load the trained model
    model = joblib.load('feedback_model.joblib')

    # Prepare the input data
    input_data = pd.DataFrame({
        'manufacturer': [str(manufacturer)],  # Convert to string
        'model': [str(model)],  # Convert to string
        'year': [year],
        'comfort': [comfort],
        'performance': [performance],
        'fuel_efficiency': [fuel_efficiency],
        'safety': [safety],
        'technology': [technology]
    })

    # Encode categorical variables
    le = LabelEncoder()
    input_data['manufacturer'] = le.fit_transform(input_data['manufacturer'])
    input_data['model'] = le.fit_transform(input_data['model'])

    # Make prediction
    prediction = model.predict(input_data)
    probability = model.predict_proba(input_data)[0][1]

    return prediction[0], probability

if __name__ == "__main__":
    train_model()