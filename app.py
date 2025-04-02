from flask import Flask, request, jsonify, render_template
import pickle
import numpy as np
from preprocess_url import preprocess_url  # Import the feature extraction function

# Load the trained model
with open('classifier.pkl', 'rb') as file:
    model = pickle.load(file)

# Initialize Flask app
app = Flask(__name__)

# Home route to render the HTML form
@app.route('/')
def home():
    return render_template('index.html')

# Route to predict URL legitimacy
@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form['url']  # Get URL from user input
        features = np.array(preprocess_url(url)).reshape(1, -1)  # Preprocess URL & reshape for prediction
        prediction = model.predict(features)[0]  # Predict using the model
        
        result = "Legitimate" if prediction == 1 else "Phishing"
        
        return render_template('index.html', prediction_text=f"The URL is classified as: {result}")

    except Exception as e:
        return jsonify({'error': str(e)})

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
