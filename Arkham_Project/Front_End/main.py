from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt 
import seaborn as sns
import scapy.all as scapy
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
import io
import base64

# Initialize Flask app and set up the upload folder for storing files
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # Create the upload folder if it doesn't exist

# Function to process pcap files, reading packets and extracting relevant details
def process_pcap(file_path):
    packets = scapy.rdpcap(file_path)  # Read the pcap file using scapy
    data = []
    for pkt in packets:
        # Extract relevant packet details: time, length, and protocol
        protocol = pkt.proto if hasattr(pkt, 'proto') else None
        data.append([pkt.time, len(pkt), protocol])
    return pd.DataFrame(data, columns=['Time', 'Length', 'Protocol'])  # Return data as a DataFrame

# Function to detect potential threats from the packet data
def detect_threats(df):
    threats = []  # List to store identified threats
    for _, row in df.iterrows():
        # Check for conditions that suggest a threat (e.g., large packet length or reconnaissance scan)
        if row['Length'] > 1500:
            threat_type = "Potential DDoS Attack"
            severity = "High"
        elif row['Protocol'] == 1:  # ICMP protocol, commonly used in reconnaissance attacks
            threat_type = "Reconnaissance Scan"
            severity = "Medium"
        else:
            continue  # If no threat is detected, skip the row
        
        # Append detected threat information to the threats list
        threats.append({
            'Time': row['Time'],
            'Length': row['Length'],
            'Protocol': row['Protocol'],
            'Severity': severity,
            'ThreatType': threat_type
        })
    return threats  # Return the list of detected threats

# Function to generate and return a confusion matrix image based on the packet data
def generate_matrices(df):
    df = df.dropna()  # Remove any rows with missing data
    X = df[['Length', 'Protocol']]  # Feature columns (Length and Protocol)
    y = np.random.randint(0, 2, size=len(df))  # Dummy labels for classification (0 or 1)
    
    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
    
    # Create and train a Naive Bayes classifier model
    model = GaussianNB()
    model.fit(X_train, y_train)
    
    # Make predictions on the test data
    y_pred = model.predict(X_test)
    
    # Compute confusion matrix to evaluate the model
    cm = confusion_matrix(y_test, y_pred)
    
    # Create a heatmap to visualize the confusion matrix
    fig, ax = plt.subplots()
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax)
    ax.set_title("Confusion Matrix")
    
    # Save the heatmap as an image in memory
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    
    # Convert the image to base64 format for embedding in the HTML page
    cm_img = base64.b64encode(buf.getvalue()).decode('utf-8')
    plt.close(fig)  # Close the plot to free resources
    
    return cm_img  # Return the base64-encoded image of the confusion matrix

# Route for the main page
@app.route('/', methods=['GET', 'POST'])
def index():
    threats = []  # List to store detected threats
    cm_img = None  # Variable to store confusion matrix image
    
    # Handle file upload if the request method is POST
    if request.method == 'POST':
        file = request.files['file']  # Get the uploaded file
        if file and file.filename.endswith(('.pcap', '.csv')):  # Check if the file is a valid pcap or CSV
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)  # Save the file to the upload folder
            
            # Process the file based on its type (pcap or CSV)
            df = process_pcap(file_path) if file.filename.endswith('.pcap') else pd.read_csv(file_path)
            
            # Detect threats from the packet data
            threats = detect_threats(df)
            
            # Generate confusion matrix image
            cm_img = generate_matrices(df)
    
    # Render the index page and pass the threats and confusion matrix image
    return render_template('index.html', cm_img=cm_img, threats=threats)

# Run the app in debug mode
if __name__ == '__main__':
    app.run(debug=True)
