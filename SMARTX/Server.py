import os
import numpy as np
import datetime
from flask import Flask, request, jsonify
from neo4j import GraphDatabase
import joblib
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Set environment variable to disable oneDNN optimizations if needed
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# Global variables for model, vectorizer, and Neo4j driver
model = None
vectorizer = None
driver = None

# Paths to resources
VECTORIZER_PATH = r'Your vector path'
MODEL_PATH = r'Your Model path'
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "12345678"
DATABASE_NAME = "test"

# Load resources at the start of the app
def load_resources():
    global model, vectorizer, driver
    try:
        vectorizer = joblib.load(VECTORIZER_PATH)
        model = joblib.load(MODEL_PATH)
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD), database=DATABASE_NAME)
        print("All resources loaded successfully.")
    except Exception as e:
        app.logger.error(f"Failed to load resources: {str(e)}")
        raise RuntimeError(f"Failed to load resources: {str(e)}")

def calculate_features(urls):
    url_length = np.array([len(url) for url in urls])
    special_char_count = np.array([sum(1 for char in url if char in ['<', '>', '"', '&']) for url in urls])
    keyword_presence = np.array([1 if any(kw in url.lower() for kw in ['script', 'alert', 'img', 'onerror']) else 0 for url in urls])
    return url_length, special_char_count, keyword_presence

def process_batch(urls):
    X_tfidf = vectorizer.transform(urls).toarray()
    url_length, special_char_count, keyword_presence = calculate_features(urls)
    X_features = np.hstack([X_tfidf, url_length.reshape(-1, 1), special_char_count.reshape(-1, 1), keyword_presence.reshape(-1, 1)])
    return X_features

@app.route('/detect', methods=['POST'])
def detect():
    if not model or not vectorizer or not driver:
        return jsonify({"error": "System not ready, resources are not loaded"}), 500

    try:
        data = request.get_json(force=True)
        if 'inputString' not in data:
            return jsonify({"error": "Missing required field: inputString"}), 400

        urls = [data['inputString']]
        X_features = process_batch(urls)
        prediction = bool(model.predict(X_features)[0] > 0.5)

        if prediction:
            store_in_neo4j(data.get('clientID', 'Unknown'), data.get('hostIP', 'Unknown'), datetime.datetime.now(), urls[0])

        return jsonify({"isXSS": prediction})
    except Exception as e:
        app.logger.error(f"Error in detection: {str(e)}")
        return jsonify({"error": str(e)}), 500

def store_in_neo4j(client_id, host_ip, timestamp, url):
    try:
        with driver.session() as session:
            session.write_transaction(create_detection_record, client_id, host_ip, timestamp, url)
            print("XSS data stored successfully in Neo4j.")
    except Exception as e:
        app.logger.error(f"Error writing to Neo4j: {str(e)}")
        raise

def create_detection_record(tx, client_id, host_ip, timestamp, url):
    query = """
    MERGE (client:Client {id: $client_id})
    MERGE (host:Host {ip: $host_ip})
    MERGE (client)-[:HAS_HOST]->(host)
    CREATE (detection:Detection {timeStamp: $timestamp, payload: $url})
    MERGE (host)-[:HAS_DETECTION]->(detection)
    """
    tx.run(query, client_id=client_id, host_ip=host_ip, timestamp=timestamp.isoformat(), url=url)

if __name__ == "__main__":
    load_resources()
    app.run(host='127.0.0.1', port=8000, debug=True, threaded=True)
