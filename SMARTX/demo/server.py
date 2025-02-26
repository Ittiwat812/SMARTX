import os
import logging
from typing import List, Tuple
from datetime import datetime
import pickle
import numpy as np
from flask import Flask, render_template, request, jsonify
from neo4j import GraphDatabase
import threading
import queue
from urllib.parse import unquote

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class XSSDetectionApp:
    def __init__(self):
        self.app = Flask(__name__)
        
        # Environment Variables (Your Neo4j environment)
        self.NEO4J_URI = os.getenv('NEO4J_URI', "bolt://localhost:7687")
        self.NEO4J_USER = os.getenv('NEO4J_USER', "neo4j")
        self.NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD', "")
        
        # Fixed client and host values (For Demo)
        self.DEFAULT_CLIENT = "default_client"
        self.DEFAULT_HOST = "192.168.1.1"
        
        # Model and Vectorizer Paths
        self.MODEL_PATH = r'PATH/TO/mlpc_xss_model_without_custom_features.pkl'
        self.VECTORIZER_PATH = r'PATH/TO/tfidf_vectorizer_without_custom_features.pkl'
        
        # Threshold for XSS detection
        self.THRESHOLD = 0.95
        
        # Batch size and timeout
        self.BATCH_SIZE = 3
        self.BATCH_TIMEOUT = 100
        
        # Queue for batch processing
        self.batch_queue = queue.Queue()
        
        # Load ML Components
        self.load_ml_components()
        
        # Initialize Neo4j
        self.init_neo4j_driver()
        
        # Start batch processing thread
        self.start_batch_processing()
        
        # Setup Routes
        self.setup_routes()
        
    def load_ml_components(self):
        try:
            if not os.path.exists(self.MODEL_PATH) or not os.path.exists(self.VECTORIZER_PATH):
                logger.warning("Model files not found. Using dummy classifier.")
                self.model = DummyClassifier()
                self.vectorizer = DummyVectorizer()
            else:
                with open(self.MODEL_PATH, 'rb') as model_file:
                    self.model = pickle.load(model_file)
                with open(self.VECTORIZER_PATH, 'rb') as vectorizer_file:
                    self.vectorizer = pickle.load(vectorizer_file)
            logger.info("ML components loaded successfully")
        except Exception as e:
            logger.error(f"Error loading ML components: {e}")
            self.model = DummyClassifier()
            self.vectorizer = DummyVectorizer()
    
    def init_neo4j_driver(self):
        try:
            self.neo4j_driver = GraphDatabase.driver(
                self.NEO4J_URI, 
                auth=(self.NEO4J_USER, self.NEO4J_PASSWORD)
            )
            logger.info("Neo4j driver initialized")
        except Exception as e:
            logger.error(f"Neo4j driver initialization failed: {e}")
    
    def store_detection(self, xss_payload: str):
        try:
            with self.neo4j_driver.session() as session:
                random_time_str = datetime.now().isoformat()
                cypher_query = """
                MERGE (client:Client {client_name: $client_name})
                MERGE (host:Host {host_ip: $host_ip})
                CREATE (detection:Detection {xss_payload: $payload, timestamp: $timestamp})
                MERGE (client)-[:VISITED]->(host)
                MERGE (host)-[:HAS_DETECTION]->(detection)
                """
                session.run(cypher_query, 
                           client_name=self.DEFAULT_CLIENT,
                           host_ip=self.DEFAULT_HOST,
                           payload=xss_payload,
                           timestamp=random_time_str)
                logger.info(f"Detection stored in Neo4j: {xss_payload[:50]}...")
        except Exception as e:
            logger.error(f"Error storing detection in Neo4j: {e}")
    
    def process_batch(self, urls: List[str]) -> List[str]:
        logger.info(f"Processing batch of {len(urls)} inputs")
        return self.vectorizer.transform(urls)
    
    def predict_batch(self, X_batch: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        logger.info(f"Predicting on batch of {len(X_batch)} inputs")
        predictions = self.model.predict(X_batch)
        probabilities = self.model.predict_proba(X_batch)
        logger.info(f"Predictions: {predictions.tolist()}")
        return predictions, probabilities[:, 1]
    
    def batch_processing_worker(self):
        while True:
            inputs_to_process = []
            try:
                while len(inputs_to_process) < self.BATCH_SIZE:
                    input_data = self.batch_queue.get(timeout=self.BATCH_TIMEOUT)
                    inputs_to_process.append(input_data)
            except queue.Empty:
                if inputs_to_process:
                    logger.info(f"Timeout reached, processing {len(inputs_to_process)} inputs")
                else:
                    continue

            batch_urls = [data['text'] for data in inputs_to_process]
            X_batch = self.process_batch(batch_urls)
            predictions, probabilities = self.predict_batch(X_batch)

            for i, (input_data, pred, prob) in enumerate(zip(inputs_to_process, predictions, probabilities)):
                logger.info(f"Input: {input_data['text'][:50]}... Prediction: {pred}, Probability: {prob}")
                if pred == 1:
                    self.store_detection(input_data['text'])

            for _ in inputs_to_process:
                self.batch_queue.task_done()
    
    def start_batch_processing(self):
        batch_thread = threading.Thread(target=self.batch_processing_worker, daemon=True)
        batch_thread.start()
        logger.info("Batch processing thread started")
    
    def setup_routes(self):
        @self.app.route('/')
        def home():
            return render_template('index.html')
        
        @self.app.route('/api/detect', methods=['POST'])
        def detect_xss(self=self):
            try:
                data = request.json
                input_text = data.get('text', '').strip()
                
                if not input_text:
                    return jsonify({'error': 'Empty input'}), 400
                
                logger.info(f"Queuing input: {input_text[:100]}...")
                
                self.batch_queue.put({'text': input_text})
                
                return jsonify({
                    'input': input_text,
                    'message': 'Input queued for XSS detection'
                })
            
            except Exception as e:
                logger.error(f"XSS Detection error: {str(e)}")
                return jsonify({'error': 'Detection failed', 'details': str(e)}), 500
    
    def run(self, debug=True, port=5000):
        try:
            self.app.run(debug=debug, port=port)
        except Exception as e:
            logger.error(f"Application startup failed: {e}")
        finally:
            if hasattr(self, 'neo4j_driver'):
                self.neo4j_driver.close()

class DummyClassifier:
    def predict(self, X: List[str]) -> np.ndarray:
        if isinstance(X, str):
            X = [X]
        suspicious_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(']
        predictions = []
        for text in X:
            decoded_text = unquote(text).lower()
            is_xss = any(pattern in decoded_text for pattern in suspicious_patterns)
            logger.info(f"DummyClassifier predict - Input: {text[:50]}..., Decoded: {decoded_text[:50]}..., Is XSS: {is_xss}")
            predictions.append(1.0 if is_xss else 0.0)
        return np.array(predictions)
    
    def predict_proba(self, X: List[str]) -> np.ndarray:
        predictions = self.predict(X)
        probs = np.array([[1 - pred, pred] for pred in predictions])
        logger.info(f"DummyClassifier proba - Predictions: {predictions.tolist()}")
        return probs

class DummyVectorizer:
    def transform(self, X: List[str]) -> List[str]:
        logger.info(f"DummyVectorizer transform - Input: {X[:50]}...")
        return X

if __name__ == '__main__':
    app = XSSDetectionApp()
    app.run()