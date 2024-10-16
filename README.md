# A Scalable Machine Learning-Based Framework for Real-Time Detection of XSS Attacks in Web Applications

This project focuses on detecting and preventing Cross-Site Scripting (XSS) attacks using machine learning. The model is trained to identify potential XSS vulnerabilities in web applications and prevent malicious payloads from executing.

## Features

- **Real-Time XSS Detection:** Utilizes TF-IDF vectorization and custom features for real-time detection.
- **Machine Learning Model:** Employs MLPClassifier for classifying malicious scripts with high accuracy.
- **Data Preprocessing:** Includes custom feature extraction, such as URL length, special character count, and keyword presence.
- **Neo4j Integration:** Logs detected attacks and analysis in a Neo4j graph database for visualization.

## Prerequisites

- Python 3.8+
- Neo4j Database

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/Ittiwat812/SMARTX.git
    ```

2. Navigate to the project directory:
    ```bash
    cd SMARTX
    ```

3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Start the Flask app:
    ```bash
    python app.py
    ```

5. Open your browser and go to `http://localhost:5000`.

## Dataset

The training data used in this project consists of both legitimate and malicious samples to improve the model's accuracy in detecting XSS attacks.

- **Train_XSS.txt**: Contains examples of XSS payloads.
- **Train_NonXSS.txt**: Contains examples of non-malicious scripts.

## Model Training

The machine learning model is trained using the `MLPClassifier` from `scikit-learn`. The training script can be found in `Better_XSS_Detection_Model.ipynb`.

## Contributors

-  [Thanapat Thaipakdee](https://github.com/Nameister)
-  [Sirapitch Boonyasampan](https://github.com/titlesirapitch)
-  [Chawanakon Promsila]()

## Instructor

- **Dr. Somchart Fugkaew** - Advisor.

## License

This project is licensed under the Sirindhorn International Institute of Technology (SIIT), Thammasat University. All rights reserved.
