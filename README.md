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

## Installation (For Demo)

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
4. Change to your path

5. Start your neo4j and config an environment.

6. Start the Flask app:
    ```bash
    python server.py
    ```

7. Use a live server with template.
   
8. Try to input something.

### NOTE : Since, we have a batch processing we need at least 3 input (bath_size) if not you need to wait for 100 second.

## Dataset

The training data used in this project consists of both legitimate and malicious samples to improve the model's accuracy in detecting XSS attacks.

- **Train_XSS.txt**: Contains examples of XSS payloads.
- **Train_NonXSS.txt**: Contains examples of non-malicious scripts.

## Model Training

The machine learning model is trained using the `MLPClassifier` from `scikit-learn`. The training script can be found in `SMARTX_Model.ipynb`.

## Contributors

-  [Thanapat Thaipakdee](https://github.com/Nameister)
-  [Sirapitch Boonyasampan](https://github.com/titlesirapitch)
-  [Chawanakon Promsila]()

## Instructor

- **Dr. Somchart Fugkaew** - Advisor.

## Support the Project

If you find this project useful and would like to support its continued development, please consider making a donation. Your contributions help to encourage further development and improvements.

You can donate via PayPal: [Donate here](https://www.paypal.me/Ittiwat812)

Thank you for your support! 

## License

This project is licensed under the Sirindhorn International Institute of Technology (SIIT), Thammasat University. All rights reserved.
