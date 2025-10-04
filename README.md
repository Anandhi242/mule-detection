# mule-detection
Detect mule accounts and financial fraud using AI-powered graph analysis and pattern recognition
Mule Detection System Using HGT
AI-powered fraud detection system for identifying mule accounts using Hierarchical Graph Transformers and advanced fraud pattern analysis.
Features

10+ fraud pattern biomarkers (crypto transfers, round-robin, reversal loops, etc.)
Interactive network graph visualization
Real-time risk scoring (Critical/High/Medium/Low)
Transaction analysis dashboard
Secure authentication system

Quick Start
bash# Clone repository
git clone https://github.com/yourusername/mule-detection-system.git
cd "  "

Setup virtual environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

Install dependencies:
pip install -r requirements.txt

Create directories:
mkdir uploads static

Run application:
python app.py
Open browser to http://localhost:5000
Usage

Login with credentials:
Upload JSON transaction file
View analysis, graph, and risk scores

Sample JSON format:
json[
    {
        "source": "ACC001",
        "destination": "ACC002",
        "amount": 75000,
        "timestamp": "2024-01-15T10:30:00",
        "device": "DEV001",
        "ip": "192.168.1.100",
        "remarks": "transfer"
    }
]
Fraud Biomarkers:

Crypto Transfers (90% risk)
Round-Robin Patterns (85% risk)
Shared Device/IP (75% risk)
High Velocity Transactions (70% risk)
Suspicious Remarks (60% risk)
Plus 5 more advanced patterns

Tech Stack:
Flask 2.3.3
vis.js for network graphs
HTML/CSS/JavaScript

Author
Anandhi G
