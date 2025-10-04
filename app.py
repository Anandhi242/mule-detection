import os
import json
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename

# Flask Configuration
app = Flask(__name__)
app.secret_key = "mule_detection_hgt_2025"
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("static", exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# User Credentials
USERS = {
    "admin": "password123",
    "analyst": "fraud2025"
}

# Biomarkers from your project report
FRAUD_BIOMARKERS = {
    "Reversal Loops": {
        "description": "Funds received and quickly refunded to create confusion in audit trails",
        "risk_weight": 75,
        "example": "₹50,000 received, refunded in 10 minutes"
    },
    "Crypto Transfers": {
        "description": "Money transferred to cryptocurrency exchanges to obscure ownership",
        "risk_weight": 90,
        "example": "₹1,20,000 sent to Binance wallet"
    },
    "Round-Robin": {
        "description": "Money cycles through accounts in loops before exiting",
        "risk_weight": 85,
        "example": "A → B → C → A with timing variations"
    },
    "Fixed-Time Loops": {
        "description": "Automated transfers at precise, predictable intervals",
        "risk_weight": 70,
        "example": "₹10,000 daily at exactly 9:01 AM"
    },
    "Fake Merchant QR": {
        "description": "QR codes labeled as business without valid GST/PAN registration",
        "risk_weight": 80,
        "example": "QR tagged 'shop' with no GST link"
    },
    "Suspicious Remarks": {
        "description": "Transaction comments with fraud-associated keywords",
        "risk_weight": 60,
        "example": "Words like 'gift', 'loan', 'refund', 'test'"
    },
    "Headless Browser": {
        "description": "Multiple accounts accessed via automated browser tools",
        "risk_weight": 85,
        "example": "5 accounts logged in via Chrome Headless within 1 minute"
    },
    "Cloud-Hosted Access": {
        "description": "Remote access from cloud servers to manage multiple accounts",
        "risk_weight": 80,
        "example": "5 accounts accessed from AWS EC2 instance"
    },
    "Shared Device/IP": {
        "description": "Multiple accounts using same device or IP address",
        "risk_weight": 75,
        "example": "Device DEV001 used by 8 different accounts"
    },
    "High Velocity": {
        "description": "Rapid succession of high-value transactions",
        "risk_weight": 70,
        "example": "10 transactions totaling ₹5L in 30 minutes"
    }
}

def detect_fraud_patterns(transactions):
    """Detect fraud patterns based on biomarkers"""
    patterns = []
    account_data = {}
    
    # Analyze each transaction
    for i, txn in enumerate(transactions):
        source = txn.get("source", f"ACC{i:03d}")
        dest = txn.get("destination", f"ACC{i+100:03d}")
        amount = float(txn.get("amount", random.randint(1000, 200000)))
        device = txn.get("device", f"DEV{random.randint(1,50):03d}")
        ip = txn.get("ip", f"192.168.{random.randint(1,255)}.{random.randint(1,255)}")
        remarks = txn.get("remarks", "transfer")
        timestamp = txn.get("timestamp", datetime.now().isoformat())
        
        # Track account activity
        for acc in [source, dest]:
            if acc not in account_data:
                account_data[acc] = {
                    "transactions": [], "devices": set(), "ips": set(),
                    "total_in": 0, "total_out": 0, "remarks": []
                }
        
        account_data[source]["transactions"].append(txn)
        account_data[source]["devices"].add(device)
        account_data[source]["ips"].add(ip)
        account_data[source]["total_out"] += amount
        account_data[source]["remarks"].append(remarks.lower())
        
        account_data[dest]["transactions"].append(txn)
        account_data[dest]["devices"].add(device)
        account_data[dest]["ips"].add(ip)
        account_data[dest]["total_in"] += amount
        account_data[dest]["remarks"].append(remarks.lower())
        
        # Pattern Detection
        
        # 1. High Velocity Transactions
        if amount > 100000:
            patterns.append({
                "pattern": "High Velocity",
                "account": source,
                "details": f"High-value transfer: ₹{amount:,.0f} from {source} to {dest}",
                "risk_score": min(95, 50 + (amount / 10000)),
                "timestamp": timestamp
            })
        
        # 2. Crypto Transfer Pattern
        if "crypto" in remarks.lower() or "binance" in remarks.lower() or "exchange" in remarks.lower():
            patterns.append({
                "pattern": "Crypto Transfers",
                "account": source,
                "details": f"Suspected crypto transfer: ₹{amount:,.0f} with remarks '{remarks}'",
                "risk_score": 90,
                "timestamp": timestamp
            })
        
        # 3. Suspicious Remarks
        suspicious_words = ["gift", "loan", "refund", "test", "urgent", "help"]
        if any(word in remarks.lower() for word in suspicious_words):
            patterns.append({
                "pattern": "Suspicious Remarks",
                "account": source,
                "details": f"Suspicious transaction remark: '{remarks}' for ₹{amount:,.0f}",
                "risk_score": 60,
                "timestamp": timestamp
            })
    
    # Shared Device/IP Detection
    device_usage = {}
    ip_usage = {}
    
    for acc, data in account_data.items():
        for device in data["devices"]:
            if device not in device_usage:
                device_usage[device] = []
            device_usage[device].append(acc)
        
        for ip in data["ips"]:
            if ip not in ip_usage:
                ip_usage[ip] = []
            ip_usage[ip].append(acc)
    
    # Flag shared devices
    for device, accounts in device_usage.items():
        if len(accounts) > 3:
            patterns.append({
                "pattern": "Shared Device/IP",
                "accounts": accounts,
                "details": f"Device {device} used by {len(accounts)} accounts: {', '.join(accounts[:5])}",
                "risk_score": min(90, 40 + len(accounts) * 8),
                "timestamp": datetime.now().isoformat()
            })
    
    # Flag shared IPs
    for ip, accounts in ip_usage.items():
        if len(accounts) > 4:
            patterns.append({
                "pattern": "Shared Device/IP",
                "accounts": accounts,
                "details": f"IP {ip} used by {len(accounts)} accounts: {', '.join(accounts[:5])}",
                "risk_score": min(85, 35 + len(accounts) * 7),
                "timestamp": datetime.now().isoformat()
            })
    
    return patterns

def calculate_risk_scores(patterns, transactions):
    """Calculate comprehensive risk scores"""
    account_risks = {}
    
    # Initialize accounts from transactions
    for txn in transactions:
        source = txn.get("source", "Unknown")
        dest = txn.get("destination", "Unknown")
        amount = float(txn.get("amount", 0))
        
        for acc in [source, dest]:
            if acc not in account_risks:
                account_risks[acc] = {
                    "base_score": 10,
                    "patterns": [],
                    "total_amount": 0,
                    "transaction_count": 0,
                    "risk_factors": []
                }
            
            account_risks[acc]["total_amount"] += amount
            account_risks[acc]["transaction_count"] += 1
    
    # Add pattern-based risks
    for pattern in patterns:
        pattern_name = pattern["pattern"]
        risk_score = pattern.get("risk_score", 50)
        
        # Single account patterns
        if "account" in pattern:
            acc = pattern["account"]
            if acc in account_risks:
                account_risks[acc]["patterns"].append(pattern_name)
                account_risks[acc]["base_score"] += risk_score * 0.6
                account_risks[acc]["risk_factors"].append(pattern["details"])
        
        # Multi-account patterns
        if "accounts" in pattern:
            for acc in pattern["accounts"]:
                if acc in account_risks:
                    account_risks[acc]["patterns"].append(pattern_name)
                    account_risks[acc]["base_score"] += risk_score * 0.4
                    account_risks[acc]["risk_factors"].append(pattern["details"])
    
    # Calculate final risk scores
    risk_results = []
    for account, data in account_risks.items():
        final_score = min(100, data["base_score"])
        
        # Determine risk level and color
        if final_score >= 80:
            risk_level = "Critical"
            color = "#FF4444"
        elif final_score >= 60:
            risk_level = "High"
            color = "#FF8800"
        elif final_score >= 35:
            risk_level = "Medium"
            color = "#FFAA00"
        else:
            risk_level = "Low"
            color = "#44AA44"
        
        risk_results.append({
            "account": account,
            "risk_score": round(final_score, 1),
            "risk_level": risk_level,
            "color": color,
            "total_amount": data["total_amount"],
            "transaction_count": data["transaction_count"],
            "patterns": list(set(data["patterns"])),
            "risk_factors": data["risk_factors"][:3]
        })
    
    return sorted(risk_results, key=lambda x: x["risk_score"], reverse=True)

def create_graph_html(transactions):
    """Create interactive graph HTML using vis.js"""
    if not transactions:
        return "<p style='color: white; text-align: center;'>No transaction data available</p>"
    
    # Collect nodes and edges
    nodes = {}
    edges = []
    
    for i, txn in enumerate(transactions):
        source = str(txn.get("source", f"ACC{i:03d}"))
        dest = str(txn.get("destination", f"ACC{i+100:03d}"))
        amount = float(txn.get("amount", 10000))
        
        # Add nodes with colors based on amount
        if amount > 100000:
            source_color = "#FF4444"  # Red for high risk
            dest_color = "#FF8800"    # Orange
        elif amount > 50000:
            source_color = "#FFAA00"  # Yellow
            dest_color = "#87CEEB"    # Light blue
        else:
            source_color = "#87CEEB"  # Light blue
            dest_color = "#90EE90"    # Light green
        
        nodes[source] = {"color": source_color, "label": source}
        nodes[dest] = {"color": dest_color, "label": dest}
        
        # Add edge
        edge_color = "#FF4444" if amount > 100000 else "#FFAA00" if amount > 50000 else "#00d4aa"
        edges.append({
            "from": source,
            "to": dest,
            "label": f"₹{amount:,.0f}",
            "color": edge_color,
            "width": min(8, amount / 20000) or 2
        })
    
    # Create HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Transaction Network Graph</title>
        <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
        <style>
            body {{ 
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); 
                margin: 0; 
                font-family: 'Segoe UI', sans-serif; 
                color: white;
            }}
            #network {{ 
                width: 100%; 
                height: 600px; 
                border: 2px solid #00d4aa; 
                border-radius: 10px;
                background: #0f0f23;
            }}
            .info {{ 
                text-align: center; 
                padding: 20px;
                background: rgba(255,255,255,0.1);
                backdrop-filter: blur(10px);
                margin: 10px;
                border-radius: 10px;
            }}
            .legend {{
                display: flex;
                justify-content: center;
                gap: 20px;
                margin: 10px;
                flex-wrap: wrap;
            }}
            .legend-item {{
                display: flex;
                align-items: center;
                gap: 8px;
                background: rgba(255,255,255,0.1);
                padding: 5px 10px;
                border-radius: 15px;
                font-size: 12px;
            }}
            .legend-color {{
                width: 12px;
                height: 12px;
                border-radius: 50%;
            }}
        </style>
    </head>
    <body>
        <div class="info">
            <h2 style="color: #00d4aa; margin-bottom: 10px;">Transaction Network Graph</h2>
            <p>Nodes: {len(nodes)} | Transactions: {len(edges)}</p>
        </div>
        
        <div class="legend">
            <div class="legend-item">
                <div class="legend-color" style="background: #FF4444;"></div>
                <span>High Risk (>₹1L)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #FF8800;"></div>
                <span>Medium-High (>₹50K)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #FFAA00;"></div>
                <span>Medium Risk</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #87CEEB;"></div>
                <span>Low-Medium</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #90EE90;"></div>
                <span>Low Risk</span>
            </div>
        </div>
        
        <div id="network"></div>
        
        <script>
            // Create nodes array
            var nodes = new vis.DataSet([
    """
    
    # Add nodes
    for i, (node_id, node_data) in enumerate(nodes.items()):
        html_content += f"""
                {{
                    id: "{node_id}",
                    label: "{node_data['label']}",
                    color: "{node_data['color']}",
                    font: {{ color: "white", size: 14 }},
                    borderWidth: 2,
                    size: 25
                }},"""
    
    html_content += """
            ]);
            
            // Create edges array
            var edges = new vis.DataSet([
    """
    
    # Add edges
    for edge in edges:
        html_content += f"""
                {{
                    from: "{edge['from']}",
                    to: "{edge['to']}",
                    label: "{edge['label']}",
                    color: "{edge['color']}",
                    width: {edge['width']},
                    arrows: "to",
                    font: {{ color: "white", size: 12 }}
                }},"""
    
    html_content += f"""
            ]);
            
            // Create network
            var container = document.getElementById('network');
            var data = {{ nodes: nodes, edges: edges }};
            var options = {{
                physics: {{
                    enabled: true,
                    barnesHut: {{
                        gravitationalConstant: -2000,
                        centralGravity: 0.3,
                        springLength: 100,
                        springConstant: 0.04,
                        damping: 0.09
                    }},
                    stabilization: {{ iterations: 200 }}
                }},
                nodes: {{
                    shape: 'dot',
                    scaling: {{
                        min: 20,
                        max: 50
                    }}
                }},
                edges: {{
                    smooth: {{ type: 'continuous' }}
                }},
                interaction: {{
                    hover: true,
                    tooltipDelay: 200
                }}
            }};
            
            var network = new vis.Network(container, data, options);
            
            // Add click event
            network.on("click", function(params) {{
                if (params.nodes.length > 0) {{
                    var nodeId = params.nodes[0];
                    alert('Account: ' + nodeId + '\\nClick and drag to move nodes');
                }}
            }});
        </script>
    </body>
    </html>
    """
    
    return html_content

# Routes
@app.route("/", methods=["GET"])
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        if username in USERS and USERS[username] == password:
            session["user"] = username
            session.permanent = True
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials!", "error")
    
    return render_template("login.html")

@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file selected!", "error")
            return redirect(url_for("upload"))
        
        file = request.files["file"]
        if file.filename == "":
            flash("No file selected!", "error")
            return redirect(url_for("upload"))
        
        if file and file.filename.endswith('.json'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                
                if not isinstance(data, list):
                    data = [data]
                
                session["transactions"] = data
                session["filename"] = filename
                flash(f"File uploaded successfully! {len(data)} transactions loaded.", "success")
                return redirect(url_for("analysis"))
                
            except Exception as e:
                flash(f"Error processing file: {str(e)}", "error")
                return redirect(url_for("upload"))
        else:
            flash("Please upload a JSON file!", "error")
    
    return render_template("upload.html")

@app.route("/analysis", methods=["GET"])
def analysis():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if "transactions" not in session:
        flash("Please upload transaction data first!", "warning")
        return redirect(url_for("upload"))
    
    transactions = session["transactions"]
    filename = session.get("filename", "data.json")
    
    return render_template("analysis.html", 
                         transactions=transactions, 
                         filename=filename,
                         biomarkers=FRAUD_BIOMARKERS)

@app.route("/graph", methods=["GET"])
def graph_view():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if "transactions" not in session:
        flash("Please upload transaction data first!", "warning")
        return redirect(url_for("upload"))
    
    try:
        transactions = session["transactions"]
        print(f"Creating graph for {len(transactions)} transactions")
        
        # Create graph HTML
        graph_html = create_graph_html(transactions)
        
        # Save to file
        with open("static/graph.html", "w", encoding='utf-8') as f:
            f.write(graph_html)
        
        print("Graph HTML created successfully")
        return render_template("graph.html", graph_available=True)
        
    except Exception as e:
        print(f"Graph error: {str(e)}")
        flash(f"Error generating graph: {str(e)}", "error")
        return render_template("graph.html", graph_available=False)

@app.route("/risk_analysis", methods=["GET"])
def risk_analysis():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if "transactions" not in session:
        flash("Please upload transaction data first!", "warning")
        return redirect(url_for("upload"))
    
    try:
        transactions = session["transactions"]
        patterns = detect_fraud_patterns(transactions)
        risk_scores = calculate_risk_scores(patterns, transactions)
        
        return render_template("risk_analysis.html", 
                             patterns=patterns,
                             risk_scores=risk_scores,
                             biomarkers=FRAUD_BIOMARKERS)
    except Exception as e:
        flash(f"Error in risk analysis: {str(e)}", "error")
        return redirect(url_for("home"))

@app.route("/view_graph", methods=["GET"])
def view_graph():
    """Serve the generated graph"""
    try:
        with open("static/graph.html", "r", encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"<p style='color: white; text-align: center; padding: 50px;'>Graph not available: {str(e)}</p>"

@app.route("/debug")
def debug():
    debug_info = {
        "user_in_session": "user" in session,
        "transactions_in_session": "transactions" in session,
        "session_keys": list(session.keys()),
    }
    
    if "transactions" in session:
        transactions = session["transactions"]
        debug_info.update({
            "num_transactions": len(transactions),
            "first_transaction": transactions[0] if transactions else None,
        })
    
    return f"<pre style='color: white; background: #1a1a1a; padding: 20px;'>{json.dumps(debug_info, indent=2)}</pre>"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)