# app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import pandas as pd
import numpy as np
import datetime
import hashlib # For master password hashing
import os # For session secret key and master hash file
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Set a secret key for session management. IMPORTANT: Change this in production!
app.secret_key = 'your_super_secret_key_for_this_demo_only' # <--- USE A FIXED STRING FOR DEMO PERSISTENCE

# --- Master Password Hashing (for dashboard authentication) ---
MASTER_HASH_FILE = 'dashboard_master_hash.txt'
DASHBOARD_SALT = b'security_dashboard_salt_123' # Unique salt for dashboard master password

def hash_password(password: str, salt: bytes) -> str:
    """Hashes a password using SHA256."""
    return hashlib.sha256(salt + password.encode()).hexdigest()

def set_dashboard_master_password(password: str):
    """Sets/updates the dashboard master password hash in a file."""
    hashed_pass = hash_password(password, DASHBOARD_SALT)
    with open(MASTER_HASH_FILE, 'w') as f:
        f.write(hashed_pass)
    logger.info("Dashboard master password hash set/updated.")

def verify_dashboard_master_password(password: str) -> bool:
    """Verifies the entered master password against the stored hash."""
    if not os.path.exists(MASTER_HASH_FILE):
        return False # No master password set yet
    with open(MASTER_HASH_FILE, 'r') as f:
        stored_hash = f.read().strip()
    return hash_password(password, DASHBOARD_SALT) == stored_hash

# Check if master password is set on startup. If not, set a default for demo.
if not os.path.exists(MASTER_HASH_FILE):
    logger.warning("No dashboard master password found. Setting default: 'adminpass'")
    set_dashboard_master_password('adminpass') # Default password for first run

# --- Security Event Data Simulation ---
def generate_simulated_events(num_events=100):
    """Generates a list of simulated security events."""
    event_types = ['Login Attempt', 'File Access', 'Network Scan', 'Malware Detected', 'Firewall Block', 'System Alert', 'Unauthorized Access'] # Added Unauthorized Access
    severities = ['Low', 'Medium', 'High', 'Critical']
    ips = [f'192.168.1.{i}' for i in range(1, 20)] + [f'10.0.0.{i}' for i in range(1, 10)] + ['203.0.113.10', '172.16.0.5'] # Mix of internal/external
    users = ['admin', 'guest', 'user1', 'system', 'root']
    
    events = []
    start_time = datetime.datetime.now() - datetime.timedelta(days=7) # Events over last 7 days

    for i in range(num_events):
        event_time = start_time + datetime.timedelta(minutes=np.random.randint(0, 7 * 24 * 60))
        event_type = np.random.choice(event_types, p=[0.35, 0.15, 0.1, 0.1, 0.1, 0.1, 0.1]) # Skew towards login attempts
        severity = np.random.choice(severities, p=[0.4, 0.3, 0.2, 0.1]) # Skew towards lower severity
        source_ip = np.random.choice(ips)
        username = np.random.choice(users)
        description = f"{event_type} from {source_ip} by {username}."

        # Add specific scenarios for higher severity
        if event_type == 'Login Attempt' and severity == 'High':
            description = f"Multiple failed login attempts from {source_ip} for user {username}."
        elif event_type == 'Malware Detected':
            description = f"Malware detected on host {source_ip}. Threat: {np.random.choice(['Trojan', 'Ransomware', 'Phishing'])}."
        elif event_type == 'Network Scan':
            description = f"Suspicious network scan detected from {source_ip} targeting multiple ports."
        elif event_type == 'Unauthorized Access':
             description = f"Unauthorized access attempt to sensitive resource from {source_ip}."

        events.append({
            'id': i + 1,
            'timestamp': event_time, # Store as datetime object
            'type': event_type,
            'severity': severity,
            'source_ip': source_ip,
            'username': username,
            'description': description
        })
    
    # Add a few critical events manually for demonstration
    events.append({
        'id': num_events + 1,
        'timestamp': datetime.datetime.now() - datetime.timedelta(minutes=5),
        'type': 'Malware Detected',
        'severity': 'Critical',
        'source_ip': '192.168.1.50',
        'username': 'system',
        'description': 'Critical ransomware attack detected and blocked on server.'
    })
    events.append({
        'id': num_events + 2,
        'timestamp': datetime.datetime.now() - datetime.timedelta(minutes=10),
        'type': 'Unauthorized Access',
        'severity': 'Critical',
        'source_ip': '203.0.113.10',
        'username': 'root',
        'description': 'Repeated unauthorized access attempts to root account from external IP.'
    })

    return pd.DataFrame(events)

# Generate events once when the app starts
security_events_df = generate_simulated_events(200)
logger.info(f"Generated {len(security_events_df)} simulated security events.")

# --- Routes ---

@app.route('/')
def root_redirect():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        if verify_dashboard_master_password(password):
            session['logged_in'] = True
            logger.info("User logged in successfully.")
            return redirect(url_for('dashboard'))
        else:
            logger.warning("Failed login attempt.")
            return render_template('login.html', error="Incorrect Password")
    
    # If master password is not set, allow setting it
    if not os.path.exists(MASTER_HASH_FILE):
        return render_template('login.html', set_password_mode=True)
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    logger.info("User logged out.")
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session or not session['logged_in']:
        logger.warning("Attempted to access dashboard without login. Redirecting.")
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# API for dashboard data
@app.route('/api/security_data', methods=['GET'])
def get_security_data():
    if 'logged_in' not in session or not session['logged_in']:
        logger.warning("Unauthorized API access attempt to /api/security_data. Returning 401.")
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Convert DataFrame to list of dictionaries for JSON response
        # Apply isoformat() to each datetime object in the Series using .apply()
        events_data_for_json = security_events_df.copy() # Work on a copy
        events_data_for_json['timestamp'] = events_data_for_json['timestamp'].apply(lambda x: x.isoformat()) # <--- FIX IS HERE
        
        events_list_of_dicts = events_data_for_json.to_dict(orient='records')
        
        # --- Aggregate Data for Charts ---
        # Events by Type
        events_by_type = security_events_df['type'].value_counts().to_dict()
        
        # Events by Severity
        severity_order = ['Critical', 'High', 'Medium', 'Low'] # Define order for consistent charting
        events_by_severity = security_events_df['severity'].value_counts().reindex(severity_order, fill_value=0).to_dict()

        # Top 5 Attacking IPs (simplistic: IPs with most 'Network Scan' or 'Login Attempt' events)
        attacking_ips = security_events_df[
            (security_events_df['type'] == 'Network Scan') |
            (security_events_df['type'] == 'Login Attempt') |
            (security_events_df['type'] == 'Unauthorized Access') # Include unauthorized access in attacking IPs
        ]['source_ip'].value_counts().head(5).to_dict()

        # Critical Alerts (recent Critical events)
        critical_alerts_for_json = security_events_df[security_events_df['severity'] == 'Critical'].sort_values(by='timestamp', ascending=False).head(5).copy() # Use copy
        critical_alerts_for_json['timestamp'] = critical_alerts_for_json['timestamp'].apply(lambda x: x.isoformat()) # <--- FIX IS HERE
        critical_alerts_list_of_dicts = critical_alerts_for_json.to_dict(orient='records')

        logger.info(f"API data requested. Total events: {len(events_list_of_dicts)}")
        return jsonify({
            'events': events_list_of_dicts,
            'summary': {
                'total_events': len(security_events_df),
                'critical_count': security_events_df[security_events_df['severity'] == 'Critical'].shape[0],
                'high_count': security_events_df[security_events_df['severity'] == 'High'].shape[0]
            },
            'charts': {
                'events_by_type': events_by_type,
                'events_by_severity': events_by_severity,
                'top_attacking_ips': attacking_ips
            },
            'alerts': critical_alerts_list_of_dicts
        })
    except Exception as e:
        logger.error(f"Error generating security data for API: {e}", exc_info=True) # Log full traceback
        return jsonify({'error': 'Internal server error processing security data.'}), 500

# --- Run the Flask app ---
if __name__ == '__main__':
    app.run(debug=True, port=5000)