from flask import Flask

# Initialize the Flask application
app = Flask(__name__)

# --- Main Web Page Route ---
@app.route('/')
def index():
    """
    This is the main "index" page of our web application.
    When a user visits the root URL, this function runs.
    """
    return "Hello, PyLogSIEM!"

# --- Main execution ---
if __name__ == '__main__':
    """
    This block runs ONLY when you execute `python app.py` directly.
    It starts the Flask development web server.
    """
    print("[SIEM] Starting Flask web application...")
    
    # Run the app on host='0.0.0.0' to make it accessible
    # to other VMs on the network.
    # debug=True makes the server auto-reload when you save changes.
    app.run(host='0.0.0.0', port=5000, debug=True)

