from flask import Flask, render_template
from flask_socketio import SocketIO

# Initialize the Flask application
app = Flask(__name__)
# Add a secret key, required for Socket.IO
app.config['SECRET_KEY'] = 'your-very-secret-key!' 

# Initialize SocketIO with the Flask app
# async_mode='threading' is crucial to allow our background
# syslog server (which we'll add later) to run
socketio = SocketIO(app, async_mode='threading')

# --- Main Web Page Route ---
@app.route('/')
def index():
    """
    This is the main "index" page.
    Instead of returning a string, we now render our HTML file.
    Flask will look for this file in a folder named 'templates'.
    """
    return render_template('index.html')

# --- WebSocket Event Handlers ---
@socketio.on('connect')
def handle_connect():
    """
    This function runs when a new web client (a browser)
    connects to our WebSocket.
    """
    print('[SIEM GUI] Client connected to WebSocket.')

@socketio.on('disconnect')
def handle_disconnect():
    """
    This function runs when a client disconnects.
    """
    print('[SIEM GUI] Client disconnected from WebSocket.')

# --- Main execution ---
def run_web_server():
    """
    This function will run our web server.
    We put it in a function so we can run it in a thread.
    """
    print("[SIEM GUI] Starting Flask-SocketIO web server on http://0.0.0.0:5000...")
    # Use socketio.run() instead of app.run()
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    """
    This block runs ONLY when you execute `python app.py` directly.
    """
    run_web_server()

