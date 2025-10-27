# log_schema.py
# B1.8: Defines the standardized format (schema) that all raw logs 

NORMALIZED_SCHEMA = {
    # --- Temporal and Identification ---
    "timestamp": None,         # The exact time the event occurred 
    "event_id": None,          # The original unique ID from the log source (e.g., Windows Event ID 4624).
    "host_ip": None,           # IP of the machine that generated the log (e.g., 192.168.1.10).
    "host_name": None,         # Name of the machine that generated the log (e.g., WIN-SERVER-19).
    "log_source": None,        # The type of source (e.g., 'Windows Security', 'Windows Application', 'Apache').
    
    # --- Network and User Context ---
    "source_ip": None,         # The IP address initiating the action (often the client).
    "destination_ip": None,    # The IP address receiving the action (often the server).
    "username": None,          # The user account involved in the event.
    "target_username": None,   # The user/account *being acted upon*
    "event_type": None,        # A simple, standardized type (e.g., 'SUCCESSFUL_LOGIN', 'ACCESS_DENIED').
    
    # --- Detail and Raw Data ---
    "severity": None,          # The severity level (e.g., 'INFORMATIONAL', 'WARNING', 'CRITICAL').
    "message": None,           # A concise summary of the event for display in the GUI.
    "raw_log": None            # The entire original, unparsed log line/entry. Essential for debugging/review.
}

def create_empty_event():
    # Returns a fresh dictionary based on the schema for a new log entry.
    return NORMALIZED_SCHEMA.copy() # Create a copy to avoid accidentially modify the schema

if __name__ == "__main__":
    sample_log = create_empty_event()
    
    sample_log.update({
        "timestamp": "2025-10-21T15:30:00Z",
        "event_id": "4625",
        "host_ip": "192.168.1.50",
        "host_name": "WIN-CLIENT-1",
        "log_source": "Windows Security",
        "source_ip": "192.168.1.100",
        "username": "tminh2007",
        "target_username": "nkhanh2007",
        "event_type": "FAILED_LOGIN",
        "severity": "HIGH",
        "message": "User failed to log in due to bad password.",
        "raw_log": "Audit Failure 4625: A failure occurred during logon (full raw text here)..."
    })
    
    import json
    print("--- Normalized Log Schema Example ---")
    print(json.dumps(sample_log, indent=4))
