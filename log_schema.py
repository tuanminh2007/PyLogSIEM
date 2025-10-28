import re
from datetime import datetime

# --- Constants for Event Types ---
# We define constants to avoid using "magic strings" in our code
UNKNOWN = "UNKNOWN"
FAILED_LOGIN = "FAILED_LOGIN"
SUCCESSFUL_LOGIN = "SUCCESSFUL_LOGIN"
LOGOFF = "LOGOFF"
PROC_CREATED = "PROC_CREATED"
USER_CREATED = "USER_CREATED"
USER_ADDED_TO_GROUP = "USER_ADDED_TO_GROUP"
USER_REMOVED_FROM_GROUP = "USER_REMOVED_FROM_GROUP"
POLICY_CHANGE = "POLICY_CHANGE"

# --- Event ID to Type Mapping ---
# This maps Windows Event IDs to our internal, human-readable types
EVENT_ID_MAP = {
    # Logon/Logoff
    4624: SUCCESSFUL_LOGIN,
    4625: FAILED_LOGIN,
    4634: LOGOFF,
    
    # Process Tracking
    4688: PROC_CREATED,
    
    # Account Management (Users)
    4720: USER_CREATED,
    
    # Account Management (Groups)
    4728: USER_ADDED_TO_GROUP,    # Member added to Global group (e.g., "Domain Admins")
    4732: USER_ADDED_TO_GROUP,    # Member added to Local group (e.g., "Administrators")
    4729: USER_REMOVED_FROM_GROUP, # Member removed from Global group
    4733: USER_REMOVED_FROM_GROUP, # Member removed from Local group
    
    # Policy
    4719: POLICY_CHANGE, # System audit policy was changed
}

# --- The Standardized Schema ---
# This is the "blueprint" for our database.
# Every log will be normalized to fit this structure.
NORMALIZED_SCHEMA = {
    "timestamp": None,      # (Special field, handled separately)
    "raw_log": None,        # (Special field, handled separately)
    "event_id": None,
    "event_type": UNKNOWN,
    "host_ip": None,        # The IP of the machine *generating* the log
    "source_ip": "N/A",     # The IP an action *came from* (if applicable)
    "username": "N/A",      # The user *performing* an action
    "target_username": "N/A", # The user *affected by* an action
    "severity": "N/A",
    "logon_type": "N/A",    # e.g., "2" (Interactive), "3" (Network), "10" (RDP)
    "process_id": "N/A",
    "process_name": "N/A",
    "failure_reason": "N/A" # For failed logins
}

def create_empty_event():
    """Returns a fresh copy of the normalized schema dictionary."""
    return NORMALIZED_SCHEMA.copy()

def normalize_from_nxlog_json(log_data: dict, source_host_ip: str) -> dict:
    """
    Parses a raw log dictionary (from NXLog's JSON) and maps it
    to our standardized NORMALIZED_SCHEMA.
    
    :param log_data: The raw dictionary from json.loads()
    :param source_host_ip: The IP of the machine that sent us this log
    :return: A normalized log dictionary
    """
    
    norm_event = create_empty_event()
    
    # --- Universal Fields ---
    norm_event["raw_log"] = str(log_data) # Store the original JSON as text
    norm_event["host_ip"] = source_host_ip
    
    # Parse the NXLog timestamp (e.g., "2025-10-27T15:01:02.123456Z")
    try:
        # Use fromisoformat for modern, fast parsing.
        # We strip the 'Z' (UTC marker) as fromisoformat can be picky.
        norm_event["timestamp"] = datetime.fromisoformat(log_data.get("EventTime", "").rstrip("Z"))
    except Exception:
        norm_event["timestamp"] = datetime.now() # Fallback

    norm_event["severity"] = log_data.get("SeverityValue", "N/A")
    
    # --- Event-Specific Fields ---
    event_id = log_data.get("EventID")
    if event_id is not None:
        norm_event["event_id"] = str(event_id)
        norm_event["event_type"] = EVENT_ID_MAP.get(event_id, UNKNOWN)
    
    # --- Field Extraction based on Event Type ---
    
    # SUCCESSFUL_LOGIN (4624) or FAILED_LOGIN (4625)
    if norm_event["event_type"] in [SUCCESSFUL_LOGIN, FAILED_LOGIN]:
        norm_event["username"] = log_data.get("AccountName", "N/A")
        norm_event["source_ip"] = log_data.get("IpAddress", "N/A")
        norm_event["logon_type"] = str(log_data.get("LogonType", "N/A"))
        if norm_event["event_type"] == FAILED_LOGIN:
            # Clean up the hex status code
            status = log_data.get("Status", "N/A")
            norm_event["failure_reason"] = f"Code: {status}"

    # PROC_CREATED (4688)
    elif norm_event["event_type"] == PROC_CREATED:
        norm_event["username"] = log_data.get("AccountName", "N/A")
        norm_event["process_name"] = log_data.get("NewProcessName", "N/A")
        norm_event["process_id"] = str(log_data.get("NewProcessID", "N/A"))

    # USER_CREATED (4720)
    elif norm_event["event_type"] == USER_CREATED:
        # User *doing* the creating
        norm_event["username"] = log_data.get("AccountName", "N/A")
        # User *being* created
        norm_event["target_username"] = log_data.get("TargetAccountName", "N/A")

    # USER_ADDED_TO_GROUP (4728, 4732)
    elif norm_event["event_type"] == USER_ADDED_TO_GROUP:
        # User *doing* the adding
        norm_event["username"] = log_data.get("AccountName", "N/A")
        # User *being* added
        norm_event["target_username"] = log_data.get("MemberName", "N/A")
        
    # USER_REMOVED_FROM_GROUP (4729, 4733)
    elif norm_event["event_type"] == USER_REMOVED_FROM_GROUP:
        norm_event["username"] = log_data.get("AccountName", "N/A")
        norm_event["target_username"] = log_data.get("MemberName", "N/A")

    # --- Data Cleanup ---
    # Replace empty/placeholder values with a standard 'N/A'
    for key, value in norm_event.items():
        if value is None or str(value).strip() in ["-", ""]:
            norm_event[key] = "N/A"
            
    return norm_event

if __name__ == "__main__":
    # This block is for testing the normalization function.
    print("Testing normalization function...")
    
    # Simulate a raw JSON log from NXLog for a failed login
    test_log = {
        "EventTime": "2025-10-27T15:01:02.123456Z",
        "Hostname": "CLIENT-01",
        "EventID": 4625,
        "SeverityValue": 2,
        "AccountName": "Attacker01",
        "IpAddress": "192.168.1.51",
        "LogonType": 10,
        "Status": "0xc000006d"
    }
    
    normalized = normalize_from_nxlog_json(test_log, "192.168.1.51")
    
    print("\n--- Raw Log ---")
    print(test_log)
    print("\n--- Normalized Output ---")
    import json
    print(json.dumps(normalized, indent=4, default=str))

    # Test a process creation
    test_log_proc = {
        "EventTime": "2025-10-27T15:02:00.000000Z",
        "Hostname": "WIN-DC-01",
        "EventID": 4688,
        "SeverityValue": 0,
        "AccountName": "TestUser01",
        "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
        "NewProcessID": "0x1a2b"
    }
    
    normalized_proc = normalize_from_nxlog_json(test_log_proc, "192.168.1.50")
    print("\n--- Normalized Process ---")
    print(json.dumps(normalized_proc, indent=4, default=str))

