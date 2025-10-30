import re
from datetime import datetime

# --- Constants for Event Types ---
# (This section is unchanged)
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
# (This section is unchanged)
EVENT_ID_MAP = {
    4624: SUCCESSFUL_LOGIN,
    4625: FAILED_LOGIN,
    4634: LOGOFF,
    4688: PROC_CREATED,
    4720: USER_CREATED,
    4728: USER_ADDED_TO_GROUP,
    4732: USER_ADDED_TO_GROUP,
    4729: USER_REMOVED_FROM_GROUP,
    4733: USER_REMOVED_FROM_GROUP,
    4719: POLICY_CHANGE,
}

# --- The Standardized Schema ---
# (This section is unchanged)
# This schema is good. It's concise and covers the
# main fields we want to query for M3.2.
NORMALIZED_SCHEMA = {
    "timestamp": None,
    "raw_log": None,
    "event_id": None,
    "event_type": UNKNOWN,
    "host_ip": None,        # The IP of the machine *generating* the log
    "source_ip": "N/A",     # The IP an action *came from* (if applicable)
    "username": "N/A",      # The user *performing* an action
    "target_username": "N/A", # The user *affected by* an action
    "severity": "N/A",
    "logon_type": "N/A",
    "process_id": "N/A",
    "process_name": "N/A",
    "failure_reason": "N/A"
}

def create_empty_event():
    """Returns a fresh copy of the normalized schema dictionary."""
    return NORMALIZED_SCHEMA.copy()

def normalize_from_nxlog_json(log_data: dict, source_host_ip: str) -> dict:
    """
    Parses a raw log dictionary (from NXLog's JSON) and maps it
    to our standardized NORMALIZED_SCHEMA.
    
    --- THIS FUNCTION IS NOW MUCH SMARTER ---
    """
    
    norm_event = create_empty_event()
    
    # --- Universal Fields ---
    norm_event["raw_log"] = str(log_data)
    norm_event["host_ip"] = source_host_ip # IP of the Windows VM
    
    try:
        norm_event["timestamp"] = datetime.fromisoformat(log_data.get("EventTime", "").rstrip("Z"))
    except Exception:
        norm_event["timestamp"] = datetime.now()

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
        
        # Get the source IP from the log
        ip_addr = log_data.get("IpAddress", "N/A")
        
        # If IpAddress is local (-, 127.0.0.1, ::1), use the host IP.
        if ip_addr in ["-", "127.0.0.1", "::1", "N/A"]:
            norm_event["source_ip"] = source_host_ip
        else:
            norm_event["source_ip"] = ip_addr
            
        norm_event["logon_type"] = str(log_data.get("LogonType", "N/A"))
        if norm_event["event_type"] == FAILED_LOGIN:
            status = log_data.get("Status", "N/A")
            norm_event["failure_reason"] = f"Code: {status}"

    # PROC_CREATED (4688)
    elif norm_event["event_type"] == PROC_CREATED:
        norm_event["username"] = log_data.get("AccountName", "N/A")
        norm_event["process_name"] = log_data.get("NewProcessName", "N/A")
        norm_event["process_id"] = str(log_data.get("NewProcessID", "N/A"))
        
        # --- ROOT FIX ---
        # A process is created *on* the host.
        # So, the 'source_ip' is the 'host_ip'.
        norm_event["source_ip"] = source_host_ip

    # USER_CREATED (4720)
    elif norm_event["event_type"] == USER_CREATED:
        norm_event["username"] = log_data.get("AccountName", "N/A")
        norm_event["target_username"] = log_data.get("TargetAccountName", "N/A")
        # This is a local action. Source is the host.
        norm_event["source_ip"] = source_host_ip

    # USER_ADDED_TO_GROUP (4728, 4732)
    elif norm_event["event_type"] == USER_ADDED_TO_GROUP:
        norm_event["username"] = log_data.get("AccountName", "N/A")
        norm_event["target_username"] = log_data.get("MemberName", "N/A")
        # This is a local action. Source is the host.
        norm_event["source_ip"] = source_host_ip
        
    # USER_REMOVED_FROM_GROUP (4729, 4733)
    elif norm_event["event_type"] == USER_REMOVED_FROM_GROUP:
        norm_event["username"] = log_data.get("AccountName", "N/A")
        norm_event["target_username"] = log_data.get("MemberName", "N/A")
        # This is a local action. Source is the host.
        norm_event["source_ip"] = source_host_ip

    # --- Data Cleanup ---
    for key, value in norm_event.items():
        if value is None or str(value).strip() in ["-", ""]:
            # We default to the schema's 'N/A'
            norm_event[key] = NORMALIZED_SCHEMA[key] 
            
    return norm_event

if __name__ == "__main__":
    # ... (Test block is unchanged) ...
    # (You can run `python log_schema.py` to test this new logic)
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
    
    normalized = normalize_from_nxlog_json(test_log, "192.168.1.100") # Host IP
    
    print("\n--- Raw Log (Failed Login) ---")
    print(test_log)
    print("\n--- Normalized Output (Failed Login) ---")
    import json
    print(json.dumps(normalized, indent=4, default=str))
    # Note: source_ip should be "192.168.1.51"

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
    
    normalized_proc = normalize_from_nxlog_json(test_log_proc, "192.168.1.50") # Host IP
    print("\n--- Normalized Process ---")
    print(json.dumps(normalized_proc, indent=4, default=str))
    # Note: source_ip should now be "192.168.1.50" (the host ip)