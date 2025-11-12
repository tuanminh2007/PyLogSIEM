import re
from datetime import datetime

UNKNOWN = "UNKNOWN"
FAILED_LOGIN = "FAILED_LOGIN"
EVENT_ID_MAP = {
    4624: "SUCCESSFUL_LOGIN",
    4625: "FAILED_LOGIN",
    4634: "LOGOFF",
    4688: "PROC_CREATED",
    4720: "USER_CREATED",
    4728: "USER_ADDED_TO_GROUP",
    4732: "USER_ADDED_TO_GROUP",
    4729: "USER_REMOVED_FROM_GROUP",
    4733: "USER_REMOVED_FROM_GROUP",
    4719: "POLICY_CHANGE",
    4738: "USER_ACCOUNT_CHANGED"
}
NORMALIZED_SCHEMA = {
    "timestamp": None,
    "raw_log": None,
    "event_id": None,
    "event_description": "N/A",
    "host_ip": None,        
    "source_ip": "N/A",     
    "username": "N/A",      
    "target_username": "N/A", 
    "computer_name": "N/A", 
    "severity": "N/A",
    "logon_type": "N/A",
    "process_id": "N/A",
    "process_name": "N/A",
    "failure_reason": "N/A"
}
DYNAMIC_FIELD_MAP = {
    "username":          ["SubjectUserName", "AccountName", "User"],
    "target_username":   ["TargetUserName", "MemberName", "TargetUser"],
    "process_name":      ["NewProcessName", "ProcessName"],
    "process_id":        ["NewProcessID", "ProcessId"],
    "source_ip":         ["IpAddress"],
    "logon_type":        ["LogonType"],
    "failure_reason":    ["Status", "SubStatus"]
}

def create_empty_event():
    return NORMALIZED_SCHEMA.copy()

def normalize_from_nxlog_json(log_data: dict, source_host_ip: str) -> dict:
    
    norm_event = create_empty_event()
    
    # --- 1. Universal Fields ---
    norm_event["raw_log"] = str(log_data)
    norm_event["host_ip"] = source_host_ip
    norm_event["timestamp"] = log_data.get("EventTime")
    if not norm_event["timestamp"]:
        norm_event["timestamp"] = datetime.now().isoformat()
    norm_event["severity"] = log_data.get("SeverityValue", "N/A")

    norm_event["computer_name"] = log_data.get("Hostname", "N/A") 
    
    event_id = log_data.get("EventID")
    if event_id is not None:
        norm_event["event_id"] = str(event_id)
    norm_event["event_description"] = log_data.get("Message", "No description provided.")

    # --- 2. Field Extraction ---
    if event_id == 4625 or event_id == 4624:
        norm_event["username"] = log_data.get("TargetUserName", "N/A")
        norm_event["computer_name"] = log_data.get("SubjectUserName", "N/A") 
        
        ip_addr = log_data.get("IpAddress", "N/A")
        if ip_addr in ["-", "127.0.0.1", "::1", "N/A"]:
            norm_event["source_ip"] = source_host_ip
        else:
            norm_event["source_ip"] = ip_addr
        norm_event["logon_type"] = str(log_data.get("LogonType", "N/A"))
        if event_id == 4625:
            norm_event["failure_reason"] = log_data.get("Status", "N/A")
    
    else:
        # Dynamic mapping for all other events
        for std_field, raw_keys in DYNAMIC_FIELD_MAP.items():
            for raw_key in raw_keys:
                if raw_key in log_data:
                    norm_event[std_field] = log_data[raw_key]
                    break 
        
        if norm_event["source_ip"] == "N/A":
            norm_event["source_ip"] = source_host_ip

    # --- 3. Data Cleanup & Normalization ---
    
    if norm_event["computer_name"] and norm_event["computer_name"] != 'N/A':
        name = norm_event["computer_name"].upper()
        # Remove the $ sign (from SAM account names)
        name = name.replace("$", "")
        # Remove the domain (from FQDN)
        name = name.split(".")[0]
        norm_event["computer_name"] = name

    for key, value in norm_event.items():
        if value is None or str(value).strip() in ["-", ""]:
            norm_event[key] = NORMALIZED_SCHEMA.get(key, "N/A") 
            
    return norm_event