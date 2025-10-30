import json
import os
from datetime import datetime, timedelta

# --- M2.3: Rule File Loader ---
RULE_FILE = 'rules.json'

def load_rules():
    """
    Loads detection rules from the JSON file.
    """
    if not os.path.exists(RULE_FILE):
        print(f"[RULE ENGINE] FATAL: '{RULE_FILE}' not found!")
        return []
    
    try:
        with open(RULE_FILE, 'r') as f:
            rules = json.load(f)
        
        # Filter out any disabled rules
        enabled_rules = [r for r in rules if r.get('enabled', True)]
        print(f"[RULE ENGINE] Successfully loaded {len(enabled_rules)} enabled rules.")
        return enabled_rules
    except json.JSONDecodeError as e:
        print(f"[RULE ENGINE] FATAL: Could not parse '{RULE_FILE}'. Error: {e}")
        return []
    except Exception as e:
        print(f"[RULE ENGINE] FATAL: An error occurred loading rules: {e}")
        return []

# --- M2.3: Simple "Match" Rule Logic ---
def check_match_rule(log, rule):
    """
    Checks a single log against a single 'match' rule.
    Returns an alert dictionary if it matches, else None.
    """
    match_criteria = rule.get('match', {})
    
    # Check if all criteria in the rule are met by the log
    for key, value in match_criteria.items():
        # Check if the key exists in the log and the value matches
        # We use .lower() for case-insensitive matching
        if str(log.get(key)).lower() != str(value).lower():
            # This criterion doesn't match, so the rule fails
            return None
    
    # All criteria matched! Create an alert.
    alert_desc = rule['description']
    
    # Make the alert description more descriptive
    if log.get('username'):
        alert_desc = alert_desc.replace("A user", f"User '{log['username']}'")
        alert_desc = alert_desc.replace("a user", f"user '{log['username']}'")
    if log.get('source_ip'):
        alert_desc += f" (Source IP: {log['source_ip']})"
        
    alert = {
        "rule_id": rule['rule_id'],
        "rule_name": rule['rule_name'],
        "description": alert_desc,
        "level": rule['level'],
        "level_color": rule['level_color'],
        "log_timestamp": log['timestamp']
    }
    return alert

# --- M2.4: Stateful "Threshold" Rule Logic ---
# This is a stub for now. We will build this in the next step (M2.4).
# We'll need to store recent events in memory to do this.
def check_threshold_rules(log, rules, state):
    """
    Checks a log against all stateful 'threshold' rules.
    This is a complex function we will build out in M2.4.
    
    'state' will be a dictionary holding recent events.
    """
    # Placeholder: In M2.4, this will do time-based analysis
    return [] # No alerts for now

# --- Main Rule Check Function ---
def check_all_rules(log, rules, state):
    """
    Checks a single log against all loaded rules.
    
    Returns a list of any alerts that were triggered.
    """
    triggered_alerts = []
    
    # 1. Check simple "match" rules
    for rule in rules:
        if rule['type'] == 'match':
            alert = check_match_rule(log, rule)
            if alert:
                triggered_alerts.append(alert)
                
    # 2. Check "threshold" rules (for M2.4)
    # This will update the 'state' and check for threshold breaches
    threshold_alerts = check_threshold_rules(log, rules, state)
    triggered_alerts.extend(threshold_alerts)
    
    return triggered_alerts
