import json
from datetime import datetime, timedelta

RULES_FILE = 'rules.json'

def load_rules():
    """
    Loads the detection rules from the JSON file.
    """
    try:
        with open(RULES_FILE, 'r') as f:
            rules = json.load(f)
        print(f"[Rule Engine] Successfully loaded {len(rules)} rules.")
        return rules
    except FileNotFoundError:
        print(f"[Rule Engine] FATAL: {RULES_FILE} not found.")
        return []
    except json.JSONDecodeError:
        print(f"[Rule Engine] FATAL: Could not decode {RULES_FILE}. Check for syntax errors.")
        return []

def check_match_rule(log, rule, verbose=False):
    """
    Checks a single log against a simple 'match' rule.
    This now operates on the RAW log dictionary.
    Returns the rule if it matches, otherwise None.
    """
    match_criteria = rule.get('match', {})
    
    for field, expected_value in match_criteria.items():
        # Check if the field even exists in the raw log
        if field not in log:
            if verbose:
                print(f"[Rule Check] FAILED on '{field}': field not in raw log.")
            return None

        log_value = log.get(field)
        
        # --- NEW Wildcard Logic ---
        # If expected_value is a string and starts with '*',
        # perform an 'ends_with' check.
        if isinstance(expected_value, str) and expected_value.startswith('*'):
            check_val = expected_value[1:] # e.g., "powershell.exe"
            if not str(log_value).endswith(check_val):
                if verbose:
                    print(f"[Rule Check] FAILED on '{field}': log value '{log_value}' did not end with '{check_val}'")
                return None # Failed 'ends_with' check
        
        # --- Original Exact Match Logic ---
        # (for all other cases, like EventID)
        else:
            if str(log_value) != str(expected_value):
                if verbose:
                    print(f"[Rule Check] FAILED on '{field}': log value '{log_value}' != rule value '{expected_value}'")
                return None # Field doesn't match
            
    # If we get through the whole loop, all fields matched.
    if verbose:
         print(f"[Rule Check] SUCCESS on rule '{rule.get('rule_id')}'")
    return rule

def check_threshold_rule(log, rule, state_tracker, verbose=False):
    """
    Checks a single log against a 'threshold' (stateful) rule.
    This now operates on the RAW log dictionary.
    
    :return: The rule if triggered, otherwise None
    """
    match_criteria = rule.get('match', {})
    
    # --- 1. Check if the log matches the rule's criteria ---
    if not check_match_rule(log, {'match': match_criteria}, verbose):
        # This log isn't relevant to this threshold rule
        return None

    # --- 2. If it matches, update the state ---
    group_by_field = rule.get('group_by') # e.g., "IpAddress"
    group_by_value = log.get(group_by_field) # e.g., "192.168.1.51"
    
    if not group_by_value:
        if verbose:
            print(f"[Rule Check] SKIPPED threshold rule '{rule.get('rule_id')}': 'group_by' field '{group_by_field}' not in log.")
        return None

    rule_id = rule.get('rule_id')
    timeframe_sec = rule.get('timeframe_seconds')
    threshold_count = rule.get('threshold')
    
    state_key = (rule_id, group_by_value)
    
    state = state_tracker.get(state_key, {
        "timestamps": [],
        "alerted": False
    })
    
    # --- 3. Get timestamp directly from raw log ---
    try:
        # Parse the NXLog timestamp (e.g., "2025-10-27T15:01:02.123456Z")
        now = datetime.fromisoformat(log.get("EventTime", "").rstrip("Z"))
    except Exception:
        now = datetime.now() # Fallback
        
    timeframe = timedelta(seconds=timeframe_sec)
    
    # --- 4. Prune old timestamps ---
    state["timestamps"] = [t for t in state["timestamps"] if (now - t) <= timeframe]
    
    # --- 5. Add new timestamp ---
    state["timestamps"].append(now)
    
    alert = None
    
    # --- 6. Check if threshold is breached ---
    if len(state["timestamps"]) >= threshold_count:
        if not state["alerted"]:
            if verbose:
                print(f"[Rule Check] THRESHOLD ALERT for '{rule_id}' on '{group_by_value}'")
            alert = rule
            state["alerted"] = True 
    else:
        state["alerted"] = False

    # --- 7. Save the updated state ---
    state_tracker[state_key] = state
    
    return alert


def check_all_rules(log, rules, state_tracker, verbose=False):
    """
    Checks a single log (RAW dict) against all loaded rules.
    """
    triggered_alerts = []
    
    if verbose:
        print(f"--- [Rule Check] --- Checking Event ID {log.get('EventID')} from {log.get('IpAddress', log.get('Hostname'))} ---")

    for rule in rules:
        alert = None
        rule_type = rule.get('type')
        
        if rule_type == 'match':
            alert = check_match_rule(log, rule, verbose)
        
        elif rule_type == 'threshold':
            alert = check_threshold_rule(log, rule, state_tracker, verbose)
        
        if alert:
            triggered_alerts.append(alert)
            
    return triggered_alerts