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
    Returns the rule if it matches, otherwise None.
    """
    match_criteria = rule.get('match', {})
    
    for field, expected_value in match_criteria.items():
        # Check if the field even exists in the log
        if field not in log:
            if verbose:
                print(f"[Rule Check] FAILED on '{field}': field not in log.")
            return None

        log_value = log.get(field)
        
        # Compare log value to rule value (as strings, for flexibility)
        if str(log_value) != str(expected_value):
            if verbose:
                print(f"[Rule Check] FAILED on '{field}': log value '{log_value}' != rule value '{expected_value}'")
            return None # Field doesn't match, so the rule fails
            
    # If we get through the whole loop, all fields matched.
    if verbose:
         print(f"[Rule Check] SUCCESS on rule '{rule.get('rule_id')}'")
    return rule

def check_threshold_rule(log, rule, state_tracker, verbose=False):
    """
    Checks a single log against a 'threshold' (stateful) rule.
    
    :param log: The normalized log data (dict)
    :param rule: The rule definition (dict)
    :param state_tracker: A dict to store state data
    :param verbose: Print debug messages
    :return: The rule if triggered, otherwise None
    """
    match_criteria = rule.get('match', {})
    
    # --- 1. Check if the log matches the rule's criteria ---
    # We re-use check_match_rule's logic for the 'match' block
    if not check_match_rule(log, {'match': match_criteria}, verbose):
        # This log isn't relevant to this threshold rule
        return None

    # --- 2. If it matches, update the state ---
    group_by_field = rule.get('group_by') # e.g., "source_ip"
    group_by_value = log.get(group_by_field) # e.g., "192.168.1.51"
    
    if not group_by_value:
        if verbose:
            print(f"[Rule Check] SKIPPED threshold rule '{rule.get('rule_id')}': 'group_by' field '{group_by_field}' not in log.")
        return None

    rule_id = rule.get('rule_id')
    timeframe_sec = rule.get('timeframe_seconds')
    threshold_count = rule.get('threshold')
    
    # This is the unique key for this state
    # e.g., ("SIEM-004", "192.168.1.51")
    state_key = (rule_id, group_by_value)
    
    # Get the current state for this key, or create a new one
    # State stores event timestamps and if we've already alerted
    state = state_tracker.get(state_key, {
        "timestamps": [],
        "alerted": False
    })
    
    # Get the timestamp from the log (it's a datetime object)
    now = log.get('timestamp') 
    timeframe = timedelta(seconds=timeframe_sec)
    
    # --- 3. Prune old timestamps ---
    # Keep only timestamps that are within the rule's timeframe
    state["timestamps"] = [t for t in state["timestamps"] if (now - t) <= timeframe]
    
    # --- 4. Add new timestamp ---
    state["timestamps"].append(now)
    
    alert = None
    
    # --- 5. Check if threshold is breached ---
    if len(state["timestamps"]) >= threshold_count:
        if not state["alerted"]:
            # Threshold met, and we haven't alerted yet!
            if verbose:
                print(f"[Rule Check] THRESHOLD ALERT for '{rule_id}' on '{group_by_value}'")
            alert = rule
            state["alerted"] = True # Set flag to prevent alert spam
    else:
        # Count is below threshold, so reset the alert flag
        state["alerted"] = False

    # --- 6. Save the updated state ---
    state_tracker[state_key] = state
    
    return alert


def check_all_rules(log, rules, state_tracker, verbose=False):
    """
    Checks a single log against all loaded rules.
    
    :param log: The normalized log data (dict)
    :param rules: The list of all rules
    :param state_tracker: The dict for managing state
    :param verbose: Print debug messages
    :return: A list of all alerts that were triggered.
    """
    triggered_alerts = []
    
    if verbose:
        print(f"--- [Rule Check] --- Checking Event ID {log.get('event_id')} from {log.get('source_ip')} ---")

    for rule in rules:
        alert = None
        rule_type = rule.get('type')
        
        if rule_type == 'match':
            alert = check_match_rule(log, rule, verbose)
        
        elif rule_type == 'threshold':
            # Pass the state_tracker to the threshold checker
            alert = check_threshold_rule(log, rule, state_tracker, verbose)
        
        if alert:
            triggered_alerts.append(alert)
            
    return triggered_alerts