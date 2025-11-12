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

def save_rules(rules_list):
    """
    Saves the provided list of rules to the JSON file.
    """
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(rules_list, f, indent=2)
        print(f"[Rule Engine] Successfully saved {len(rules_list)} rules to {RULES_FILE}.")
    except IOError as e:
        print(f"[Rule Engine] FATAL: Could not write to {RULES_FILE}: {e}")
    except TypeError as e:
        print(f"[Rule Engine] FATAL: Could not serialize rules list: {e}")

def check_match_rule(log, rule, verbose=False):
    match_criteria = rule.get('match', {})
    
    for field, expected_value in match_criteria.items():
        if field not in log:
            if verbose:
                print(f"[Rule Check] FAILED on '{field}': field not in raw log.")
            return None

        log_value = log.get(field)
        
        if isinstance(expected_value, str) and expected_value.startswith('*'):
            check_val = expected_value[1:] # e.g., "powershell.exe"
            if not str(log_value).endswith(check_val):
                if verbose:
                    print(f"[Rule Check] FAILED on '{field}': log value '{log_value}' did not end with '{check_val}'")
                return None 
        else:
            if str(log_value) != str(expected_value):
                if verbose:
                    print(f"[Rule Check] FAILED on '{field}': log value '{log_value}' != rule value '{expected_value}'")
                return None
            
    if verbose:
         print(f"[Rule Check] SUCCESS on rule '{rule.get('rule_id')}'")
    return rule

def check_threshold_rule(log, rule, state_tracker, verbose=False):
    match_criteria = rule.get('match', {})
    
    if not check_match_rule(log, {'match': match_criteria}, verbose):
        return None

    group_by_field = rule.get('group_by')
    group_by_value = log.get(group_by_field)
    
    if not group_by_value:
        if verbose:
            print(f"[Rule Check] SKIPPED threshold rule '{rule.get('rule_id')}': 'group_by' field '{group_by_field}' not in log.")
        return None

    rule_id = rule.get('rule_id')
    timeframe_sec = rule.get('timeframe_seconds')
    threshold_count = rule.get('threshold')
    
    state_key = (rule_id, group_by_value)
    
    state = state_tracker.get(state_key, {
        "logs": [], 
        "alerted": False
    })
    
    try:
        now = datetime.fromisoformat(log.get("EventTime", "").rstrip("Z"))
    except Exception:
        now = datetime.now() 
        
    timeframe = timedelta(seconds=timeframe_sec)
    
    state["logs"] = [
        l for l in state["logs"] 
        if (now - datetime.fromisoformat(l.get("EventTime", "").rstrip("Z"))) <= timeframe
    ]
    
    state["logs"].append(log)
    
    alert = None
    
    if len(state["logs"]) >= threshold_count:
        if not state["alerted"]:
            if verbose:
                print(f"[Rule Check] THRESHOLD ALERT for '{rule_id}' on '{group_by_value}'")
            
            alert = rule.copy() 
            alert['triggering_logs'] = state["logs"] 
            
            state["alerted"] = True 
    else:
        state["alerted"] = False
 
    state_tracker[state_key] = state
    
    return alert


def check_all_rules(log, rules, state_tracker, verbose=False):
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