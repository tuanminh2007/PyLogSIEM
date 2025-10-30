import json

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
        log_value = log.get(field)
        
        # This handles cases where the field is 'process_name' but the log
        # might have 'powershell.exe' and the rule is 'powershell.exe'.
        # We also handle integer-to-string comparisons for event_id.
        if str(log_value) != str(expected_value):
            if verbose:
                print(f"[Rule Check] FAILED on '{field}': log value '{log_value}' != rule value '{expected_value}'")
            return None # Field doesn't match, so the rule fails
            
    # If we get through the whole loop, all fields matched.
    return rule

def check_all_rules(log, rules, verbose=False):
    """
    Checks a single log against all loaded rules.
    Returns a list of all alerts that were triggered.
    """
    triggered_alerts = []
    
    if verbose:
        print(f"[Rule Check] Checking Event ID {log.get('event_id')} from {log.get('source_host_ip')}")

    for rule in rules:
        alert = None
        if rule.get('type') == 'match':
            alert = check_match_rule(log, rule, verbose)
        
        # We will add check_threshold_rule here in the next step
        
        if alert:
            triggered_alerts.append(alert)
            
    return triggered_alerts
