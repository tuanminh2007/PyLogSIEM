import json
import time

# --- Configuration ---
RULES_FILE = 'rules.json'
# --- End Configuration ---

class RuleEngine:
    """
    The RuleEngine is a stateful class that loads detection rules
    and checks logs against them.
    
    It maintains a "memory" (self.threshold_tracker) to track
    stateful rules (like brute-force attacks) over time.
    """
    
    def __init__(self, rules_file=RULES_FILE):
        """
        Initializes the engine by loading rules and creating the
        in-memory tracker for threshold rules.
        """
        self.rules = self.load_rules(rules_file)
        # This is the "memory" for our stateful rules.
        # It will store timestamps for specific keys.
        # Example: {'192.168.1.51': [timestamp1, timestamp2, ...]}
        self.threshold_tracker = {}

    def load_rules(self, rules_file):
        """
        Loads detection rules from the specified JSON file.
        """
        try:
            with open(rules_file, 'r') as f:
                rules = json.load(f)
                print(f"[Rule Engine] Successfully loaded {len(rules)} rules from {rules_file}")
                return rules
        except FileNotFoundError:
            print(f"[Rule Engine] ERROR: Rules file not found at {rules_file}. No rules will be loaded.")
            return []
        except json.JSONDecodeError:
            print(f"[Rule Engine] ERROR: Failed to decode {rules_file}. Check for JSON syntax errors.")
            return []
        except Exception as e:
            print(f"[Rule Engine] ERROR: An unexpected error occurred loading rules: {e}")
            return []

    def check_all_rules(self, normalized_log, verbose=False):
        """
        Checks a single log against all loaded rules (both match and threshold).
        Returns a list of any alerts that were triggered.
        """
        alerts = []
        for rule in self.rules:
            alert = None
            if rule.get('enabled', True) == False:
                continue # Skip disabled rules

            if rule['type'] == 'match':
                alert = self.check_match_rule(normalized_log, rule, verbose)
            
            elif rule['type'] == 'threshold':
                alert = self.check_threshold_rule(normalized_log, rule, verbose)

            if alert:
                alerts.append(alert)
        
        return alerts

    def check_match_rule(self, normalized_log, rule, verbose=False):
        """
        Checks a log against a simple "match" rule.
        All conditions in the rule must be met for it to trigger.
        """
        for field, rule_value in rule['conditions'].items():
            log_value = normalized_log.get(field)

            # --- Flexible Match Logic ---
            # This is the fix for Problem 1 (powershell.exe)
            # If the field is 'process_name', we check if the rule value
            # is *in* the log value (e.g., 'powershell.exe' in '...powershell.exe')
            if field == 'process_name' and log_value is not None:
                if rule_value.lower() not in log_value.lower():
                    if verbose:
                        print(f"[Rule Engine] Rule check FAILED on '{field}': log value '{log_value}' does not contain rule value '{rule_value}'")
                    return None # Rule does not match
            
            # --- Standard Match Logic ---
            # For all other fields, we do a simple exact match
            elif log_value != rule_value:
                if verbose:
                    print(f"[Rule Engine] Rule check FAILED on '{field}': log value '{log_value}' != rule value '{rule_value}'")
                return None # Rule does not match
            
        # If we get here, all conditions matched
        return rule # Return the rule as the "alert"

    def check_threshold_rule(self, normalized_log, rule, verbose=False):
        """
        Checks a log against a "threshold" (stateful) rule.
        This is the logic for M2.4.
        """
        # 1. See if this log matches the rule's event criteria
        log_matches_criteria = True
        for field, rule_value in rule['event_criteria'].items():
            if normalized_log.get(field) != rule_value:
                log_matches_criteria = False
                break
        
        if not log_matches_criteria:
            return None # This log isn't part of this threshold rule

        # 2. Get the key we are grouping by (e.g., 'source_ip')
        group_by_field = rule['group_by']
        key = normalized_log.get(group_by_field)
        
        if not key or key == 'N/A':
            return None # Can't track a threshold for a "N/A" key

        # 3. Add this event's timestamp to our "memory"
        now = time.time()
        if key not in self.threshold_tracker:
            self.threshold_tracker[key] = []
        
        self.threshold_tracker[key].append(now)
        
        # 4. Clean out old timestamps
        timeframe_seconds = rule['timeframe_seconds']
        self.threshold_tracker[key] = [
            ts for ts in self.threshold_tracker[key] if now - ts <= timeframe_seconds
        ]
        
        if verbose:
            print(f"[Rule Engine] Threshold check: key '{key}' has {len(self.threshold_tracker[key])} events in last {timeframe_seconds}s")

        # 5. Check if the threshold has been breached
        if len(self.threshold_tracker[key]) > rule['threshold']:
            if verbose:
                print(f"[Rule Engine] !!! THRESHOLD BREACHED for rule {rule['rule_id']} by key {key}")
            
            # Clear the tracker for this key to prevent alert spam
            self.threshold_tracker[key] = [] 
            
            # Return the rule as the "alert"
            return rule 
            
        return None

