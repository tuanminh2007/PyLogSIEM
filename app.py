import socketserver
import json
import socket
import threading
import sqlite3 
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO

# --- SIEM Imports ---
import database
import log_schema
import rule_engine

# --- Configuration ---
SYSLOG_HOST, SYSLOG_PORT = "0.0.0.0", 5140
WEB_HOST, WEB_PORT = "0.0.0.0", 5000
VERBOSE_RULE_CHECK = True 

ALERT_LEVEL_COLORS = {
    "CRITICAL": "text-red-400",
    "HIGH": "text-orange-400",
    "MEDIUM": "text-yellow-400",
    "LOW": "text-blue-400",
    "DEFAULT": "text-gray-400"
}

# --- Initialize Flask & SocketIO ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key!' 
socketio = SocketIO(app, async_mode='threading')

# --- Shared State ---
RULES_LIST = []
RULES_LOCK = threading.Lock()
KNOWN_MACHINES = {}
MACHINES_LOCK = threading.Lock()
MACHINE_OFFLINE_THRESHOLD = timedelta(minutes=5)

# --- Database connection for web routes ---
def get_db_conn():
    conn = sqlite3.connect(database.SIEM_DB)
    conn.row_factory = sqlite3.Row 
    return conn

# --- Background Task ---
def start_machine_stats_thread():
    print("[Stats Thread] Started.")
    while True:
        socketio.sleep(5) 
        machine_list = []
        now = datetime.now()
        with MACHINES_LOCK:
            for ip, machine in list(KNOWN_MACHINES.items()):
                try:
                    last_seen_dt = datetime.fromisoformat(machine['last_seen'])
                except (ValueError, TypeError):
                    last_seen_dt = now 
                
                if (now - last_seen_dt) > MACHINE_OFFLINE_THRESHOLD:
                    machine['status'] = 'Offline'
                else:
                    machine['status'] = 'Online'
                
                machine_list.append(machine)
        socketio.emit('update_machine_stats', machine_list)

# --- Web Server Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/rules')
def rules_page():
    with RULES_LOCK:
        rules_copy = list(RULES_LIST) 
    return render_template('rules.html', rules=rules_copy)

@app.route('/query', methods=['GET', 'POST'])
def query_page():
    query = ""
    results = []
    headers = []
    error = None
    if request.method == 'POST':
        try:
            query = request.form.get('sql_query', '')
            query_lower = query.strip().lower()
            if not query_lower.startswith('select'):
                raise Exception("Invalid query: Must be a SELECT statement.")
            blocked_keywords = ['drop', 'delete', 'update', 'insert', 'alter', 'create', 'attach']
            if any(keyword in query_lower for keyword in blocked_keywords):
                raise Exception("Invalid query: Modifying keywords (DROP, DELETE, etc.) are not allowed.")
            if 'from logs' not in query_lower:
                 raise Exception("Invalid query: Must be a query on the 'logs' table (e.g., '... FROM logs ...')")
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
            if results:
                headers = results[0].keys()
            conn.close()
        except sqlite3.Error as e:
            error = f"Database Error: {e}"
        except Exception as e:
            error = str(e)
    return render_template('query.html', query=query, results=results, headers=headers, error=error)

@app.route('/statistics')
def statistics_page():
    stats = {
        "avg_logs_per_hour": 0,
        "avg_failed_logons_per_hour": 0,
        "avg_processes_per_hour": 0,
        "top_events": [],
        "top_machines": [],
        "top_failed_users": [],
        "top_attacker_ips": [],
        "top_active_users": []
    }
    error = None

    try:
        conn = get_db_conn()
        cursor = conn.cursor()

        # --- 1. Get data for Averages ---
        cursor.execute("SELECT COUNT(*) as total_logs, MIN(timestamp) as first_log, MAX(timestamp) as last_log FROM logs")
        time_stats = cursor.fetchone()
        
        total_logs = time_stats['total_logs']
        
        if total_logs > 0:
            first_log_dt = datetime.fromisoformat(time_stats['first_log'])
            last_log_dt = datetime.fromisoformat(time_stats['last_log'])
            
            total_hours = (last_log_dt - first_log_dt).total_seconds() / 3600.0
            # Avoid division by zero if logs came in < 1 hour
            if total_hours == 0:
                total_hours = 1 

            # Get specific counts
            cursor.execute("SELECT COUNT(*) FROM logs WHERE event_id = '4625'")
            total_failed_logons = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM logs WHERE event_id = '4688'")
            total_processes = cursor.fetchone()[0]

            # Calculate averages
            stats["avg_logs_per_hour"] = round(total_logs / total_hours, 1)
            stats["avg_failed_logons_per_hour"] = round(total_failed_logons / total_hours, 1)
            stats["avg_processes_per_hour"] = round(total_processes / total_hours, 1)

        # --- 2. Get Top 5 Lists ---
        stats["top_machines"] = cursor.execute(
            "SELECT computer_name, COUNT(*) as count FROM logs GROUP BY computer_name ORDER BY count DESC"
        ).fetchall()
        
        stats["top_events"] = cursor.execute(
            "SELECT event_id, event_description, COUNT(*) as count FROM logs GROUP BY event_id ORDER BY count DESC LIMIT 5"
        ).fetchall()
        
        stats["top_failed_users"] = cursor.execute(
            "SELECT username, COUNT(*) as count FROM logs WHERE event_id = '4625' GROUP BY username ORDER BY count DESC LIMIT 5"
        ).fetchall()
        
        stats["top_attacker_ips"] = cursor.execute(
            "SELECT source_ip, COUNT(*) as count FROM logs WHERE event_id = '4625' GROUP BY source_ip ORDER BY count DESC LIMIT 5"
        ).fetchall()
        
        stats["top_active_users"] = cursor.execute(
            "SELECT username, COUNT(*) as count FROM logs WHERE username != 'N/A' GROUP BY username ORDER BY count DESC LIMIT 5"
        ).fetchall()

        conn.close()

    except Exception as e:
        error = f"An error occurred while generating statistics: {e}"

    return render_template('statistics.html', stats=stats, error=error)

@app.route('/rules/add', methods=['POST'])
def add_rule():
    try:
        current_rules_list = rule_engine.load_rules()
        form = request.form
        
        new_rule = {
            "rule_id": form.get('rule_id'),
            "rule_name": form.get('rule_name'),
            "description": form.get('description'),
            "level": form.get('level'),
            "type": form.get('rule_type')
        }
        
        match_criteria = {
            "EventID": int(form.get('match_event_id'))
        }
        if form.get('match_process_name'):
            match_criteria['NewProcessName'] = form.get('match_process_name')
        
        new_rule['match'] = match_criteria
        
        if new_rule['type'] == 'threshold':
            new_rule['group_by'] = form.get('group_by')
            new_rule['threshold'] = int(form.get('threshold_count'))
            new_rule['timeframe_seconds'] = int(form.get('timeframe_seconds'))
        elif new_rule['type'] != 'match':
            raise Exception(f"Invalid query type submitted: {new_rule['type']}")
            
        current_rules_list.append(new_rule)
        rule_engine.save_rules(current_rules_list)
        
        print("[Main] Acquiring lock to update live rules...")
        with RULES_LOCK:
            RULES_LIST.clear()
            RULES_LIST.extend(current_rules_list)
        print(f"[Main] Live rules reloaded. {len(RULES_LIST)} rules total.")
        
        flash(f"Rule {new_rule['rule_id']} added successfully!", 'success')
        
    except Exception as e:
        flash(f"Error adding rule: {e}", 'error')
        
    return redirect(url_for('rules_page'))

@app.route('/rules/delete/<rule_id>', methods=['POST'])
def delete_rule(rule_id):
    try:
        rules = rule_engine.load_rules()
        rules_to_keep = [r for r in rules if r.get('rule_id') != rule_id]
        
        if len(rules) == len(rules_to_keep):
            flash(f"Error: Rule {rule_id} not found.", 'error')
        else:
            rule_engine.save_rules(rules_to_keep)
            
            print("[Main] Acquiring lock to update live rules...")
            with RULES_LOCK:
                RULES_LIST.clear()
                RULES_LIST.extend(rules_to_keep)
            print(f"[Main] Live rules reloaded. {len(RULES_LIST)} rules total.")

            flash(f"Rule {rule_id} deleted successfully!", 'success')
            
    except Exception as e:
        flash(f"Error deleting rule: {e}", 'error')

    return redirect(url_for('rules_page'))

@socketio.on('connect')
def handle_connect():
    print('[SIEM GUI] Client connected to WebSocket.')

@socketio.on('disconnect')
def handle_disconnect():
    print('[SIEM GUI] Client disconnected from WebSocket.')

# --- Syslog Server Logic ---
class LogRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client_ip = self.client_address[0]
        
        try:
            client_socket_file = self.request.makefile('r')
            
            while True:
                line = client_socket_file.readline()
                if not line:
                    break 
                
                log_json = line.strip()
                
                try:
                    log_data = json.loads(log_json)
                except json.JSONDecodeError:
                    continue

                try:
                    normalized_log = log_schema.normalize_from_nxlog_json(log_data, client_ip)
                except Exception as e:
                    print(f"[ERROR] Failed to normalize log: {e}")
                    continue

                with self.server.machines_lock:
                    if client_ip not in self.server.known_machines:
                        self.server.known_machines[client_ip] = {
                            'ip': client_ip,
                            'hostname': normalized_log.get('computer_name', 'Unknown'),
                            'total_logs': 0,
                            'status': 'Online'
                        }
                    self.server.known_machines[client_ip]['total_logs'] += 1
                    self.server.known_machines[client_ip]['last_seen'] = datetime.now().isoformat()
                    self.server.known_machines[client_ip]['hostname'] = normalized_log.get('computer_name', 'Unknown')
                
                self.server.socketio.emit('new_log', normalized_log)

                try:
                    with self.server.rules_lock:
                        alerts = rule_engine.check_all_rules(
                            log_data, 
                            self.server.rules, 
                            self.server.state_tracker,
                            verbose=VERBOSE_RULE_CHECK
                        )
                except Exception as e:
                    print(f"[ERROR] Rule engine failed: {e}")
                    alerts = []

                try:
                    database.insert_log(self.server.db_conn, normalized_log)
                except Exception as e:
                    print(f"[ERROR] Failed to save log to DB: {e}")
                    continue

                for alert in alerts:
                    alert_level = alert.get('level', 'DEFAULT')
                    
                    alert_data = {
                        "rule": alert,
                        "normalized_log": normalized_log,
                        "raw_log": log_data,
                        "triggering_logs_raw": alert.get("triggering_logs"), 
                        "level_color": ALERT_LEVEL_COLORS.get(alert_level, ALERT_LEVEL_COLORS['DEFAULT'])
                    }
                    
                    self.server.socketio.emit('new_alert', alert_data)
                    
                    print("\n" + "!"*20 + " ALERT " + "!"*20)
                    print(f"  Rule ID:   {alert.get('rule_id')}")
                    print(f"  Name:    {alert.get('rule_name')}")
                    print(f"  >>> Alert sent to GUI <<<")
                    print("!"*47 + "\n")

        except ConnectionResetError:
            pass 
        except Exception as e:
            print(f"[Syslog Server] An unexpected error occurred with {client_ip}: {e}")
        finally:
            pass 

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def start_syslog_server(db_conn, rules, state_tracker, rules_lock, known_machines, machines_lock):
    try:
        server = ThreadedTCPServer((SYSLOG_HOST, SYSLOG_PORT), LogRequestHandler)
        
        server.db_conn = db_conn 
        server.rules = rules         
        server.state_tracker = state_tracker
        server.socketio = socketio 
        server.rules_lock = rules_lock 
        server.known_machines = known_machines
        server.machines_lock = machines_lock
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        display_ip = s.getsockname()[0]
        s.close()

        print(f"\n[Syslog Server] Started on {display_ip}:{SYSLOG_PORT} (Listening on {SYSLOG_HOST}:{SYSLOG_PORT})")
        
        server.serve_forever()

    except Exception as e:
        print(f"[Syslog Server] FATAL: Could not start: {e}")
    finally:
        if 'db_conn' in locals() and db_conn:
            db_conn.close()
            print("[Syslog Server] Database connection closed.")
        print("[Syslog Server] Shut down.")

# --- Main Execution ---
if __name__ == '__main__':
    try:
        print("[Main] Initializing database...")
        db_conn = database.init_db()
        if not db_conn:
            raise Exception("Could not initialize database. Exiting.")
        print("[Main] Database initialized successfully.")
        
        print("[Main] Loading initial detection rules...")
        with RULES_LOCK:
            RULES_LIST.extend(rule_engine.load_rules())
        if not RULES_LIST:
            print("[Main] WARNING: No rules were loaded. Check rules.json.")
        else:
            print(f"[Main] {len(RULES_LIST)} rules loaded.")
        
        state_tracker = {}
        
        print("[Main] Starting Syslog server in a background thread...")
        syslog_thread = threading.Thread(
            target=start_syslog_server, 
            args=(db_conn, RULES_LIST, state_tracker, RULES_LOCK, KNOWN_MACHINES, MACHINES_LOCK),
            daemon=True 
        )
        syslog_thread.start()

        print("[Main] Starting machine stats emitter thread...")
        socketio.start_background_task(target=start_machine_stats_thread)

        print(f"[Main] Starting Flask-SocketIO web server on http://{WEB_HOST}:{WEB_PORT}...")
        socketio.run(app, host=WEB_HOST, port=WEB_PORT, allow_unsafe_werkzeug=True)

    except KeyboardInterrupt:
        print("\n[Main] Ctrl+C received, shutting down...")
    except Exception as e:
        print(f"[Main] FATAL: {e}")
    finally:
        if 'db_conn' in locals() and db_conn:
            db_conn.close()
            print("[Main] Database connection closed.")
        print("[Main] Server shut down.")