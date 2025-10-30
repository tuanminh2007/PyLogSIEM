import socketserver
import json
import socket  # <-- Import to fix the NameError
import threading

# Import our project-specific modules
import database
import rule_engine
from log_schema import normalize_from_nxlog_json

# --- Configuration ---
HOST, PORT = "0.0.0.0", 5140
SIEM_DB = 'pylogsiem.db'

# This will be our "state" for the rule engine (for M2.4)
# It's a dictionary that will hold recent events
rule_state = {}

class LogRequestHandler(socketserver.BaseRequestHandler):
    """
    Handles incoming TCP log messages.
    A new instance is created for each connection.
    """
    def handle(self):
        client_ip = self.client_address[0]
        print(f"[SYSLOG] Client connection from {client_ip}")
        
        try:
            # self.request is the client socket
            client_socket_file = self.request.makefile('r', encoding='utf-8')
            
            # Loop and read data line-by-line
            while True:
                line = client_socket_file.readline()
                if not line:
                    break  # Client disconnected
                
                log_json = line.strip()
                if not log_json:
                    continue

                # --- 1. PARSE LOG ---
                try:
                    log_data = json.loads(log_json)
                except json.JSONDecodeError:
                    print(f"[SYSLOG] Received non-JSON data from {client_ip}: {log_json}")
                    continue
                
                # --- 2. NORMALIZE LOG ---
                try:
                    # Pass the client_ip to the normalization function
                    normalized_log = normalize_from_nxlog_json(log_data, client_ip)
                except Exception as e:
                    # Catch the "missing 1 argument" error if it happens
                    print(f"[ERROR] Failed to normalize log: {e}\nRaw log: {log_data}")
                    continue
                
                # --- 3. SAVE LOG TO DB ---
                try:
                    # Use the server's shared database connection
                    database.insert_log(self.server.db_conn, normalized_log)
                    print(f"[DATABASE] Saved Event {normalized_log.get('event_id', 'N/A')} from {normalized_log.get('host_ip')}")
                except Exception as e:
                    print(f"[ERROR] Failed to save log to DB: {e}")
                    continue

                # --- 4. CHECK RULES ---
                try:
                    # Pass the log, rules, and state to the engine
                    alerts = rule_engine.check_all_rules(normalized_log, self.server.rules, rule_state)
                    
                    # For now, just print any alerts to the console
                    if alerts:
                        for alert in alerts:
                            print(f"\n!!!!!!!!!!!! ALERT !!!!!!!!!!")
                            print(f"  Rule: {alert['rule_name']} ({alert['level']})")
                            print(f"  Desc: {alert['description']}")
                            print(f"!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
                            
                except Exception as e:
                    print(f"[ERROR] Rule engine failed: {e}")

        except Exception as e:
            # Catch errors like 'Connection reset by peer'
            if "Connection reset" not in str(e):
                print(f"[ERROR] Error in socket handler: {e}")
        finally:
            print(f"[SYSLOG] Client {client_ip} disconnected.")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """A threaded TCP server to handle multiple clients."""
    allow_reuse_address = True
    daemon_threads = True  # This is True by default, but good to be explicit.
                           # Daemon threads will exit when the main thread exits.

# --- Main Server Startup ---
if __name__ == "__main__":
    # --- 1. Find our internal IP (for display only) ---
    internal_ip = "0.0.0.0"
    try:
        # This is a small "hack" to find the machine's primary internal IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        internal_ip = s.getsockname()[0]
        s.close()
    except Exception:
        print("Could not detect internal IP. Using 0.0.0.0")

    # --- 2. Initialize Database ---
    try:
        # Call init_db with zero arguments, as per our fix
        db_conn = database.init_db() 
        print(f"[DATABASE] Database '{SIEM_DB}' initialized successfully.")
    except Exception as e:
        print(f"[FATAL] Database initialization error: {e}")
        exit(1)
        
    # --- 3. Load Detection Rules ---
    rules = rule_engine.load_rules()
    if not rules:
        print("[WARNING] No rules were loaded. SIEM will only log events.")

    # --- 4. Start the Server ---
    try:
        server = ThreadedTCPServer((HOST, PORT), LogRequestHandler)
        
        # Make the db connection and rules available to all handlers
        server.db_conn = db_conn 
        server.rules = rules 
        
        print(f"[SYSLOG] Syslog server started on {internal_ip}:{PORT}...")
        
        # Run the server loop
        server.serve_forever()
        
    except KeyboardInterrupt:
        # This block will now be reached on the *first* Ctrl+C
        print("\n[SYSLOG] Shutdown signal received...")
    except Exception as e:
        print(f"[FATAL] Server startup error: {e}")
    finally:
        # Clean up
        if 'db_conn' in locals():
            db_conn.close()
            print("[DATABASE] Database connection closed.")
        if 'server' in locals():
            server.server_close()
        print("[SYSLOG] Server shut down gracefully.")

