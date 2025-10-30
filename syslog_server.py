import socketserver
import json
import database
import log_schema
import rule_engine
import socket # Added to get host IP

# --- Configuration ---
HOST, PORT = "0.0.0.0", 5140
SIEM_DB = 'pylogsiem.db'
VERBOSE_RULE_CHECK = True # Set to True to see why rules fail
# --- End Configuration ---

class LogRequestHandler(socketserver.BaseRequestHandler):
    """
    Handles incoming log messages.
    Each connection (from each NXLog agent) will have its own instance.
    """
    def handle(self):
        client_ip = self.client_address[0]
        print(f"[Syslog Server] Client connected: {client_ip}")
        
        try:
            # Use makefile to treat the socket as a file
            # This allows us to use .readline(), which is very clean
            client_socket_file = self.request.makefile('r')
            
            while True:
                line = client_socket_file.readline()
                if not line:
                    break # Client disconnected
                
                log_json = line.strip()
                
                # --- 1. PARSE ---
                try:
                    log_data = json.loads(log_json)
                except json.JSONDecodeError:
                    print(f"[ERROR] Failed to decode JSON from {client_ip}: {log_json[:100]}...")
                    continue

                # --- 2. CHECK RULES (M2.3 & M2.4) ---
                # We now run rules on the RAW log_data dict
                try:
                    alerts = rule_engine.check_all_rules(
                        log_data, 
                        self.server.rules, 
                        self.server.state_tracker,
                        verbose=VERBOSE_RULE_CHECK
                    )
                except Exception as e:
                    print(f"[ERROR] Rule engine failed: {e}")
                    alerts = [] # Ensure alerts is a list

                # --- 3. NORMALIZE ---
                # Normalization now happens *after* detection
                try:
                    normalized_log = log_schema.normalize_from_nxlog_json(log_data, client_ip)
                except Exception as e:
                    print(f"[ERROR] Failed to normalize log: {e}")
                    continue

                # --- 4. SAVE TO DB ---
                try:
                    database.insert_log(self.server.db_conn, normalized_log)
                    print(f"[Database] Saved Event {normalized_log.get('event_id')} from {client_ip}")
                except Exception as e:
                    print(f"[ERROR] Failed to save log to DB: {e}")
                    continue

                # --- 5. EMIT ALERTS ---
                # We process the alerts *after* saving, so the log is in the DB
                # when the alert fires.
                for alert in alerts:
                    print("\n" + "!"*20 + " ALERT " + "!"*20)
                    print(f"  Rule ID:   {alert['rule_id']}")
                    print(f"  Name:    {alert['rule_name']}")
                    print(f"  Level:   {alert['level']}")
                    print(f"  Event:   {normalized_log.get('event_type')} (ID: {normalized_log.get('event_id')})")
                    print(f"  Source:  {normalized_log.get('source_ip')} ({normalized_log.get('host_ip')})")
                    print(f"  User:    {normalized_log.get('username')}")
                    
                    # Add process info if it's a process alert
                    process = normalized_log.get('process_name')
                    if process and process != 'N/A':
                         print(f"  Process: {process}")
                         
                    print("!"*47 + "\n")

        except ConnectionResetError:
            print(f"[Syslog Server] Client disconnected (connection reset): {client_ip}")
        except Exception as e:
            print(f"[Syslog Server] An unexpected error occurred with {client_ip}: {e}")
        finally:
            print(f"[Syslog Server] Closing connection from {client_ip}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """
    A multi-threaded TCP server.
    ThreadingMixIn allows each connection to be handled in a new thread.
    """
    allow_reuse_address = True # Allow server to restart quickly
    daemon_threads = True      # Auto-kill threads when main server exits

if __name__ == "__main__":
    try:
        # --- 1. Get Host IP for display ---
        # This is a small "hack" to find the machine's real IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        display_ip = s.getsockname()[0]
        s.close()
        
        # --- 2. Initialize Database ---
        print("[Main] Initializing database...")
        # We pass the db name to init_db, and it returns a connection
        db_conn = database.init_db()
        if not db_conn:
            raise Exception("Could not initialize database. Exiting.")
        print("[Main] Database initialized successfully.")
        
        # --- 3. Load Rules ---
        print("[Main] Loading detection rules...")
        rules = rule_engine.load_rules()
        if not rules:
            print("[Main] WARNING: No rules were loaded. Check rules.json.")
        
        # --- 4. Start Server ---
        server = ThreadedTCPServer((HOST, PORT), LogRequestHandler)
        
        # Make the db connection and rules available to all handlers
        server.db_conn = db_conn 
        server.rules = rules
        server.state_tracker = {} 
        
        print(f"\n[Syslog Server] Started on {display_ip}:{PORT} (Listening on {HOST}:{PORT})")
        print("Waiting for logs... (Press Ctrl+C to shut down)")
        
        server.serve_forever()

    except KeyboardInterrupt:
        print("\n[Main] Ctrl+C received, shutting down server...")
    except Exception as e:
        print(f"[Main] FATAL: {e}")
    finally:
        # Cleanly close the database connection
        if 'db_conn' in locals() and db_conn:
            db_conn.close()
            print("[Main] Database connection closed.")
        print("[Main] Server shut down.")