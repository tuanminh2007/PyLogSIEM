import socketserver
import json
import database
import log_schema
import rule_engine # M2.3: Import the new rule engine
import socket # For getting host IP

# --- Configuration ---
HOST_IP = "0.0.0.0" # Listen on all interfaces
PORT = 5140
SIEM_DB = 'pylogsiem.db'
VERBOSE_RULE_CHECK = True # M2.3: Set to True for detailed rule debugging
# --- End Configuration ---

class LogRequestHandler(socketserver.BaseRequestHandler):
    """
    A custom handler for each incoming log connection.
    self.request is the client socket connection.
    self.server is the main server object.
    self.client_address is the (ip, port) of the log sender.
    """
    def handle(self):
        client_ip = self.client_address[0]
        print(f"[Syslog Server] Connection established from: {client_ip}")
        
        try:
            # .makefile() is a robust way to read line-by-line from a socket
            client_socket_file = self.request.makefile('r', encoding='utf-8')
            
            while True:
                # Read one line, which is one full JSON log (thanks to NXLog's `\n`)
                line = client_socket_file.readline()
                if not line:
                    break # Client disconnected
                
                log_json = line.strip()
                if not log_json:
                    continue

                # --- 1. PARSE ---
                try:
                    log_data = json.loads(log_json)
                except json.JSONDecodeError:
                    print(f"[Syslog Server] ERROR: Failed to decode JSON from {client_ip}. Data: {log_json}")
                    continue

                # --- 2. NORMALIZE ---
                try:
                    # Pass both the log and the source IP for normalization
                    normalized_log = log_schema.normalize_from_nxlog_json(log_data, client_ip)
                except Exception as e:
                    print(f"[ERROR] Failed to normalize log: {e}. Raw data: {log_json}")
                    continue

                # --- 3. SAVE TO DB ---
                try:
                    # Pass the server's shared DB connection and the log
                    database.insert_log(self.server.db_conn, normalized_log)
                    print(f"[Syslog Server] Saved Event {normalized_log.get('event_id', 'N/A')} from {normalized_log.get('host_ip', 'N/A')}")
                
                except Exception as e:
                    # This will catch the "insert_log() takes 1... but 2 were given" error if database.py is old
                    print(f"[ERROR] Failed to save log to DB: {e}")
                    continue

                # --- 4. CHECK RULES (M2.3) ---
                try:
                    alerts = self.server.engine.check_all_rules(normalized_log, verbose=VERBOSE_RULE_CHECK)
                    for alert in alerts:
                        print("\n" + "="*20)
                        print(f"!!!!!!!!!!!! ALERT !!!!!!!!!!")
                        print(f"Rule: {alert['rule_id']} - {alert['name']}")
                        print(f"Details: {alert['description']}")
                        print(f"Triggering Log: Event {normalized_log.get('event_id')} from {normalized_log.get('host_ip')}")
                        print("="*20 + "\n")
                except Exception as e:
                    print(f"[ERROR] Rule engine failed: {e}")

        except Exception as e:
            print(f"[Syslog Server] Error in handler for {client_ip}: {e}")
        finally:
            print(f"[Syslog Server] Connection closed from: {client_ip}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """
    A multi-threaded TCP server.
    ThreadingMixIn means it will create a new thread for each connection.
    """
    # This allows the server to restart quickly on the same port
    allow_reuse_address = True
    
    def __init__(self, server_address, RequestHandlerClass, db_conn, engine):
        # Pass the db connection and rule engine to the server object
        # so all handlers can access them via `self.server.db_conn`
        self.db_conn = db_conn
        self.engine = engine
        # Call the base class constructor
        super().__init__(server_address, RequestHandlerClass)


def get_server_ip():
    """
    A small 'hack' to find the server's primary IP address for display.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) # Connect to a public server
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0" # Fallback

if __name__ == "__main__":
    try:
        # Initialize the database (creates table if not exists)
        # We call this with ZERO arguments to fix the M2.3 TypeError
        db_conn = database.init_db()
        if not db_conn:
            print("[FATAL] Could not initialize database. Exiting.")
            exit(1)
            
        # Initialize the rule engine (M2.3)
        engine = rule_engine.RuleEngine()
        
        server_ip = get_server_ip()

        # Create the server, passing our handler, the DB connection, and the engine
        with ThreadedTCPServer((HOST_IP, PORT), LogRequestHandler, db_conn, engine) as server:
            print(f"[Syslog Server] Started on {server_ip}:{PORT} (Listening on {HOST_IP})")
            print("[Syslog Server] Waiting for logs from NXLog...")
            
            # Start the server and wait for connections
            server.serve_forever()

    except KeyboardInterrupt:
        print("\n[Syslog Server] Ctrl+C received. Shutting down server...")
        
    except Exception as e:
        print(f"[FATAL] Server crashed: {e}")
        
    finally:
        # Cleanly close the database connection
        if 'db_conn' in locals() and db_conn:
            db_conn.close()
            print("[Syslog Server] Database connection closed. Exiting.")

