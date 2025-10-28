import socketserver
import json
import database  # Our new database manager
from log_schema import normalize_from_nxlog_json # Our new normalization function

# --- Configuration ---
# This must match the IP of your Linux VM's Host-Only NIC
# 0.0.0.0 means "listen on all available IPs"
LISTEN_IP = "0.0.0.0" 

# This must match the Port in your nxlog.conf
LISTEN_PORT = 5140
# --- End Configuration ---

class LogRequestHandler(socketserver.BaseRequestHandler):
    """
    A custom handler for each incoming log connection.
    socketserver creates a new instance of this class for each connection.
    """
    def handle(self):
        """
        This method is called every time a log is received.
        """
        try:
            # self.request is the TCP socket connection
            # We read data in a loop until the client disconnects
            # NXLog sends one JSON string per line, ending in '\n'
            
            # Use makefile to treat the socket like a file
            # This makes reading line-by-line easy
            client_socket_file = self.request.makefile('rb') # 'rb' = read binary
            
            while True:
                line_bytes = client_socket_file.readline()
                if not line_bytes:
                    break # Client disconnected
                
                # Decode bytes to string and strip whitespace/newlines
                log_json_string = line_bytes.decode('utf-8').strip()
                
                if not log_json_string:
                    continue # Skip empty lines

                # 1. PARSE the raw JSON string into a Python dict
                try:
                    log_data = json.loads(log_json_string)
                except json.JSONDecodeError:
                    print(f"Error: Received invalid JSON: {log_json_string}")
                    continue
                
                # 2. NORMALIZE the dict using our schema function
                # self.client_address[0] is the IP of the sender (e.g., your Windows VM)
                host_ip = self.client_address[0]
                normalized_log = normalize_from_nxlog_json(log_data, host_ip)
                
                # 3. SAVE the normalized dict to the database
                database.insert_log(normalized_log)

                # 4. Print a clean confirmation to the console
                event_id = normalized_log.get('event_id', 'N/A')
                event_type = normalized_log.get('event_type', 'UNKNOWN')
                print(f"Log from {host_ip}: Saved Event {event_id} ({event_type})")
                
        except ConnectionResetError:
            print(f"Client disconnected: {self.client_address[0]}")
        except Exception as e:
            print(f"An error occurred in handle: {e}")
        finally:
            client_socket_file.close()

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """
    A multi-threaded TCP server.
    This allows our server to handle multiple Windows VMs sending logs
    at the exact same time without blocking.
    """
    allow_reuse_address = True # Allow server to restart quickly

if __name__ == "__main__":
    print("PyLogSIEM v2 - Real-Time Log Collector")
    print("---------------------------------------")
    
    # 1. Initialize the database (create table if it doesn't exist)
    database.init_db()
    
    # 2. Start the log listener server
    try:
        server = ThreadedTCPServer((LISTEN_IP, LISTEN_PORT), LogRequestHandler)
        
        # Get the actual IP for a friendlier message
        server_ip = LISTEN_IP
        if LISTEN_IP == "0.0.0.0":
            # Find our "real" IP to show the user
            try:
                # This is a small trick to find the machine's outbound IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80)) # Doesn't send, just finds route
                server_ip = s.getsockname()[0]
                s.close()
            except Exception:
                server_ip = "127.0.0.1" # Fallback

        print(f"\n[OK] Syslog server started on {server_ip}:{LISTEN_PORT}")
        print("Listening for JSON logs from NXLog agents...")
        print("Press Ctrl+C to stop.")
        
        # 3. Run the server forever
        server.serve_forever()
        
    except KeyboardInterrupt:
        print("\nCtrl+C received. Shutting down server...")
        server.shutdown()
        server.server_close()
        print("Server shut down.")
    except Exception as e:
        print(f"FATAL: Could not start server: {e}")
        print("Check if the port is in use or if you have permission.")

