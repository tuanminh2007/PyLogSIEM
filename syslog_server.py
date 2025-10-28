import socketserver
import json
import database
import log_schema
from log_schema import normalize_from_nxlog_json # Our new parser
import threading
import socket 

# Use 0.0.0.0 to listen on all available IPs
HOST, PORT = "0.0.0.0", 5140

# Get the IP of the host-only adapter for a nice print message
# This is a bit advanced, but useful. We'll default to 0.0.0.0 if we can't find it.
LISTEN_IP = "0.0.0.0"
try:
    # This is a 'hack' to find the IP of the interface used to route to a public IP
    # In our VM, it should find the 192.168.1.10 (or 192.168.10.2) IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    LISTEN_IP = s.getsockname()[0]
    s.close()
except OSError:
    print("Warning: Could not auto-detect host-only IP. Listening on all interfaces.")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """
    A TCP server that handles each new connection in a separate thread.
    This is critical for a SIEM so one slow client can't block another.
    """
    daemon_threads = True       # This is the key: allows main thread to exit
    allow_reuse_address = True  # Allows server to restart quickly

class LogRequestHandler(socketserver.StreamRequestHandler):
    """
    This class is instantiated once per connection.
    The 'handle' method is run in a new thread.
    """
    def handle(self):
        client_ip = self.client_address[0]
        print(f"[+] Connection from {client_ip}")
        
        try:
            # self.rfile is a file-like object for the socket
            # We can iterate over it line-by-line, which is perfect for syslog
            for line in self.rfile:
                # 1. Decode the raw bytes to a string and strip whitespace/newlines
                log_json_str = line.decode('utf-8').strip()
                
                # If we get an empty line, just ignore it
                if not log_json_str:
                    continue

                # 2. Process the log line in a try/except block
                try:
                    # Parse the JSON string into a Python dictionary
                    log_data = json.loads(log_json_str)
                    
                    # 3. Normalize the log using our schema function
                    # ******** THIS IS THE FIX ********
                    normalized_log = normalize_from_nxlog_json(log_data, client_ip)
                    
                    # 4. Save the normalized log to our database
                    database.insert_log(normalized_log)
                    
                    # 5. Print a clean, friendly message to the console
                    print(f"  [OK] Normalized and saved Event {normalized_log.get('event_id')} from {normalized_log.get('host_ip')}")

                except json.JSONDecodeError:
                    print(f"  [ERROR] Received non-JSON data from {client_ip}: {log_json_str[:80]}...")
                except Exception as e:
                    print(f"  [ERROR] Failed to process/save log: {e}")
                    
        except ConnectionResetError:
            # This happens when a client (NXLog) disconnects forcefully
            print(f"[-] Client {client_ip} disconnected (connection reset).")
        except Exception as e:
            # Catch any other handler-level errors
            print(f"[-] An error occurred in the handler for {client_ip}: {e}")
        finally:
            # This 'finally' block runs when the loop is broken
            # (i.e., the client disconnects)
            print(f"[-] Connection closed from {client_ip}")

# --- Main execution ---
if __name__ == "__main__":
    
    print("[DB] Initializing database...")
    # Initialize the database (creates table if it doesn't exist)
    database.init_db()
    
    # Create the server instance
    server = ThreadingTCPServer((HOST, PORT), LogRequestHandler)
    
    try:
        print(f"[SIEM] Syslog server started on {LISTEN_IP}:{PORT}...")
        print("[SIEM] Waiting for logs... (Press Ctrl+C to shut down)")
        # Start the server's main loop.
        # This will block until a KeyboardInterrupt (Ctrl+C).
        server.serve_forever()
        
    except KeyboardInterrupt:
        # This block catches the Ctrl+C
        print("\n[SIEM] Shutdown signal (Ctrl+C) received...")
        
    except Exception as e:
        # Catch any fatal server errors (e.g., port in use)
        print(f"\n[SIEM] Server crashed with a fatal error: {e}")
        
    finally:
        # This 'finally' block runs no matter what (on clean exit or crash)
        # We just need to close the main server socket.
        # The 'daemon_threads = True' setting will handle killing
        # any active handler threads automatically.
        server.server_close()
        print("[SIEM] Server shut down.")

