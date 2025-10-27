import socketserver
import threading

# --- Configuration ---
# Use 0.0.0.0 to listen on all available interfaces (including 192.168.1.10)
HOST = "0.0.0.0" 
PORT = 5140 # The port we set in nxlog.conf
# --- End Configuration ---

class LogRequestHandler(socketserver.BaseRequestHandler):
    """
    Handles incoming log messages from NXLog.
    A new instance is created for each connection.
    """
    def handle(self):
        print(f"Connection received from: {self.client_address[0]}")
        try:
            # self.request is the TCP socket connected to the client
            # We wrap it in makefile() to get a file-like object
            # This allows us to use readline(), which is very efficient.
            rfile = self.request.makefile('rb')
            
            # Loop until the client disconnects
            while True:
                # Read one line, ending in the newline character NXLog adds
                data = rfile.readline()
                
                # If data is empty, the client disconnected
                if not data:
                    print(f"Client {self.client_address[0]} disconnected.")
                    break
                
                # Decode from bytes to string and strip whitespace (the \n)
                log_json = data.decode('utf-8').strip()
                
                # For M1.2, we just print the raw JSON to the console
                print(f"Received log: {log_json}")

        except Exception as e:
            print(f"Error handling request from {self.client_address[0]}: {e}")
        finally:
            rfile.close()

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """
    A multi-threaded TCP server.
    This allows the server to handle multiple NXLog agents 
    (e.g., from DC, Client 1, Client 2) at the same time.
    """
    allow_reuse_address = True # Allows server to restart quickly

if __name__ == "__main__":
    print(f"Starting PyLogSIEM Syslog server on {HOST}:{PORT}...")
    print(f"Note: The server is listening on 0.0.0.0, but your agents")
    print(f"should be configured to send to your Host-Only IP (e.g., 192.168.1.10).\n")
    
    try:
        # Create the server, binding to HOST:PORT and using our handler
        with ThreadedTCPServer((HOST, PORT), LogRequestHandler) as server:
            # Start a thread to handle requests.
            # The server_thread will run forever until interrupted.
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True # Allows Ctrl+C to stop the server
            server_thread.start()
            
            print(f"Server started on thread: {server_thread.name}")
            print("Press Ctrl+C to stop the server.")
            
            # Keep the main thread alive (so Ctrl+C can be detected)
            while True:
                server_thread.join(1.0) # Check every second
                
    except KeyboardInterrupt:
        print("\nCtrl+C received. Shutting down the server...")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if 'server' in locals():
            server.shutdown()
        print("Server shut down.")

