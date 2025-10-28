import sqlite3
import log_schema # Import our schema
import os

DB_FILE = "pylogsiem.db"

def init_db():
    """
    Initializes the database and creates the 'logs' table
    based on the fields in NORMALIZED_SCHEMA.
    """
    try:
        # Connect (or create if it doesn't exist)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # --- Dynamically build the CREATE TABLE command ---
        
        # Start with special columns
        columns = [
            "id INTEGER PRIMARY KEY AUTOINCREMENT",
            "timestamp DATETIME NOT NULL",
            "raw_log TEXT"
        ]
        
        # Add all other columns from our schema
        # We must add a check to skip fields we already handle manually
        for key, default_value in log_schema.NORMALIZED_SCHEMA.items():
            
            # ******** THIS IS THE FIX ********
            # Skip keys that are handled manually to avoid duplication
            if key not in ['timestamp', 'raw_log']:
            # *********************************
            
                # We can infer the type, but for a SIEM, storing everything
                # as TEXT is the most robust and simple solution.
                # Numbers, IPs, etc., are all stored as text.
                columns.append(f"{key} TEXT")

        # Join all columns into a single string
        columns_sql = ", ".join(columns)
        
        # The final SQL command
        create_table_sql = f"CREATE TABLE IF NOT EXISTS logs ({columns_sql});"
        
        # --- Execute the SQL ---
        cursor.execute(create_table_sql)
        
        # --- Create an index for faster searching ---
        # An index on 'timestamp' is critical for a SIEM
        # It makes queries like "WHERE timestamp > '...'" very fast.
        index_sql = "CREATE INDEX IF NOT EXISTS idx_timestamp ON logs (timestamp);"
        cursor.execute(index_sql)
        
        # Commit and close
        conn.commit()
        conn.close()
        
        print(f"[DB] Database '{DB_FILE}' initialized successfully.")
        
    except sqlite3.Error as e:
        print(f"FATAL: Database initialization error: {e}")
        # If we can't init the DB, the server can't run.
        raise # Re-raise the exception to stop the main server

def insert_log(normalized_log: dict):
    """
    Inserts a single normalized log dictionary into the database.
    
    :param normalized_log: A dictionary matching the structure of
                           log_schema.NORMALIZED_SCHEMA
    """
    
    try:
        conn = sqlite3.connect(DB_FILE)
        # Use a "row factory" to make inserting from a dict easier
        # But for this, we'll build the query manually for clarity
        
        # 1. Get all keys from the log dict
        keys = list(normalized_log.keys())
        
        # 2. Create the SQL string
        # e.g., "INSERT INTO logs (timestamp, event_id) VALUES (?, ?)"
        cols_sql = ", ".join(keys)
        placeholders_sql = ", ".join(["?"] * len(keys))
        
        insert_sql = f"INSERT INTO logs ({cols_sql}) VALUES ({placeholders_sql})"
        
        # 3. Get the values in the same order as the keys
        values = list(normalized_log.values())
        
        # 4. Execute
        cursor = conn.cursor()
        cursor.execute(insert_sql, values)
        
        # Commit and close
        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Error inserting log into database: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during log insertion: {e}")

if __name__ == "__main__":
    # This block allows you to test the DB module directly
    # To run: python database.py
    
    print("Running database self-test...")
    
    # 1. Nuke old DB for a clean test
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print(f"Removed old '{DB_FILE}' for testing.")
        
    # 2. Initialize
    init_db()
    
    # 3. Create a fake normalized log and insert it
    print("Testing log insertion...")
    fake_log = log_schema.create_empty_event()
    fake_log['timestamp'] = log_schema.datetime.now()
    fake_log['raw_log'] = '{"test": "This is a fake log"}'
    fake_log['event_id'] = "TEST_001"
    fake_log['event_type'] = "TEST"
    fake_log['host_ip'] = "127.0.0.1"
    
    insert_log(fake_log)
    
    # 4. Verify insertion
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs WHERE event_id = 'TEST_001'")
        row = cursor.fetchone()
        conn.close()
        
        if row:
            print("[SUCCESS] Self-test passed. Log inserted and retrieved.")
            # print(f"Retrieved row: {row}")
        else:
            print("[FAILURE] Self-test failed. Log was not retrieved.")
    except Exception as e:
        print(f"[FAILURE] Self-test failed during verification: {e}")

