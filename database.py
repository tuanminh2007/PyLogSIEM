import sqlite3
import os
from log_schema import NORMALIZED_SCHEMA # Import the schema to build the table

# --- Configuration ---
DB_FILE = "pylogsiem.db"
# --- End Configuration ---

def init_db():
    """
    Initializes the database and creates the 'logs' table
    if it doesn't already exist.
    The table structure is dynamically built from the log_schema.
    """
    print("Initializing database...")
    try:
        # Connect to the DB file (it will be created if it doesn't exist)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # --- Dynamically build the CREATE TABLE command ---
        
        # Start with special columns
        table_columns = [
            "id INTEGER PRIMARY KEY AUTOINCREMENT",
            "timestamp DATETIME",
            "raw_log TEXT" # To store the original JSON
        ]
        
        # Add all fields from our normalized schema as TEXT columns
        for field in NORMALIZED_SCHEMA.keys():
            # We already handled 'timestamp'
            if field == 'timestamp':
                continue
            table_columns.append(f"{field} TEXT")
            
        # Join all columns into a single string
        columns_sql = ", ".join(table_columns)
        
        # Create the full SQL command
        create_table_sql = f"CREATE TABLE IF NOT EXISTS logs ({columns_sql});"
        
        # --- End of dynamic build ---

        # Execute the CREATE TABLE command
        cursor.execute(create_table_sql)
        print(f"Database table 'logs' is ready (columns: {len(table_columns)}).")

        # Create an index on the timestamp for faster queries
        index_sql = "CREATE INDEX IF NOT EXISTS idx_timestamp ON logs (timestamp);"
        cursor.execute(index_sql)
        print("Timestamp index is ready.")

        # Commit changes and close
        conn.commit()
        conn.close()
        print("Database initialization complete.")
        
    except sqlite3.Error as e:
        print(f"FATAL: Database initialization error: {e}")
        # If we can't init the DB, we can't run.
        exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during DB init: {e}")
        exit(1)


def insert_log(log_data: dict):
    """
    Inserts a single, normalized log dictionary into the database.
    
    :param log_data: A dictionary matching the NORMALIZED_SCHEMA
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # We build the INSERT query dynamically to match the schema
        # This is robust to schema changes (adding/removing fields)
        
        # Get a list of all keys (columns) present in this log
        columns = list(log_data.keys())
        
        # Create the 'VALUES (?, ?, ...)' part
        placeholders = ", ".join(["?"] * len(columns))
        
        # Get the corresponding values
        values = [log_data.get(col) for col in columns]
        
        # Create the full SQL
        # e.g., INSERT INTO logs (timestamp, event_id, ...) VALUES (?, ?, ...)
        insert_sql = f"INSERT INTO logs ({', '.join(columns)}) VALUES ({placeholders})"
        
        # Execute the insert
        cursor.execute(insert_sql, values)
        conn.commit()
        
    except sqlite3.Error as e:
        print(f"DB Insert Error: {e}")
    except Exception as e:
        print(f"Unexpected error during log insert: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    # This block allows you to run 'python database.py' to init the DB
    print("Running in main. Deleting old DB (if exists) and creating fresh table...")
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print(f"Removed old database: {DB_FILE}")
        
    init_db()
    print("New database created successfully.")

