import sqlite3
import os
from log_schema import NORMALIZED_SCHEMA

SIEM_DB = 'pylogsiem.db'

def init_db():
    """
    Initializes the SQLite database.
    Creates the 'logs' table based on the NORMALIZED_SCHEMA.
    Returns the database connection.
    """
    conn = sqlite3.connect(SIEM_DB, check_same_thread=False) 
    
    cursor = conn.cursor()
    
    # --- Build the CREATE TABLE query dynamically from the schema ---
    
    # Start with special columns
    columns = [
        "id INTEGER PRIMARY KEY AUTOINCREMENT",
        "timestamp DATETIME NOT NULL",
        "raw_log TEXT"
    ]
    
    # Add all columns from our schema
    for key, value_type in NORMALIZED_SCHEMA.items():
        # Skip special-cased keys
        if key in ['timestamp', 'raw_log']:
            continue
            
        sql_type = "TEXT" # Default to TEXT
        if value_type == int:
            sql_type = "INTEGER"
        elif value_type == float:
            sql_type = "REAL"
            
        columns.append(f"{key} {sql_type}")
    
    create_table_query = f"CREATE TABLE IF NOT EXISTS logs ({', '.join(columns)})"
    
    try:
        cursor.execute(create_table_query)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON logs (timestamp);")
        conn.commit()
        
    except sqlite3.Error as e:
        print(f"[DATABASE] FATAL: Error initializing database: {e}")
        raise
        
    return conn

def insert_log(conn, log_data):
    """
    Inserts a single, normalized log dictionary into the database
    using the provided connection.
    """
    
    keys = []
    values = []
    keys.append('timestamp')
    values.append(log_data.get('timestamp'))

    # Add all other keys from the schema
    for key in NORMALIZED_SCHEMA.keys():
        if key == 'timestamp': 
            continue
        keys.append(key)
        values.append(log_data.get(key))

    # Build the query
    # e.g., INSERT INTO logs (timestamp, event_id) VALUES (?, ?)
    placeholders = ", ".join(["?"] * len(keys))
    query = f"INSERT INTO logs ({', '.join(keys)}) VALUES ({placeholders})"
    
    try:
        cursor = conn.cursor()
        cursor.execute(query, values)
        conn.commit()
    except sqlite3.Error as e:
        print(f"[DATABASE] ERROR: Failed to insert log: {e}")
        print(f"[DATABASE] Query: {query}")
        print(f"[DATABASE] Values: {values}")

