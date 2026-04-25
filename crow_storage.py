import os
import psycopg2
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
from psycopg2.extras import RealDictCursor


load_dotenv()

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("CROW_DB_HOST"),
        port=os.getenv("CROW_DB_PORT"),
        database=os.getenv("CROW_DB_NAME"),
        user=os.getenv("CROW_DB_USER"),
        password=os.getenv("CROW_DB_PASS")
    )

def bootstrap_db():
    """Run this to ensure all required tables exist."""
    commands = [
        """CREATE TABLE IF NOT EXISTS traffic_log (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMPTZ,
            src_ip INET,
            dst_ip INET,
            src_port INT,
            dst_port INT,
            protocol VARCHAR(10),
            packet_length INT,
            tcp_flags VARCHAR(20)
        );""",
        """CREATE TABLE IF NOT EXISTS security_alerts (
            id SERIAL PRIMARY KEY,
            alert_type VARCHAR(100),
            source_ip INET,
            target_ip INET,
            severity INT,
            description TEXT,
            report TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );"""
    ]
    conn = get_db_connection()
    cur = conn.cursor()
    for cmd in commands:
        cur.execute(cmd)
    conn.commit()
    cur.close()
    conn.close()
    print("Database tables verified.")

# Helper for the Acquisition module
def save_packet_batch(batch):
    # This keeps the logic contained here
    pass

# Helper for the Detection module
def log_security_alert(alert_type, src_ip, target_ip, severity, description):
    """Logs a security alert to the database."""
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
        INSERT INTO security_alerts 
        (alert_type, source_ip, target_ip, severity, description)
        VALUES (%s, %s, %s, %s, %s)
    """
    cur.execute(query, (alert_type, src_ip, target_ip, severity, description))
    conn.commit()
    cur.close()
    conn.close()

def setup_logging():
    """Configures centralized, rotating logging for all modules."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # Change to DEBUG to see packet details

    # Create the rotating handler
    handler = RotatingFileHandler(
        'crow.log', 
        maxBytes=10 * 1024 * 1024, # 10MB per file
        backupCount=3              # Keep 3 historical logs
    )
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    
    # Optional: Also print to console so the user can see alerts live
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

def get_all_alerts():
    """Queries the security_alerts table and returns a list of dictionaries."""
    conn = get_db_connection()
    # RealDictCursor makes the rows act like dictionaries
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("SELECT * FROM security_alerts ORDER BY id DESC LIMIT 50")
        alerts = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    return alerts

def get_metrics():
    """Queries aggregated stats using the correct schema names."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    data = {}
    try:
        # Packets in last 10 minutes
        cursor.execute("SELECT COUNT(*) as count FROM traffic_log WHERE timestamp > NOW() - INTERVAL '10 minutes'")
        data["packets_10min"] = cursor.fetchone()['count']
        
        # Packets in last 1 hour
        cursor.execute("SELECT COUNT(*) as count FROM traffic_log WHERE timestamp > NOW() - INTERVAL '1 hour'")
        data["packets_1h"] = cursor.fetchone()['count']

        # Port Scans in last 10 minutes
        cursor.execute("""
            SELECT COUNT(*) as count FROM security_alerts 
            WHERE alert_type = 'PORT_SCAN' 
            AND created_at > NOW() - INTERVAL '10 minutes'
        """)
        data["port_scans_10min"] = cursor.fetchone()['count']
        
        # Most common Source IP
        cursor.execute("""
            SELECT source_ip, COUNT(*) as frequency 
            FROM security_alerts 
            GROUP BY source_ip 
            ORDER BY frequency DESC LIMIT 1
        """)
        row_ip = cursor.fetchone()
        data["top_ip"] = str(row_ip['source_ip']) if row_ip else "N/A"
        
        # Most common Protocol
        cursor.execute("""
            SELECT protocol, COUNT(*) as frequency 
            FROM traffic_log 
            GROUP BY protocol 
            ORDER BY frequency DESC LIMIT 1
        """)
        row_proto = cursor.fetchone()
        data["top_protocol"] = row_proto['protocol'] if row_proto else "N/A"

    except Exception as e:
        print(f"Error in get_metrics: {e}")
        return {"error": str(e)}
    finally:
        cursor.close()
        conn.close()
        
    return data

def get_recent_reports():
    """Fetches the latest alerts that have an LLM-generated report."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    try:
        # Crow only wants rows where 'report' is not NULL and not an empty string
        cursor.execute("""
            SELECT id, alert_type, description, report, created_at 
            FROM security_alerts 
            WHERE report IS NOT NULL AND report != ''
            ORDER BY id DESC LIMIT 10
        """)
        reports = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    return reports