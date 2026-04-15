import os
import psycopg2
from dotenv import load_dotenv

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