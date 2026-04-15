import psycopg2
import time
from crow_storage import get_db_connection, log_security_alert

def run_port_scan_detection():
    conn = get_db_connection()
    with conn.cursor() as cur:
        # Query for scans...
        cur.execute("SELECT ...") 
        alerts = cur.fetchall()
        
        for ip, port_count in alerts:
            log_security_alert("PORT_SCAN", ip, None, 3, f"Detected {port_count} ports")
    conn.close()

def detect_port_scans():
    """Rule 1: Detect Reconnaissance (scanning many ports)."""
    """
    Analyzes traffic_log for rapid distinct port connections 
    and logs alerts to security_alerts.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # PostgreSQL aggregation: Find source IPs connecting to > 10 ports in 60s
            # Testing: change number in HAVING clause back to 10
            query = """
            SELECT src_ip, COUNT(DISTINCT dst_port) as port_count
            FROM traffic_log
            WHERE timestamp > NOW() - INTERVAL '60 seconds'
            GROUP BY src_ip
            HAVING COUNT(DISTINCT dst_port) > 10;
            """
            cur.execute(query)
            alerts = cur.fetchall()
            
            # Scaffolding: Print to see if the query is finding anything
            print(f"DEBUG: Detection query finished. Found {len(alerts)} potential threats.")

            for ip, port_count in alerts:
                description = f"Detected {port_count} distinct port connections in 60s."
                # Call the storage helper for alerts
                log_security_alert("PORT_SCAN", ip, None, 3, description)
                print(f"DEBUG: Alert logged for {ip} - {description}")
                
    except Exception as e:
        print(f"ERROR: Detection cycle failed: {e}")
    finally:
        conn.close()

def detect_traffic_spikes():
    """Rule 2: Detect Intensity (rapid, high-volume bursts)."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Find IPs that sent more than 500 packets in 10 seconds
            query = """
            SELECT src_ip, COUNT(*) as packet_count
            FROM traffic_log
            WHERE timestamp > NOW() - INTERVAL '10 seconds'
            GROUP BY src_ip
            HAVING COUNT(*) > 500;
            """
            cur.execute(query)
            alerts = cur.fetchall()
            
            for ip, count in alerts:
                log_security_alert("TRAFFIC_SPIKE", ip, None, 2, f"Sent {count} packets in 60s")
    finally:
        conn.close()

def detect_high_volume():
    """Rule 3: Detect Sustained Exfiltration (high volume over time)."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Look for 5,000+ packets in 5 minutes
            query = """
            SELECT src_ip, COUNT(*) as packet_count
            FROM traffic_log
            WHERE timestamp > NOW() - INTERVAL '5 minutes'
            GROUP BY src_ip
            HAVING COUNT(*) > 5000;
            """
            cur.execute(query)
            for ip, count in cur.fetchall():
                log_security_alert("HIGH_VOLUME", ip, None, 2, f"Sustained load: {count} packets in 5m.")
    finally:
        conn.close()

def detect_blacklist_matches():
    """Rule 4: Detect activity from known malicious IPs."""
    # This list could eventually be loaded from a file or another DB table
    blacklist = ['192.168.1.105', '45.76.12.34', '10.0.0.99'] 
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Query for any activity from blacklisted IPs in the last 60 seconds
            query = """
            SELECT DISTINCT src_ip
            FROM traffic_log
            WHERE timestamp > NOW() - INTERVAL '60 seconds'
            AND src_ip = ANY(%s);
            """
            cur.execute(query, (blacklist,))
            matches = cur.fetchall()
            
            for (ip,) in matches:
                log_security_alert("BLACKLIST_MATCH", ip, None, 5, "Connection from blacklisted IP.")
    finally:
        conn.close()

if __name__ == "__main__":
    print("Crow Detection Engine starting...")

    """
    print("Testing manual alert log...")
    log_security_alert("TEST_ALERT", "127.0.0.1", "127.0.0.1", 1, "This is a test alert.")
    print("Test alert sent. Check your DB now.")
    """
    
    # Optional: Initial setup check if needed
    # bootstrap_db() 
    
    while True:
        try:
            print(f"Cycle starting at {time.strftime('%H:%M:%S')}")
            
            # Rule 1: Reconnaissance
            detect_port_scans()
            
            # Rule 2: Immediate Threats
            detect_traffic_spikes()
            
            # Rule 3: Behavioral Trends
            detect_high_volume()
            
            # Rule 4: Known Threats
            detect_blacklist_matches()
            
        except Exception as e:
            print(f"CRITICAL ERROR in detection loop: {e}")
            
        # Sleep for 60 seconds before the next check
        # This prevents the script from consuming 100% of your CPU
        time.sleep(60) # Testing: change number back to 60