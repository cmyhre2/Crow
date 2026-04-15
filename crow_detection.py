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
            # Here is the benefit: the detection logic stays clean
            log_security_alert("PORT_SCAN", ip, None, 3, f"Detected {port_count} ports")
    conn.close()

def detect_port_scans():
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
            HAVING COUNT(DISTINCT dst_port) > 5;
            """
            cur.execute(query)
            alerts = cur.fetchall()
            
            # Scaffolding: Print to see if the query is finding anything
            print(f"DEBUG: Detection query finished. Found {len(alerts)} potential threats.")

            for ip, port_count in alerts:
                description = f"Detected {port_count} distinct port connections in 60s."
                # Call the storage helper we built
                log_security_alert("PORT_SCAN", ip, None, 3, description)
                print(f"DEBUG: Alert logged for {ip} - {description}")
                
    except Exception as e:
        print(f"ERROR: Detection cycle failed: {e}")
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
            print("Running detection cycle...")
            detect_port_scans()
            # You can add other rules here later, e.g.:
            # detect_high_volume_traffic()
            # detect_blacklist_matches()
            
        except Exception as e:
            print(f"CRITICAL ERROR in detection loop: {e}")
            
        # Sleep for 60 seconds before the next check
        # This prevents the script from consuming 100% of your CPU
        time.sleep(60) # Testing: change number back to 60