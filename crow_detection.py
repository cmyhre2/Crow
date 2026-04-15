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
    """Rule 1: Detect Port Scans"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            query = "SELECT src_ip, COUNT(DISTINCT dst_port) as port_count FROM traffic_log WHERE timestamp > NOW() - INTERVAL '60 seconds' GROUP BY src_ip HAVING COUNT(DISTINCT dst_port) > 10;"
            cur.execute(query)
            alerts = cur.fetchall()
            
            if alerts:
                print(f"[!] Port Scan Alert: Found {len(alerts)} suspicious IP(s).")
                for ip, count in alerts:
                    log_security_alert("PORT_SCAN", ip, None, 3, f"Scanned {count} ports")
            else:
                print("[ ] Port Scan: No threats found.")
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
            if alerts:
                print(f"[!] Traffic Spike Alert: Found {len(alerts)} burst event(s).")
                for ip, count in alerts:
                    log_security_alert("TRAFFIC_SPIKE", ip, None, 4, f"Burst: {count} pkts/10s")
            else:
                print("[ ] Traffic Spike: No threats found.")
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
            alerts = cur.fetchall()
            if alerts:
                print(f"[!] High Volume Alert: Found {len(alerts)} high volume source(s).")
                for ip, count in alerts:
                    log_security_alert("HIGH_VOLUME", ip, None, 2, f"Volume: {count} pkts/5m")
            else:
                print("[ ] High Volume: No threats found.")
    finally:
        conn.close()

def detect_blacklist_matches():
    """Rule 4: Detect activity from known malicious IPs."""
    # This list could eventually be loaded from a file or another DB table
    blacklist = ['192.168.1.105', '45.76.12.34', '10.0.0.99','172.17.8.125']  # Testing: Remove 172.17.8.125 (computer's local IP for testing this rule) later.
    
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
            if matches:
                print(f"[!] Blacklist Alert: Found {len(matches)} blacklisted connection(s).")
                for (ip,) in matches:
                    log_security_alert("BLACKLIST_MATCH", ip, None, 5, "Connection from malicious IP.")
            else:
                print("[ ] Blacklist: No matches found.")
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
            # Rule 1: Reconnaissance
            detect_port_scans()
            
            # Rule 2: Immediate Threats
            detect_traffic_spikes()
            
            # Rule 3: Behavioral Trends
            detect_high_volume()
            
            # Rule 4: Known Threats
            detect_blacklist_matches()
            
            print("==============")
            print(f"Cycle starting at {time.strftime('%H:%M:%S')}")

        except Exception as e:
            print(f"CRITICAL ERROR in detection loop: {e}")
            
        # Sleep for 60 seconds before the next check
        # This prevents the script from consuming 100% of your CPU
        time.sleep(60) # Testing: change number back to 60