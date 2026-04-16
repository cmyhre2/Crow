import ollama
from crow_storage import get_db_connection
import time
import logging

# Logger instance for the LLM Intelligence Module
logger = logging.getLogger(__name__)

def analyze_pending_alerts():
    """Finds alerts without a report and uses LLM to generate one."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Fetch alerts that haven't been analyzed yet
            cur.execute("SELECT id, alert_type, source_ip, description FROM security_alerts WHERE report IS NULL;")
            pending_alerts = cur.fetchall()
            
            for alert in pending_alerts:
                alert_id, alert_type, src_ip, desc = alert
                logger.debug(f"Analyzing Alert ID {alert_id}: {alert_type} from {src_ip}")
                
                # The "Investigator" Prompt
                prompt = (
                    f"Act as a cybersecurity expert. Analyze this security alert: "
                    f"Type: {alert_type}, Source IP: {src_ip}, Details: {desc}. "
                    f"Provide a concise, human-readable summary of the potential threat "
                    f"and recommended immediate mitigation steps."
                )
                
                # Send to local LLM
                response = ollama.chat(model='llama3', messages=[{'role': 'user', 'content': prompt}])
                report_text = response['message']['content']
                
                # Update the database
                cur.execute("UPDATE security_alerts SET report = %s WHERE id = %s", (report_text, alert_id))
                conn.commit()
                logger.debug(f"Report generated for Alert ID {alert_id}")
                
    finally:
        conn.close()

# For use by crow_main.py only (makes it cleaner to read)
def run_llm_intelligence():
    print("Intelligence Module Active. Watching for alerts...")
    while True:
        analyze_pending_alerts()
        time.sleep(30) # Check for new reports every 30 seconds

# _Main_ method for running this file exclusively (for testing purposes)
if __name__ == "__main__":
    print("Intelligence Module Active. Watching for alerts...")
    while True:
        analyze_pending_alerts()
        time.sleep(30) # Check for new reports every 30 seconds