import os
import queue
import threading
from crow_storage import get_db_connection, bootstrap_db
from datetime import datetime
import psycopg2
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, UDP
from psycopg2.extras import execute_values
import logging

# Setup environment
load_dotenv()

# Logger instance for the Data Acquisition Module
logger = logging.getLogger(__name__)

# Thread-safe buffer for packets
packet_buffer = queue.Queue(maxsize=1000)

def process_packet(packet):
    """Parses a packet and returns a dictionary of relevant metadata."""
    if not packet.haslayer('IP'):
        return None

    # Map protocol numbers to readable names
    protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    proto_num = packet['IP'].proto
    proto_name = protocol_map.get(proto_num, str(proto_num))

    # Explicit conversion to a Postgres-friendly string
    dt_object = datetime.fromtimestamp(float(packet.time))
    formatted_time = dt_object.strftime('%Y-%m-%d %H:%M:%S')

    # Initialize basic metadata
    packet_data = {
        "timestamp": formatted_time,
        "src_ip": packet['IP'].src,
        "dst_ip": packet['IP'].dst,
        "protocol": proto_name,
        "packet_length": len(packet),
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None
    }

    # Extract TCP specific info if present (Safe check)
    if packet.haslayer('TCP'):
        packet_data["src_port"] = packet['TCP'].sport
        packet_data["dst_port"] = packet['TCP'].dport
        packet_data["tcp_flags"] = str(packet['TCP'].flags)
    
    # Extract UDP specific info if present (Safe check)
    elif packet.haslayer('UDP'):
        packet_data["src_port"] = packet['UDP'].sport
        packet_data["dst_port"] = packet['UDP'].dport

    return packet_data

def packet_callback(packet):
    data = process_packet(packet)
    if data:
        logger.debug(f"Adding packet to queue: {data['src_ip']} -> {data['dst_ip']}") # Scaffolding
        try:
            # Non-blocking put to queue
            packet_buffer.put_nowait(data)
        except queue.Full:
            logger.error("QUEUE FULL!") # Scaffolding
            pass # Drop packet if buffer is full to maintain system stability

def run_acquisition():
    print("Crow Data Acquisition Module Starting...")
    # BPF filter ensures Crow only captures IP traffic to save CPU
    sniff(filter="ip", prn=packet_callback, store=0)

def db_writer_worker():
    logger.debug("DB Writer thread started...") # Scaffolding
    """Background thread that drains the queue and writes to DB in batches."""
    try:
        conn = get_db_connection()
    
        while True:
            logger.debug("Waiting for data in queue...") # Scaffolding
            batch = []
            # Wait for the first item
            batch.append(packet_buffer.get()) # This blocks until something arrives
            logger.debug(f"Thread woke up! Collected {len(batch)} items.") # Scaffolding
        
            # Collect remaining waiting packets (up to 100)
            while len(batch) < 100 and not packet_buffer.empty():
                batch.append(packet_buffer.get_nowait())
            
            # Bulk insert
            values = [(d['timestamp'], d['src_ip'], d['dst_ip'], d['src_port'], d['dst_port'], d['protocol'], d['packet_length'], d['tcp_flags']) for d in batch]
            with conn.cursor() as cur:
                execute_values(cur, """INSERT INTO traffic_log 
    (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_length, tcp_flags) 
    VALUES %s""", values)
            conn.commit()
            logger.debug(f"Batch of {len(batch)} packets committed") # Scaffolding
    except Exception as e:
        logger.error(f"DB WRITER THREAD ERROR: {e}") # Scaffolding

# For use by crow_main.py only (makes it cleaner to read)
def run_data_acquisition():
    # Initialize tables once before starting anything else
    bootstrap_db()

    # Start the DB writer thread
    writer_thread = threading.Thread(target=db_writer_worker, daemon=True)
    writer_thread.start()
    
    print("Sniffer starting...")
    # This call is blocking, so it should keep the main thread alive
    sniff(filter="ip", prn=packet_callback, store=0)

# _Main_ method for running this file exclusively (for testing purposes)
if __name__ == "__main__":
# Initialize tables once before starting anything else
    bootstrap_db()

    # Start the DB writer thread
    writer_thread = threading.Thread(target=db_writer_worker, daemon=True)
    writer_thread.start()
    
    print("Sniffer starting...")
    # This call is blocking, so it should keep the main thread alive
    sniff(filter="ip", prn=packet_callback, store=0)