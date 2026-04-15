import os
import queue
import threading
from datetime import datetime
import psycopg2
import psycopg2
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, UDP
from psycopg2.extras import execute_values

# Setup environment
load_dotenv()

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
        print(f"DEBUG: Adding packet to queue: {data['src_ip']} -> {data['dst_ip']}") # Scaffolding
        try:
            # Non-blocking put to queue
            packet_buffer.put_nowait(data)
        except queue.Full:
            print("DEBUG: QUEUE FULL!") # Scaffolding
            pass # Drop packet if buffer is full to maintain system stability

def run_acquisition():
    print("Crow Data Acquisition Module Starting...")
    # BPF filter ensures Crow only captures IP traffic to save CPU
    sniff(filter="ip", prn=packet_callback, store=0)

def db_writer_worker():
    print("DB Writer thread started...") # Scaffolding
    """Background thread that drains the queue and writes to DB in batches."""
    try:
        conn = psycopg2.connect(
            host=os.getenv("CROW_DB_HOST"),
            port=os.getenv("CROW_DB_PORT"),
            database=os.getenv("CROW_DB_NAME"),
            user=os.getenv("CROW_DB_USER"),
            password=os.getenv("CROW_DB_PASS")
        )
    
        while True:
            print("Waiting for data in queue...") # Scaffolding
            batch = []
            # Wait for the first item
            batch.append(packet_buffer.get()) # This blocks until something arrives
            print(f"Thread woke up! Collected {len(batch)} items.") # Scaffolding
        
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
            print(f"Batch of {len(batch)} packets committed") # Scaffolding
    except Exception as e:
        print(f"DB WRITER THREAD ERROR: {e}") # Scaffolding

if __name__ == "__main__":
    # Start the DB writer thread
    writer_thread = threading.Thread(target=db_writer_worker, daemon=True)
    writer_thread.start()
    
    print("Sniffer starting...")
    # This call is blocking, so it should keep the main thread alive
    sniff(filter="ip", prn=packet_callback, store=0)