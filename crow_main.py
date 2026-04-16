import threading
import uvicorn
from fastapi import FastAPI
from crow_storage import bootstrap_db
import crow_data_acquisition
import crow_detection
import crow_llm_intelligence
from crow_storage import bootstrap_db, setup_logging

app = FastAPI()

# ... API endpoints ...

if __name__ == "__main__":
    print("--- Crow System Initializing ---")
    setup_logging()
    bootstrap_db()
    
    # Everything is now triggered by a clean method call
    threading.Thread(target=crow_data_acquisition.run_data_acquisition, daemon=True).start()
    threading.Thread(target=crow_detection.run_detection, daemon=True).start()
    threading.Thread(target=crow_llm_intelligence.run_llm_intelligence, daemon=True).start()
    
    print("--- Crow System Online. API at http://localhost:8000 ---")
    uvicorn.run(app, host="0.0.0.0", port=8000)