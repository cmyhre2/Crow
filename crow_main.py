import threading
import uvicorn
from fastapi import FastAPI
import crow_data_acquisition
import crow_detection
import crow_llm_intelligence
from crow_storage import bootstrap_db, setup_logging, get_all_alerts
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# ... API endpoints ...
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- API Routes ---
@app.get("/alerts")
def get_alerts():
    """Fetches the latest alerts from the database."""
    try:
        alerts = get_all_alerts()
        return alerts
    except Exception as e:
        return {"error": str(e)}
    
@app.get("/metrics")
def get_dashboard_metrics():
    """Returns aggregated data for dashboard tiles."""
    from crow_storage import get_metrics
    return get_metrics()

@app.get("/reports")
def get_reports():
    """Endpoint for the Intelligence Reports feed."""
    from crow_storage import get_recent_reports
    return get_recent_reports()

if __name__ == "__main__":
    print("--- Crow System Initializing ---")
    setup_logging()
    bootstrap_db()
    
    threading.Thread(target=crow_data_acquisition.run_data_acquisition, daemon=True).start()
    threading.Thread(target=crow_detection.run_detection, daemon=True).start()
    threading.Thread(target=crow_llm_intelligence.run_llm_intelligence, daemon=True).start()
    
    print("--- Crow System Online. API at http://localhost:8000 ---")
    uvicorn.run(app, host="0.0.0.0", port=8000)