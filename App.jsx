import React, { useState, useEffect } from 'react';

function App() {
  const [alerts, setAlerts] = useState([]);
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const [alertsRes, reportsRes] = await Promise.all([
        fetch('http://localhost:8000/alerts'),
        fetch('http://localhost:8000/reports')
      ]);
      const alertsData = await alertsRes.json();
      const reportsData = await reportsRes.json();
      setAlerts(alertsData);
      setReports(reportsData);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching dashboard data:", error);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={styles.appContainer}>
      {/* Top Section */}
      <div style={styles.stickyHeader}>
        <h1 style={{ margin: '0 0 20px 0' }}>Crow Security Dashboard</h1>
        <DashboardMetrics />
        <hr style={{ margin: '20px 0 0 0', border: '0', borderTop: '1px solid #ddd' }} />
      </div>

      {/* Scrollable Feed Section */}
      <div style={styles.feedGrid}>
        
        {/* Left Column: Alerts */}
        <section style={styles.scrollColumn}>
          <h2 style={styles.columnTitle}>Live Security Alerts</h2>
          {loading ? <p>Loading alerts...</p> : (
            <ul style={{ listStyle: 'none', padding: 0 }}>
              {alerts.map((alert) => (
                <li key={alert.id} style={styles.card}>
                  <strong style={{ color: alert.alert_type === 'PORT_SCAN' ? '#d32f2f' : '#1976d2' }}>
                    {alert.alert_type}
                  </strong> - {alert.description} 
                  <br/>
                  <small style={{ color: '#666' }}>Time: {new Date(alert.created_at).toLocaleString()}</small>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* Right Column: Reports */}
<section style={styles.scrollColumn}>
  <h2 style={styles.columnTitle}>Intelligence Reports (Llama3)</h2>
  {reports.length === 0 ? <p style={{color: '#888'}}>Waiting for AI analysis...</p> : (
    reports.map((rep) => (
      <div key={rep.id} style={{ ...styles.card, borderLeft: '5px solid #7b1fa2' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <strong style={{ fontWeight: '500' }}>{rep.alert_type}</strong>
          <small style={{ color: '#888' }}>
            {new Date(rep.created_at).toLocaleString([], { 
              year: 'numeric', 
              month: 'short', 
              day: 'numeric', 
              hour: '2-digit', 
              minute: '2-digit',
              second: '2-digit'
            })}
          </small>
        </div>
        <p style={{ fontSize: '0.9em', color: '#444', margin: '10px 0', fontWeight: '400' }}>
          {rep.description}
        </p>
        
        <details style={{ marginTop: '10px', cursor: 'pointer' }}>
          <summary style={{ color: '#7b1fa2', fontWeight: '400', fontSize: '0.85em' }}>
            VIEW AI ANALYSIS
          </summary>
          <div style={styles.reportBox}>
            {rep.report}
          </div>
        </details>
      </div>
    ))
  )}
</section>
      </div>
    </div>
  );
}

const styles = {
  appContainer: {
    fontFamily: 'sans-serif',
    backgroundColor: '#f1f3f5',
    height: '100vh',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden'
  },
  stickyHeader: {
    padding: '20px 40px',
    backgroundColor: 'white',
    boxShadow: '0 2px 10px rgba(0,0,0,0.05)',
    zIndex: 100
  },
  feedGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '20px',
    padding: '20px 40px',
    flex: 1,
    overflow: 'hidden'
  },
  scrollColumn: {
    overflowY: 'auto',
    paddingRight: '10px',
    height: '100%' 
  },
  columnTitle: {
    position: 'sticky',
    top: 0,
    backgroundColor: '#f1f3f5',
    padding: '10px 0',
    margin: 0,
    zIndex: 10
  },
  card: {
    backgroundColor: 'white',
    marginBottom: '15px',
    padding: '20px',
    borderRadius: '10px',
    boxShadow: '0 4px 6px rgba(0,0,0,0.02)',
  },
  reportBox: {
    marginTop: '10px',
    padding: '15px',
    backgroundColor: '#2d3436',
    color: '#dfe6e9',
    borderRadius: '6px',
    whiteSpace: 'pre-wrap',
    fontSize: '0.9em',
    lineHeight: '1.5',
    fontFamily: 'Consolas, monospace'
  }
};

function DashboardMetrics() {
    const [metrics, setMetrics] = useState({ 
      packets_10min: 0, 
      packets_1h: 0, 
      port_scans_10min: 0, 
      top_ip: 'N/A', 
      top_protocol: 'N/A' 
    });
  
    const fetchMetrics = () => {
      fetch('http://localhost:8000/metrics')
        .then(res => res.json())
        .then(data => setMetrics(data))
        .catch(err => console.error("Metrics fetch error:", err));
    };
  
    useEffect(() => {
      fetchMetrics();
      const interval = setInterval(fetchMetrics, 5000);
      return () => clearInterval(interval);
    }, []);
  
    return (
      <div style={{ display: 'flex', gap: '20px', flexWrap: 'nowrap', overflowX: 'auto' }}>
        <MetricCard title="Port Scans (10m)" value={metrics.port_scans_10min} color="#d32f2f" />
        <MetricCard title="Packets (10m)" value={metrics.packets_10min} color="#1976d2" />
        <MetricCard title="Packets (1h)" value={metrics.packets_1h} color="#388e3c" />
        <MetricCard title="Top Source IP" value={metrics.top_ip} color="#f57c00" />
        <MetricCard title="Top Protocol" value={metrics.top_protocol} color="#7b1fa2" />
      </div>
    );
  }
  
  function MetricCard({ title, value, color }) {
  return (
    <div style={{ 
      border: '1px solid #eee', 
      padding: '15px 20px', 
      borderRadius: '10px', 
      minWidth: '180px',
      backgroundColor: 'white',
      boxShadow: '0 2px 4px rgba(0,0,0,0.02)',
      borderTop: `5px solid ${color || '#ccc'}`
    }}>
      <h3 style={{ 
        margin: '0 0 8px 0', 
        fontSize: '0.8em', 
        color: '#888', 
        textTransform: 'uppercase', 
        letterSpacing: '0.5px',
        fontWeight: '400'
      }}>
        {title}
      </h3>
      <p style={{ 
        fontSize: '1.6em', 
        margin: 0, 
        color: '#2d3436',
        fontWeight: '400'
      }}>
        {value}
      </p>
    </div>
  );
}

export default App;