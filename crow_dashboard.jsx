// Inside CrowDashboard component:
const [stats, setStats] = useState(null);

useEffect(() => {
  const fetchData = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/stats');
      const data = await res.json();
      setStats(data);
    } catch (err) {
      console.error("Backend unreachable", err);
    }
  };
  fetchData();
  const interval = setInterval(fetchData, 5000); // Refresh every 5s
  return () => clearInterval(interval);
}, []);