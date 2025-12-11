import { Shield, Activity, Clock, Wifi, WifiOff } from 'lucide-react';
import { useState, useEffect } from 'react';
import { useDashboardStore } from '../../store/dashboardStore';

export default function StatusBar() {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [ollamaConnected, setOllamaConnected] = useState(false);
  const { riskScore, lastScanTime } = useDashboardStore();

  // Update time every minute
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 60000);
    return () => clearInterval(timer);
  }, []);

  // Check Ollama connection
  useEffect(() => {
    const checkOllama = async () => {
      try {
        const response = await fetch('http://localhost:11434/api/tags');
        setOllamaConnected(response.ok);
      } catch {
        setOllamaConnected(false);
      }
    };

    checkOllama();
    const interval = setInterval(checkOllama, 30000);
    return () => clearInterval(interval);
  }, []);

  const getRiskColor = () => {
    if (riskScore.critical > 0) return 'text-alert-critical';
    if (riskScore.high > 0) return 'text-alert-high';
    if (riskScore.medium > 0) return 'text-alert-warning';
    return 'text-dws-green';
  };

  const getRiskLabel = () => {
    if (riskScore.critical > 0) return `${riskScore.critical} Critical`;
    if (riskScore.high > 0) return `${riskScore.high} High`;
    if (riskScore.medium > 0) return `${riskScore.medium} Medium`;
    return 'Secure';
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: true
    });
  };

  const formatLastScan = () => {
    if (!lastScanTime) return 'Never';
    const diff = Date.now() - new Date(lastScanTime).getTime();
    const minutes = Math.floor(diff / 60000);
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  };

  return (
    <footer className="h-6 bg-dws-darker border-t border-dws-border flex items-center justify-between px-4 text-xs">
      {/* Left: Risk Status */}
      <div className="flex items-center gap-4">
        <div className={`flex items-center gap-1.5 ${getRiskColor()}`}>
          <Shield size={12} />
          <span className="font-medium">{getRiskLabel()}</span>
        </div>

        <div className="flex items-center gap-1.5 text-gray-500">
          <Activity size={12} />
          <span>Last Scan: {formatLastScan()}</span>
        </div>
      </div>

      {/* Right: System Status */}
      <div className="flex items-center gap-4">
        {/* Ollama Status */}
        <div className={`flex items-center gap-1.5 ${ollamaConnected ? 'text-dws-green' : 'text-gray-500'}`}>
          {ollamaConnected ? <Wifi size={12} /> : <WifiOff size={12} />}
          <span>Ollama {ollamaConnected ? 'Connected' : 'Offline'}</span>
        </div>

        {/* Time */}
        <div className="flex items-center gap-1.5 text-gray-500">
          <Clock size={12} />
          <span>{formatTime(currentTime)}</span>
        </div>

        {/* Version */}
        <span className="text-gray-600">v1.0.0</span>
      </div>
    </footer>
  );
}
