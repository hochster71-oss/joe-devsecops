import { motion } from 'framer-motion';

interface SeverityData {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
}

interface SeverityChartProps {
  data: SeverityData;
}

export default function SeverityChart({ data }: SeverityChartProps) {
  const total = data.critical + data.high + data.medium + data.low + (data.info || 0);

  const severities = [
    { key: 'critical', label: 'Critical', value: data.critical, color: '#FF3366' },
    { key: 'high', label: 'High', value: data.high, color: '#FF6B35' },
    { key: 'medium', label: 'Medium', value: data.medium, color: '#FFB000' },
    { key: 'low', label: 'Low', value: data.low, color: '#87C549' },
    ...(data.info ? [{ key: 'info', label: 'Info', value: data.info, color: '#6B7280' }] : [])
  ];

  const maxValue = Math.max(...severities.map(s => s.value), 1);

  return (
    <div className="space-y-4">
      {/* Bar Chart */}
      <div className="space-y-3">
        {severities.map((severity, index) => {
          const percentage = total > 0 ? (severity.value / total) * 100 : 0;
          const barWidth = (severity.value / maxValue) * 100;

          return (
            <div key={severity.key} className="space-y-1">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: severity.color }}
                  />
                  <span className="text-gray-300">{severity.label}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-white">{severity.value}</span>
                  <span className="text-gray-500 text-xs">({percentage.toFixed(0)}%)</span>
                </div>
              </div>

              {/* Bar */}
              <div className="h-2 bg-dws-card rounded-full overflow-hidden">
                <motion.div
                  className="h-full rounded-full"
                  style={{
                    backgroundColor: severity.color,
                    boxShadow: `0 0 10px ${severity.color}40`
                  }}
                  initial={{ width: 0 }}
                  animate={{ width: `${barWidth}%` }}
                  transition={{ duration: 0.8, delay: index * 0.1, ease: 'easeOut' }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Total */}
      <div className="pt-3 border-t border-dws-border">
        <div className="flex items-center justify-between">
          <span className="text-gray-400">Total Findings</span>
          <span className="text-2xl font-bold text-white">{total}</span>
        </div>
      </div>

      {/* Mini Pie Indicator */}
      <div className="flex justify-center pt-2">
        <svg width="60" height="60" viewBox="0 0 60 60">
          {(() => {
            let currentAngle = -90;
            return severities.map((severity, index) => {
              const percentage = total > 0 ? (severity.value / total) * 100 : 0;
              const angle = (percentage / 100) * 360;
              const startAngle = currentAngle;
              const endAngle = currentAngle + angle;
              currentAngle = endAngle;

              if (percentage === 0) {return null;}

              const startRad = (startAngle * Math.PI) / 180;
              const endRad = (endAngle * Math.PI) / 180;
              const largeArc = angle > 180 ? 1 : 0;

              const x1 = 30 + 25 * Math.cos(startRad);
              const y1 = 30 + 25 * Math.sin(startRad);
              const x2 = 30 + 25 * Math.cos(endRad);
              const y2 = 30 + 25 * Math.sin(endRad);

              return (
                <motion.path
                  key={severity.key}
                  d={`M 30 30 L ${x1} ${y1} A 25 25 0 ${largeArc} 1 ${x2} ${y2} Z`}
                  fill={severity.color}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.5 + index * 0.1 }}
                />
              );
            });
          })()}
          {/* Center circle */}
          <circle cx="30" cy="30" r="15" fill="#1E1E1E" />
          <text
            x="30"
            y="33"
            textAnchor="middle"
            fill="white"
            fontSize="12"
            fontWeight="bold"
          >
            {total}
          </text>
        </svg>
      </div>
    </div>
  );
}
