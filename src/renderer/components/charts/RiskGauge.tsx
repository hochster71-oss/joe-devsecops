import { motion } from 'framer-motion';

interface RiskGaugeProps {
  score: number; // 0-100, higher is better
}

export default function RiskGauge({ score }: RiskGaugeProps) {
  // Clamp score between 0 and 100
  const clampedScore = Math.max(0, Math.min(100, score));

  // Calculate rotation angle (180 deg arc)
  const rotation = (clampedScore / 100) * 180;

  // Determine color based on score
  const getColor = () => {
    if (clampedScore >= 80) {return '#87C549';} // Green
    if (clampedScore >= 60) {return '#FFB000';} // Warning
    if (clampedScore >= 40) {return '#FF6B35';} // High
    return '#FF3366'; // Critical
  };

  const getStatus = () => {
    if (clampedScore >= 80) {return 'Excellent';}
    if (clampedScore >= 60) {return 'Good';}
    if (clampedScore >= 40) {return 'Fair';}
    return 'Poor';
  };

  return (
    <div className="flex flex-col items-center">
      {/* Gauge */}
      <div className="relative w-48 h-28 overflow-hidden">
        {/* Background Arc */}
        <svg
          className="absolute inset-0 w-full h-full"
          viewBox="0 0 200 100"
          preserveAspectRatio="xMidYMax meet"
        >
          {/* Background track */}
          <path
            d="M 10 100 A 90 90 0 0 1 190 100"
            fill="none"
            stroke="#343434"
            strokeWidth="16"
            strokeLinecap="round"
          />

          {/* Score arc */}
          <motion.path
            d="M 10 100 A 90 90 0 0 1 190 100"
            fill="none"
            stroke={getColor()}
            strokeWidth="16"
            strokeLinecap="round"
            strokeDasharray="283" // Circumference of half circle (π * 90)
            initial={{ strokeDashoffset: 283 }}
            animate={{ strokeDashoffset: 283 - (283 * clampedScore) / 100 }}
            transition={{ duration: 1.5, ease: 'easeOut' }}
            style={{
              filter: `drop-shadow(0 0 8px ${getColor()}40)`
            }}
          />

          {/* Tick marks */}
          {[0, 25, 50, 75, 100].map((tick) => {
            const angle = (tick / 100) * 180;
            const radian = (angle - 180) * (Math.PI / 180);
            const x = 100 + 70 * Math.cos(radian);
            const y = 100 + 70 * Math.sin(radian);
            return (
              <text
                key={tick}
                x={x}
                y={y}
                textAnchor="middle"
                dominantBaseline="middle"
                fill="#6B7280"
                fontSize="10"
              >
                {tick}
              </text>
            );
          })}
        </svg>

        {/* Needle */}
        <motion.div
          className="absolute bottom-0 left-1/2 origin-bottom"
          style={{ width: '4px', height: '60px', marginLeft: '-2px' }}
          initial={{ rotate: -90 }}
          animate={{ rotate: rotation - 90 }}
          transition={{ duration: 1.5, ease: 'easeOut' }}
        >
          <div
            className="w-full h-full rounded-full"
            style={{
              background: `linear-gradient(to top, ${getColor()}, transparent)`
            }}
          />
        </motion.div>

        {/* Center Circle */}
        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 translate-y-1/2 w-6 h-6 rounded-full bg-dws-card border-2 border-dws-border" />
      </div>

      {/* Score Display */}
      <motion.div
        className="text-center mt-4"
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        <p className="text-4xl font-bold" style={{ color: getColor() }}>
          {clampedScore}%
        </p>
        <p className="text-gray-400 text-sm mt-1">{getStatus()}</p>
      </motion.div>

      {/* Legend */}
      <div className="flex items-center gap-4 mt-4 text-xs">
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-full bg-alert-critical" />
          <span className="text-gray-500">Poor</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-full bg-alert-warning" />
          <span className="text-gray-500">Fair</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-3 h-3 rounded-full bg-dws-green" />
          <span className="text-gray-500">Good</span>
        </div>
      </div>
    </div>
  );
}
