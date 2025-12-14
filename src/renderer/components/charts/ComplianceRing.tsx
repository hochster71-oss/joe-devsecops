import { motion } from 'framer-motion';
import { ComplianceStatus } from '../../store/dashboardStore';

interface ComplianceRingProps {
  compliance: ComplianceStatus;
}

export default function ComplianceRing({ compliance }: ComplianceRingProps) {
  const { score, level, totalControls, compliant, partiallyCompliant, nonCompliant, notAssessed } = compliance;

  // Ring properties
  const radius = 70;
  const strokeWidth = 12;
  const circumference = 2 * Math.PI * radius;
  const scoreOffset = circumference - (score / 100) * circumference;

  const getScoreColor = () => {
    if (score >= 80) {return '#87C549';}
    if (score >= 60) {return '#FFB000';}
    return '#FF3366';
  };

  const getLevelLabel = () => {
    switch (level) {
      case 1: return 'Level 1 - Foundational';
      case 2: return 'Level 2 - Advanced';
      case 3: return 'Level 3 - Expert';
      default: return 'Not Assessed';
    }
  };

  const stats = [
    { label: 'Compliant', value: compliant, color: '#87C549' },
    { label: 'Partial', value: partiallyCompliant, color: '#FFB000' },
    { label: 'Non-Compliant', value: nonCompliant, color: '#FF3366' },
    { label: 'Not Assessed', value: notAssessed, color: '#6B7280' }
  ];

  return (
    <div className="flex flex-col items-center">
      {/* Ring Chart */}
      <div className="relative w-44 h-44">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 180 180">
          {/* Background ring */}
          <circle
            cx="90"
            cy="90"
            r={radius}
            fill="none"
            stroke="#343434"
            strokeWidth={strokeWidth}
          />

          {/* Score ring */}
          <motion.circle
            cx="90"
            cy="90"
            r={radius}
            fill="none"
            stroke={getScoreColor()}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: scoreOffset }}
            transition={{ duration: 1.5, ease: 'easeOut' }}
            style={{
              filter: `drop-shadow(0 0 8px ${getScoreColor()}40)`
            }}
          />
        </svg>

        {/* Center Content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.p
            className="text-4xl font-bold"
            style={{ color: getScoreColor() }}
            initial={{ scale: 0.5, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            {score}%
          </motion.p>
          <p className="text-xs text-gray-500 mt-1">Compliance Score</p>
        </div>
      </div>

      {/* Level Badge */}
      <motion.div
        className="mt-4 px-4 py-1.5 rounded-full border text-sm font-medium"
        style={{
          backgroundColor: `${getScoreColor()}15`,
          borderColor: `${getScoreColor()}30`,
          color: getScoreColor()
        }}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
      >
        {getLevelLabel()}
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 gap-3 mt-4 w-full">
        {stats.map((stat, index) => (
          <motion.div
            key={stat.label}
            className="flex items-center gap-2 p-2 rounded-lg bg-dws-card/50"
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.8 + index * 0.1 }}
          >
            <div
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: stat.color }}
            />
            <div>
              <p className="text-xs text-gray-500">{stat.label}</p>
              <p className="font-semibold text-white">{stat.value}</p>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Total Controls */}
      <p className="text-xs text-gray-500 mt-4">
        {totalControls} Total Controls
      </p>
    </div>
  );
}
