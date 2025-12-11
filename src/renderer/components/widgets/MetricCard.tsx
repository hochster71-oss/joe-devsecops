import { LucideIcon, TrendingUp, TrendingDown } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string;
  subtitle?: string;
  icon: LucideIcon;
  color?: 'success' | 'warning' | 'critical' | 'info';
  trend?: 'up' | 'down';
  trendValue?: string;
  pulse?: boolean;
}

export default function MetricCard({
  title,
  value,
  subtitle,
  icon: Icon,
  color = 'info',
  trend,
  trendValue,
  pulse = false
}: MetricCardProps) {
  const colorClasses = {
    success: {
      bg: 'bg-dws-green/10',
      text: 'text-dws-green',
      border: 'border-dws-green/30',
      glow: 'shadow-glow-green'
    },
    warning: {
      bg: 'bg-alert-warning/10',
      text: 'text-alert-warning',
      border: 'border-alert-warning/30',
      glow: ''
    },
    critical: {
      bg: 'bg-alert-critical/10',
      text: 'text-alert-critical',
      border: 'border-alert-critical/30',
      glow: 'shadow-glow-critical'
    },
    info: {
      bg: 'bg-joe-blue/10',
      text: 'text-joe-blue',
      border: 'border-joe-blue/30',
      glow: 'shadow-glow-blue'
    }
  };

  const colors = colorClasses[color];

  return (
    <div
      className={`
        metric-card relative overflow-hidden
        ${pulse ? 'animate-pulse' : ''}
        ${pulse && color === 'critical' ? colors.glow : ''}
      `}
    >
      {/* Background Gradient */}
      <div className={`absolute inset-0 ${colors.bg} opacity-50`} />

      {/* Content */}
      <div className="relative z-10">
        <div className="flex items-start justify-between mb-4">
          <div className={`p-2 rounded-lg ${colors.bg} ${colors.border} border`}>
            <Icon size={20} className={colors.text} />
          </div>

          {trend && trendValue && (
            <div className={`flex items-center gap-1 text-sm ${
              trend === 'up' ? 'text-dws-green' : 'text-alert-critical'
            }`}>
              {trend === 'up' ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
              <span>{trendValue}</span>
            </div>
          )}
        </div>

        <p className="text-gray-400 text-sm mb-1">{title}</p>
        <p className={`text-3xl font-bold ${colors.text}`}>{value}</p>

        {subtitle && (
          <p className="text-gray-500 text-xs mt-2">{subtitle}</p>
        )}
      </div>

      {/* Decorative Element */}
      <div className={`absolute -bottom-4 -right-4 w-24 h-24 rounded-full ${colors.bg} opacity-20`} />
    </div>
  );
}
