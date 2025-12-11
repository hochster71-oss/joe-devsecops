import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';
import { Eye, EyeOff, AlertCircle, Loader2, Lock, User } from 'lucide-react';
import { motion } from 'framer-motion';

export default function LoginView() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);

  const { login, isLoading, error, clearError, isAuthenticated } = useAuthStore();
  const navigate = useNavigate();

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  // Clear error when inputs change
  useEffect(() => {
    if (error) clearError();
  }, [username, password]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const success = await login(username, password);
    if (success) {
      navigate('/dashboard', { replace: true });
    }
  };

  return (
    <div className="h-screen w-screen bg-dws-darker flex">
      {/* Left Panel - Branding */}
      <div className="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-dws-dark via-dws-darker to-[#0a0a0a] p-12 flex-col justify-between relative overflow-hidden">
        {/* Animated Background Grid */}
        <div className="absolute inset-0 opacity-[0.03]">
          <svg className="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
            <pattern id="grid" width="8" height="8" patternUnits="userSpaceOnUse">
              <path d="M 8 0 L 0 0 0 8" fill="none" stroke="#87C549" strokeWidth="0.3"/>
            </pattern>
            <rect width="100%" height="100%" fill="url(#grid)" />
          </svg>
        </div>

        {/* Gradient Orbs */}
        <div className="absolute top-20 left-20 w-64 h-64 bg-dws-green/10 rounded-full blur-3xl" />
        <div className="absolute bottom-40 right-20 w-96 h-96 bg-joe-blue/5 rounded-full blur-3xl" />

        {/* Official Dark Wolf Solutions Logo */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="relative z-10"
        >
          <img
            src="/src/renderer/assets/dark-wolf-logo.png"
            alt="Dark Wolf Solutions"
            className="max-w-[300px] h-auto"
          />
        </motion.div>

        {/* Center Content - J.O.E. Branding */}
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2, duration: 0.6 }}
          className="relative z-10 text-center"
        >
          <div className="mb-6">
            <h1 className="font-heading text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-joe-blue to-joe-blue-light tracking-tight">
              J.O.E.
            </h1>
            <p className="text-lg text-gray-400 mt-2 tracking-wide">
              Joint Operations Engine
            </p>
          </div>

          <p className="text-gray-500 max-w-md mx-auto leading-relaxed">
            AI-Driven DevSecOps Arsenal for comprehensive security scanning,
            compliance monitoring, and threat intelligence.
          </p>

          {/* Feature Pills */}
          <div className="flex flex-wrap justify-center gap-2 mt-8">
            {['Security Scanning', 'SBOM Analysis', 'Compliance', 'AI Assistant'].map((feature, i) => (
              <motion.span
                key={feature}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 + i * 0.1 }}
                className="px-3 py-1 text-xs font-medium text-dws-green bg-dws-green/10 border border-dws-green/20 rounded-full"
              >
                {feature}
              </motion.span>
            ))}
          </div>
        </motion.div>

        {/* Footer */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
          className="relative z-10"
        >
          <p className="text-dws-green/60 text-sm font-medium">
            "No Lone Wolf - Together, a pack"
          </p>
          <p className="text-gray-700 text-xs mt-2">
            © 2025 Dark Wolf Solutions. All rights reserved.
          </p>
        </motion.div>
      </div>

      {/* Right Panel - Login Form */}
      <div className="flex-1 flex items-center justify-center p-8 bg-gradient-to-b from-dws-darker to-dws-dark">
        <motion.div
          initial={{ x: 20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ duration: 0.5 }}
          className="w-full max-w-md"
        >
          {/* Mobile Logo */}
          <div className="lg:hidden text-center mb-8">
            <img
              src="/src/renderer/assets/dark-wolf-logo.png"
              alt="Dark Wolf Solutions"
              className="max-w-[200px] h-auto mx-auto mb-4"
            />
            <h2 className="font-heading text-2xl font-bold text-joe-blue">J.O.E.</h2>
            <p className="text-gray-400 text-sm">DevSecOps Arsenal</p>
          </div>

          {/* Login Card */}
          <div className="bg-dws-card/50 backdrop-blur-xl border border-dws-border/50 rounded-2xl p-8 shadow-2xl">
            {/* Header */}
            <div className="text-center mb-8">
              <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-joe-blue/20 to-joe-blue/5 border border-joe-blue/20 flex items-center justify-center">
                <Lock className="w-8 h-8 text-joe-blue" />
              </div>
              <h2 className="font-heading text-2xl font-bold text-white">
                Secure Access
              </h2>
              <p className="text-gray-500 text-sm mt-1">
                Sign in to your dashboard
              </p>
            </div>

            {/* Error Message */}
            {error && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                className="mb-6 p-4 rounded-xl bg-alert-critical/10 border border-alert-critical/30 flex items-center gap-3"
              >
                <AlertCircle className="text-alert-critical flex-shrink-0" size={20} />
                <p className="text-alert-critical text-sm">{error}</p>
              </motion.div>
            )}

            <form onSubmit={handleSubmit} className="space-y-5">
              {/* Username */}
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-400 mb-2">
                  Username
                </label>
                <div className="relative">
                  <User className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
                  <input
                    id="username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full bg-dws-dark/50 border border-dws-border rounded-xl py-3 pl-12 pr-4 text-white placeholder-gray-600 focus:outline-none focus:border-joe-blue/50 focus:ring-1 focus:ring-joe-blue/50 transition-all"
                    placeholder="Enter username"
                    autoComplete="username"
                    required
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-400 mb-2">
                  Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-dws-dark/50 border border-dws-border rounded-xl py-3 pl-12 pr-12 text-white placeholder-gray-600 focus:outline-none focus:border-joe-blue/50 focus:ring-1 focus:ring-joe-blue/50 transition-all"
                    placeholder="Enter password"
                    autoComplete="current-password"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>

              {/* Remember Me */}
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-2 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="w-4 h-4 rounded border-dws-border bg-dws-dark text-joe-blue focus:ring-joe-blue focus:ring-offset-0"
                  />
                  <span className="text-sm text-gray-500 group-hover:text-gray-400 transition-colors">Remember me</span>
                </label>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isLoading || !username || !password}
                className="w-full bg-gradient-to-r from-joe-blue to-joe-blue-light hover:from-joe-blue-light hover:to-joe-blue text-white font-semibold py-3.5 rounded-xl flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-lg shadow-joe-blue/20 hover:shadow-joe-blue/30"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="animate-spin" size={20} />
                    <span>Authenticating...</span>
                  </>
                ) : (
                  <span>Sign In</span>
                )}
              </button>
            </form>
          </div>

          {/* Footer Attribution */}
          <div className="text-center mt-8 space-y-2">
            <p className="text-gray-500 text-sm font-medium">
              Michael Hoch
            </p>
            <p className="text-joe-blue text-xs">
              michael.hoch@darkwolfsolutions.com
            </p>
            <p className="text-gray-600 text-xs">
              Cybersecurity SME • Dark Wolf Solutions
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
