import { useState } from 'react';
import { motion } from 'framer-motion';
import { useAuthStore } from '../store/authStore';
import { Eye, EyeOff, AlertCircle, Loader2, Lock, Shield, CheckCircle, XCircle } from 'lucide-react';

interface PasswordRequirement {
  label: string;
  test: (password: string) => boolean;
}

const PASSWORD_REQUIREMENTS: PasswordRequirement[] = [
  { label: 'At least 15 characters', test: (p) => p.length >= 15 },
  { label: 'One uppercase letter', test: (p) => /[A-Z]/.test(p) },
  { label: 'One lowercase letter', test: (p) => /[a-z]/.test(p) },
  { label: 'One number', test: (p) => /[0-9]/.test(p) },
  { label: 'One special character (!@#$%^&*...)', test: (p) => /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(p) },
];

export default function PasswordChangeModal() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const { changePassword, isLoading, error, user, logout } = useAuthStore();

  const passwordsMatch = newPassword === confirmPassword && newPassword.length > 0;
  const allRequirementsMet = PASSWORD_REQUIREMENTS.every(req => req.test(newPassword));
  const canSubmit = passwordsMatch && allRequirementsMet && currentPassword.length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);

    if (!passwordsMatch) {
      setLocalError('New passwords do not match');
      return;
    }

    if (!allRequirementsMet) {
      setLocalError('Password does not meet DoD requirements');
      return;
    }

    const result = await changePassword(currentPassword, newPassword);
    if (result) {
      setSuccess(true);
      // Redirect to dashboard after short delay
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 1500);
    }
  };

  const displayError = localError || error;

  return (
    <div className="h-screen w-screen bg-dws-darker flex items-center justify-center p-8">
      <motion.div
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.3 }}
        className="w-full max-w-lg"
      >
        <div className="bg-dws-card/50 backdrop-blur-xl border border-dws-border/50 rounded-2xl p-8 shadow-2xl">
          {/* Header */}
          <div className="text-center mb-6">
            <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-alert-warning/20 to-alert-warning/5 border border-alert-warning/20 flex items-center justify-center">
              <Shield className="w-8 h-8 text-alert-warning" />
            </div>
            <h2 className="font-heading text-2xl font-bold text-white">
              Password Change Required
            </h2>
            <p className="text-gray-500 text-sm mt-1">
              Hi {user?.displayName || user?.username}, please set a new DoD-compliant password
            </p>
          </div>

          {/* Success Message */}
          {success && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              className="mb-6 p-4 rounded-xl bg-dws-green/10 border border-dws-green/30 flex items-center gap-3"
            >
              <CheckCircle className="text-dws-green flex-shrink-0" size={20} />
              <p className="text-dws-green text-sm">Password changed successfully! Redirecting...</p>
            </motion.div>
          )}

          {/* Error Message */}
          {displayError && !success && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              className="mb-6 p-4 rounded-xl bg-alert-critical/10 border border-alert-critical/30 flex items-start gap-3"
            >
              <AlertCircle className="text-alert-critical flex-shrink-0 mt-0.5" size={20} />
              <p className="text-alert-critical text-sm">{displayError}</p>
            </motion.div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Current Password */}
            <div>
              <label htmlFor="currentPassword" className="block text-sm font-medium text-gray-400 mb-2">
                Current Password
              </label>
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
                <input
                  id="currentPassword"
                  type={showCurrentPassword ? 'text' : 'password'}
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  className="w-full bg-dws-dark/50 border border-dws-border rounded-xl py-3 pl-12 pr-12 text-white placeholder-gray-600 focus:outline-none focus:border-joe-blue/50 focus:ring-1 focus:ring-joe-blue/50 transition-all"
                  placeholder="Enter current password"
                  required
                  disabled={success}
                />
                <button
                  type="button"
                  onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {showCurrentPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {/* New Password */}
            <div>
              <label htmlFor="newPassword" className="block text-sm font-medium text-gray-400 mb-2">
                New Password
              </label>
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
                <input
                  id="newPassword"
                  type={showNewPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full bg-dws-dark/50 border border-dws-border rounded-xl py-3 pl-12 pr-12 text-white placeholder-gray-600 focus:outline-none focus:border-joe-blue/50 focus:ring-1 focus:ring-joe-blue/50 transition-all"
                  placeholder="Enter new DoD-compliant password"
                  required
                  disabled={success}
                />
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {showNewPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {/* Password Requirements Checklist */}
            <div className="bg-dws-dark/30 rounded-xl p-4 border border-dws-border/50">
              <p className="text-xs font-medium text-gray-400 mb-3 flex items-center gap-2">
                <Shield size={14} />
                DoD Password Requirements (NIST SP 800-63B)
              </p>
              <div className="grid grid-cols-1 gap-2">
                {PASSWORD_REQUIREMENTS.map((req, i) => {
                  const met = req.test(newPassword);
                  return (
                    <div
                      key={i}
                      className={`flex items-center gap-2 text-xs ${
                        met ? 'text-dws-green' : 'text-gray-500'
                      }`}
                    >
                      {met ? (
                        <CheckCircle size={14} className="text-dws-green" />
                      ) : (
                        <XCircle size={14} className="text-gray-600" />
                      )}
                      {req.label}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Confirm Password */}
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-400 mb-2">
                Confirm New Password
              </label>
              <div className="relative">
                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
                <input
                  id="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className={`w-full bg-dws-dark/50 border rounded-xl py-3 pl-12 pr-12 text-white placeholder-gray-600 focus:outline-none focus:ring-1 transition-all ${
                    confirmPassword.length > 0
                      ? passwordsMatch
                        ? 'border-dws-green/50 focus:border-dws-green/50 focus:ring-dws-green/50'
                        : 'border-alert-critical/50 focus:border-alert-critical/50 focus:ring-alert-critical/50'
                      : 'border-dws-border focus:border-joe-blue/50 focus:ring-joe-blue/50'
                  }`}
                  placeholder="Confirm new password"
                  required
                  disabled={success}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
              {confirmPassword.length > 0 && !passwordsMatch && (
                <p className="text-alert-critical text-xs mt-2">Passwords do not match</p>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={!canSubmit || isLoading || success}
              className="w-full bg-gradient-to-r from-dws-green to-joe-blue hover:from-dws-green/90 hover:to-joe-blue/90 text-white font-semibold py-3.5 rounded-xl flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-lg shadow-dws-green/20"
            >
              {isLoading ? (
                <>
                  <Loader2 className="animate-spin" size={20} />
                  <span>Changing Password...</span>
                </>
              ) : (
                <>
                  <Shield size={20} />
                  <span>Set New Password</span>
                </>
              )}
            </button>

            {/* Logout Option */}
            <button
              type="button"
              onClick={logout}
              className="w-full text-gray-500 hover:text-gray-300 text-sm py-2 transition-colors"
            >
              Logout and cancel
            </button>
          </form>
        </div>

        {/* Footer */}
        <div className="text-center mt-6">
          <p className="text-gray-600 text-xs">
            DoD password policy requires strong passwords to protect sensitive information
          </p>
        </div>
      </motion.div>
    </div>
  );
}
