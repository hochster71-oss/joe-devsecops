import { ReactNode, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X } from 'lucide-react';

/**
 * Advanced Modal System for J.O.E. DevSecOps Platform
 *
 * Features:
 * - Glassmorphism design with backdrop blur
 * - Smooth spring animations with framer-motion
 * - Keyboard accessibility (Escape to close)
 * - Click outside to close
 * - Multiple size variants
 * - Customizable header/footer
 *
 * Reference: Framer Motion best practices
 * https://www.framer.com/motion/animation/
 */

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  subtitle?: string;
  children: ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
  showCloseButton?: boolean;
  footer?: ReactNode;
  headerIcon?: ReactNode;
  variant?: 'default' | 'critical' | 'warning' | 'success' | 'info';
}

const sizeClasses = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
  full: 'max-w-[90vw] h-[90vh]'
};

const variantClasses = {
  default: {
    header: 'border-dws-border',
    accent: 'bg-joe-blue/10 border-joe-blue/30',
    iconColor: 'text-joe-blue'
  },
  critical: {
    header: 'border-alert-critical/30',
    accent: 'bg-alert-critical/10 border-alert-critical/30',
    iconColor: 'text-alert-critical'
  },
  warning: {
    header: 'border-alert-warning/30',
    accent: 'bg-alert-warning/10 border-alert-warning/30',
    iconColor: 'text-alert-warning'
  },
  success: {
    header: 'border-dws-green/30',
    accent: 'bg-dws-green/10 border-dws-green/30',
    iconColor: 'text-dws-green'
  },
  info: {
    header: 'border-joe-blue/30',
    accent: 'bg-joe-blue/10 border-joe-blue/30',
    iconColor: 'text-joe-blue'
  }
};

// Animation variants for the backdrop
const backdropVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1 }
};

// Animation variants for the modal with spring physics
const modalVariants = {
  hidden: {
    opacity: 0,
    scale: 0.8,
    y: 50
  },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 300
    }
  },
  exit: {
    opacity: 0,
    scale: 0.9,
    y: 30,
    transition: {
      duration: 0.2
    }
  }
};

export default function Modal({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  size = 'md',
  showCloseButton = true,
  footer,
  headerIcon,
  variant = 'default'
}: ModalProps) {
  const styles = variantClasses[variant];

  // Handle escape key
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose();
    }
  }, [onClose]);

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, handleKeyDown]);

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Backdrop with blur effect */}
          <motion.div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            variants={backdropVariants}
            initial="hidden"
            animate="visible"
            exit="hidden"
            onClick={onClose}
          />

          {/* Modal Container */}
          <motion.div
            className={`
              relative w-full ${sizeClasses[size]}
              bg-dws-card/95 backdrop-blur-xl
              border border-dws-border/50
              rounded-2xl shadow-2xl
              overflow-hidden
              ${size === 'full' ? 'flex flex-col' : ''}
            `}
            variants={modalVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Decorative gradient accent */}
            <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-joe-blue via-dws-green to-joe-blue`} />

            {/* Header */}
            {(title || showCloseButton) && (
              <div className={`flex items-start justify-between p-6 border-b ${styles.header}`}>
                <div className="flex items-center gap-4">
                  {headerIcon && (
                    <div className={`p-3 rounded-xl ${styles.accent} border`}>
                      <div className={styles.iconColor}>{headerIcon}</div>
                    </div>
                  )}
                  <div>
                    {title && (
                      <h2 className="font-heading text-xl font-bold text-white">
                        {title}
                      </h2>
                    )}
                    {subtitle && (
                      <p className="text-gray-400 text-sm mt-1">{subtitle}</p>
                    )}
                  </div>
                </div>

                {showCloseButton && (
                  <motion.button
                    onClick={onClose}
                    className="p-2 rounded-lg hover:bg-dws-elevated transition-colors"
                    whileHover={{ scale: 1.1 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <X size={20} className="text-gray-400" />
                  </motion.button>
                )}
              </div>
            )}

            {/* Content */}
            <div className={`p-6 ${size === 'full' ? 'flex-1 overflow-y-auto' : 'max-h-[60vh] overflow-y-auto'}`}>
              {children}
            </div>

            {/* Footer */}
            {footer && (
              <div className="p-6 border-t border-dws-border bg-dws-dark/50">
                {footer}
              </div>
            )}
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}

/**
 * Confirmation Modal - Specialized variant for confirmations
 */
interface ConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  variant?: 'danger' | 'warning' | 'info';
  isLoading?: boolean;
}

export function ConfirmModal({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  variant = 'info',
  isLoading = false
}: ConfirmModalProps) {
  const buttonVariant = {
    danger: 'bg-alert-critical hover:bg-alert-critical/80',
    warning: 'bg-alert-warning hover:bg-alert-warning/80 text-black',
    info: 'bg-joe-blue hover:bg-joe-blue-light'
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      size="sm"
      variant={variant === 'danger' ? 'critical' : variant === 'warning' ? 'warning' : 'info'}
      footer={
        <div className="flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="btn-secondary"
            disabled={isLoading}
          >
            {cancelText}
          </button>
          <button
            onClick={onConfirm}
            className={`px-4 py-2 rounded-lg font-medium text-white transition-colors ${buttonVariant[variant]}`}
            disabled={isLoading}
          >
            {isLoading ? 'Processing...' : confirmText}
          </button>
        </div>
      }
    >
      <p className="text-gray-300">{message}</p>
    </Modal>
  );
}
