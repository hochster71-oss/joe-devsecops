/**
 * J.O.E. AI Neural Network Background
 *
 * Advanced animated background with neural network visualization,
 * particle effects, and cyberpunk aesthetics for 4K displays.
 */

import { useEffect, useRef } from 'react';

interface Node {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  pulsePhase: number;
  type: 'core' | 'node' | 'particle';
}

interface Connection {
  from: number;
  to: number;
  strength: number;
  active: boolean;
  pulseProgress: number;
}

export default function AINetworkBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const animationRef = useRef<number>();
  const nodesRef = useRef<Node[]>([]);
  const connectionsRef = useRef<Connection[]>([]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) {return;}

    const ctx = canvas.getContext('2d');
    if (!ctx) {return;}

    // Set canvas size based on container (not window)
    const resize = () => {
      const rect = container.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      canvas.style.width = `${rect.width}px`;
      canvas.style.height = `${rect.height}px`;
      ctx.scale(dpr, dpr);
      initializeNetwork();
    };

    // Initialize neural network nodes
    const initializeNetwork = () => {
      const rect = container.getBoundingClientRect();
      const width = rect.width;
      const height = rect.height;
      const nodes: Node[] = [];

      // Core AI nodes (larger, more prominent)
      for (let i = 0; i < 5; i++) {
        nodes.push({
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * 0.3,
          vy: (Math.random() - 0.5) * 0.3,
          radius: 4 + Math.random() * 3,
          pulsePhase: Math.random() * Math.PI * 2,
          type: 'core'
        });
      }

      // Network nodes
      for (let i = 0; i < 30; i++) {
        nodes.push({
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * 0.5,
          vy: (Math.random() - 0.5) * 0.5,
          radius: 2 + Math.random() * 2,
          pulsePhase: Math.random() * Math.PI * 2,
          type: 'node'
        });
      }

      // Particles (smallest, fastest)
      for (let i = 0; i < 50; i++) {
        nodes.push({
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * 1,
          vy: (Math.random() - 0.5) * 1,
          radius: 1 + Math.random(),
          pulsePhase: Math.random() * Math.PI * 2,
          type: 'particle'
        });
      }

      nodesRef.current = nodes;

      // Create connections
      const connections: Connection[] = [];
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          if (Math.random() > 0.95) {
            connections.push({
              from: i,
              to: j,
              strength: Math.random(),
              active: Math.random() > 0.7,
              pulseProgress: Math.random()
            });
          }
        }
      }
      connectionsRef.current = connections;
    };

    // Animation loop
    const animate = () => {
      const rect = container.getBoundingClientRect();
      const width = rect.width;
      const height = rect.height;

      // Clear with fade effect for trails
      ctx.fillStyle = 'rgba(10, 15, 28, 0.1)';
      ctx.fillRect(0, 0, width, height);

      const nodes = nodesRef.current;
      const connections = connectionsRef.current;
      const time = Date.now() * 0.001;

      // Update and draw connections
      connections.forEach(conn => {
        const from = nodes[conn.from];
        const to = nodes[conn.to];
        const dx = to.x - from.x;
        const dy = to.y - from.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 300) {
          conn.pulseProgress += 0.01;
          if (conn.pulseProgress > 1) {conn.pulseProgress = 0;}

          const alpha = (1 - dist / 300) * 0.3 * conn.strength;

          // Draw connection line
          const gradient = ctx.createLinearGradient(from.x, from.y, to.x, to.y);
          gradient.addColorStop(0, `rgba(0, 180, 216, ${alpha})`);
          gradient.addColorStop(0.5, `rgba(0, 180, 216, ${alpha * 1.5})`);
          gradient.addColorStop(1, `rgba(34, 197, 94, ${alpha})`);

          ctx.beginPath();
          ctx.moveTo(from.x, from.y);
          ctx.lineTo(to.x, to.y);
          ctx.strokeStyle = gradient;
          ctx.lineWidth = conn.strength * 1.5;
          ctx.stroke();

          // Draw pulse traveling along connection
          if (conn.active) {
            const pulseX = from.x + dx * conn.pulseProgress;
            const pulseY = from.y + dy * conn.pulseProgress;

            ctx.beginPath();
            ctx.arc(pulseX, pulseY, 2, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(0, 180, 216, ${0.8})`;
            ctx.fill();
          }
        }
      });

      // Update and draw nodes
      nodes.forEach((node, _i) => {
        // Update position
        node.x += node.vx;
        node.y += node.vy;

        // Bounce off edges
        if (node.x < 0 || node.x > width) {node.vx *= -1;}
        if (node.y < 0 || node.y > height) {node.vy *= -1;}

        // Keep in bounds
        node.x = Math.max(0, Math.min(width, node.x));
        node.y = Math.max(0, Math.min(height, node.y));

        // Calculate pulse
        const pulse = Math.sin(time * 2 + node.pulsePhase) * 0.5 + 0.5;
        const glowRadius = node.radius * (1 + pulse * 0.5);

        // Draw glow
        const gradient = ctx.createRadialGradient(
          node.x, node.y, 0,
          node.x, node.y, glowRadius * 4
        );

        if (node.type === 'core') {
          gradient.addColorStop(0, 'rgba(0, 180, 216, 0.8)');
          gradient.addColorStop(0.5, 'rgba(0, 180, 216, 0.2)');
          gradient.addColorStop(1, 'rgba(0, 180, 216, 0)');
        } else if (node.type === 'node') {
          gradient.addColorStop(0, 'rgba(34, 197, 94, 0.6)');
          gradient.addColorStop(0.5, 'rgba(34, 197, 94, 0.1)');
          gradient.addColorStop(1, 'rgba(34, 197, 94, 0)');
        } else {
          gradient.addColorStop(0, 'rgba(255, 255, 255, 0.4)');
          gradient.addColorStop(1, 'rgba(255, 255, 255, 0)');
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, glowRadius * 4, 0, Math.PI * 2);
        ctx.fillStyle = gradient;
        ctx.fill();

        // Draw core
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        if (node.type === 'core') {
          ctx.fillStyle = '#00b4d8';
          ctx.shadowColor = '#00b4d8';
          ctx.shadowBlur = 20;
        } else if (node.type === 'node') {
          ctx.fillStyle = '#22c55e';
          ctx.shadowColor = '#22c55e';
          ctx.shadowBlur = 10;
        } else {
          ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
          ctx.shadowBlur = 0;
        }
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      // Draw hexagon grid overlay (subtle)
      drawHexGrid(ctx, width, height, time);

      animationRef.current = requestAnimationFrame(animate);
    };

    // Draw subtle hex grid
    const drawHexGrid = (ctx: CanvasRenderingContext2D, width: number, height: number, time: number) => {
      const size = 60;
      const h = size * Math.sqrt(3);

      ctx.strokeStyle = 'rgba(0, 180, 216, 0.03)';
      ctx.lineWidth = 1;

      for (let row = -1; row < height / h + 1; row++) {
        for (let col = -1; col < width / (size * 1.5) + 1; col++) {
          const x = col * size * 1.5;
          const y = row * h + (col % 2 ? h / 2 : 0);

          // Subtle wave animation
          const wave = Math.sin(time * 0.5 + col * 0.1 + row * 0.1) * 0.02;
          ctx.strokeStyle = `rgba(0, 180, 216, ${0.03 + wave})`;

          drawHexagon(ctx, x, y, size * 0.9);
        }
      }
    };

    const drawHexagon = (ctx: CanvasRenderingContext2D, x: number, y: number, size: number) => {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const angle = (Math.PI / 3) * i - Math.PI / 6;
        const hx = x + size * Math.cos(angle);
        const hy = y + size * Math.sin(angle);
        if (i === 0) {ctx.moveTo(hx, hy);}
        else {ctx.lineTo(hx, hy);}
      }
      ctx.closePath();
      ctx.stroke();
    };

    resize();
    window.addEventListener('resize', resize);
    animate();

    return () => {
      window.removeEventListener('resize', resize);
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, []);

  return (
    <div ref={containerRef} className="absolute inset-0 overflow-hidden">
      <canvas
        ref={canvasRef}
        className="absolute inset-0 pointer-events-none"
        style={{ zIndex: 0 }}
      />
      {/* Gradient overlays for depth */}
      <div className="absolute inset-0 pointer-events-none" style={{ zIndex: 1 }}>
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-dws-bg/80" />
        <div className="absolute inset-0 bg-gradient-to-r from-dws-bg/50 via-transparent to-dws-bg/50" />
        {/* Vignette effect */}
        <div
          className="absolute inset-0"
          style={{
            background: 'radial-gradient(ellipse at center, transparent 0%, rgba(10, 15, 28, 0.4) 100%)'
          }}
        />
      </div>
    </div>
  );
}
