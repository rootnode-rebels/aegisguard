// Ultra-Optimized, Silky Smooth Cyber Ambient Background
// Zero GPU/CPU hanging, zero shadowBlur bottlenecks, hardware accelerated

class CyberBackground {
  constructor() {
    this.canvas = document.getElementById('cyber-bg');
    if (!this.canvas) return;

    this.ctx = this.canvas.getContext('2d', { alpha: true });
    this.particles = [];
    this.mouse = { x: -1000, y: -1000, radius: 100 };
    this.maxParticles = 38; // Lightweight for 60-120fps
    this.maxDistance = 110;
    this.maxDistanceSq = this.maxDistance * this.maxDistance;
    this.animId = null;
    this.isPaused = false;

    this.init();
    
    // Throttled event listeners
    let resizeTimeout;
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => this.resize(), 150);
    }, { passive: true });

    let mouseTicking = false;
    window.addEventListener('mousemove', (e) => {
      if (!mouseTicking) {
        requestAnimationFrame(() => {
          this.mouse.x = e.clientX;
          this.mouse.y = e.clientY;
          mouseTicking = false;
        });
        mouseTicking = true;
      }
    }, { passive: true });

    window.addEventListener('mouseout', () => {
      this.mouse.x = -1000;
      this.mouse.y = -1000;
    }, { passive: true });

    // Pause when tab is not visible to free 100% CPU
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.isPaused = true;
        if (this.animId) cancelAnimationFrame(this.animId);
      } else {
        this.isPaused = false;
        this.animate();
      }
    });

    this.animate();
  }

  resize() {
    this.canvas.width = window.innerWidth;
    this.canvas.height = window.innerHeight;
    this.initParticles();
  }

  initParticles() {
    this.particles = [];
    for (let i = 0; i < this.maxParticles; i++) {
      this.particles.push({
        x: Math.random() * this.canvas.width,
        y: Math.random() * this.canvas.height,
        vx: (Math.random() - 0.5) * 0.45,
        vy: (Math.random() - 0.5) * 0.45,
        size: Math.random() * 1.5 + 1.0
      });
    }
  }

  init() {
    this.resize();
  }

  animate() {
    if (this.isPaused) return;

    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    const w = this.canvas.width;
    const h = this.canvas.height;
    const len = this.particles.length;

    // 1. Update and batch draw all particles in a single path
    this.ctx.beginPath();
    for (let i = 0; i < len; i++) {
      const p = this.particles[i];

      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = w;
      else if (p.x > w) p.x = 0;
      if (p.y < 0) p.y = h;
      else if (p.y > h) p.y = 0;

      this.ctx.moveTo(p.x + p.size, p.y);
      this.ctx.arc(p.x, p.y, p.size, 0, 6.283);
    }
    this.ctx.fillStyle = 'rgba(6, 182, 212, 0.45)';
    this.ctx.fill();

    // 2. Batch draw connections in a single stroke path
    this.ctx.beginPath();
    for (let a = 0; a < len; a++) {
      const pa = this.particles[a];
      for (let b = a + 1; b < len; b++) {
        const pb = this.particles[b];
        const dx = pa.x - pb.x;
        const dy = pa.y - pb.y;
        const distSq = dx * dx + dy * dy;

        if (distSq < this.maxDistanceSq) {
          this.ctx.moveTo(pa.x, pa.y);
          this.ctx.lineTo(pb.x, pb.y);
        }
      }
    }
    this.ctx.strokeStyle = 'rgba(6, 182, 212, 0.08)';
    this.ctx.lineWidth = 1;
    this.ctx.stroke();

    this.animId = requestAnimationFrame(() => this.animate());
  }
}

// Initialize when DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new CyberBackground());
} else {
  new CyberBackground();
}
