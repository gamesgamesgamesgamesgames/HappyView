'use client';

import { useEffect, useRef } from 'react';

export function VaporwaveGrid() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const logo = new Image();
    logo.src = '/img/face.webp';

    let animationId: number;
    let w = 0;
    let h = 0;

    function resize() {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas!.getBoundingClientRect();
      w = rect.width;
      h = rect.height;
      canvas!.width = w * dpr;
      canvas!.height = h * dpr;
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);

    function draw(time: number) {
      const elapsed = time / 1000;

      const scrollY = window.scrollY;
      const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
      const scrollProgress = maxScroll > 0 ? scrollY / maxScroll : 0;
      const scrollOffset = scrollY * 0.01;

      // Face rises in the last 30% of the scroll
      const faceThreshold = 0.7;
      const faceProgress = Math.max(0, (scrollProgress - faceThreshold) / (1 - faceThreshold));
      const faceReveal = Math.min(faceProgress, 1);

      // Dim the whole canvas, brightening as the face rises
      canvas!.style.opacity = String(0.4 + 0.6 * faceReveal);

      ctx!.clearRect(0, 0, w, h);

      const gridRegionHeight = h * 0.4;
      const horizonY = h - gridRegionHeight * 0.65;
      const centerX = w / 2;
      const gridHeight = h - horizonY;

      const styles = getComputedStyle(canvas!);
      const aquaRaw = styles.getPropertyValue('--color-aqua').trim() || '0 212 255';
      const bgRaw = styles.getPropertyValue('--color-bg').trim() || '8 8 24';
      const [ar, ag, ab] = aquaRaw.split(' ').map(Number);
      const [br, bg, bb] = bgRaw.split(' ').map(Number);

      const aquaRgba = (a: number) => `rgba(${ar}, ${ag}, ${ab}, ${a})`;
      const bgRgb = `rgb(${br}, ${bg}, ${bb})`;
      const bgRgba = (a: number) => `rgba(${br}, ${bg}, ${bb}, ${a})`;

      // --- 1. Sky fade (background, drawn first) ---
      const skyGrad = ctx!.createLinearGradient(0, 0, 0, horizonY);
      skyGrad.addColorStop(0, bgRgb);
      skyGrad.addColorStop(0.4, bgRgb);
      skyGrad.addColorStop(1, bgRgba(0));
      ctx!.fillStyle = skyGrad;
      ctx!.fillRect(0, 0, w, horizonY);

      const sunSize = Math.min(w * 0.15, 150);

      // --- 2. Logo glow + face (only when scrolled near bottom) ---
      if (logo.complete && logo.naturalWidth > 0 && faceReveal > 0) {
        // Face starts fully behind horizon and rises to 80% visible
        const faceY = horizonY - sunSize * 0.8 * faceReveal;

        // Glow (clipped above horizon)
        ctx!.save();
        ctx!.beginPath();
        ctx!.rect(0, 0, w, horizonY);
        ctx!.clip();

        const glowAlpha = faceReveal * 0.35;
        const glowGrad = ctx!.createRadialGradient(
          centerX, horizonY, sunSize * 0.2,
          centerX, horizonY, sunSize * 3,
        );
        glowGrad.addColorStop(0, `rgba(255, 51, 144, ${glowAlpha})`);
        glowGrad.addColorStop(0.3, `rgba(255, 51, 144, ${glowAlpha * 0.35})`);
        glowGrad.addColorStop(1, 'rgba(255, 51, 144, 0)');
        ctx!.fillStyle = glowGrad;
        ctx!.fillRect(0, 0, w, h);

        ctx!.restore();

        // Ground glow (below horizon)
        const groundGlow = ctx!.createRadialGradient(
          centerX, horizonY, 0,
          centerX, horizonY + gridHeight * 0.4, w * 0.5,
        );
        groundGlow.addColorStop(0, `rgba(255, 51, 144, ${faceReveal * 0.12})`);
        groundGlow.addColorStop(0.5, `rgba(255, 51, 144, ${faceReveal * 0.04})`);
        groundGlow.addColorStop(1, 'rgba(255, 51, 144, 0)');
        ctx!.fillStyle = groundGlow;
        ctx!.fillRect(0, horizonY, w, gridHeight);

        // Face (clipped at horizon, with glitch)
        ctx!.save();
        ctx!.beginPath();
        ctx!.rect(0, 0, w, horizonY);
        ctx!.clip();

        const glitchInterval = 8;
        const glitchPhase = elapsed % glitchInterval;
        const isGlitching = glitchPhase < 0.5 || (glitchPhase > 3.8 && glitchPhase < 4.15);

        if (isGlitching) {
          const numSlices = 12;
          const sliceH = sunSize / numSlices;
          const srcSliceH = logo.naturalWidth / numSlices;
          const frame = Math.floor(elapsed * 4);
          const frameFrac = (elapsed * 4) % 1;

          for (let s = 0; s < numSlices; s++) {
            const hash = Math.sin(s * 127.1 + frame * 311.7) * 43758.5453;
            const nextHash = Math.sin(s * 127.1 + (frame + 1) * 311.7) * 43758.5453;
            const shouldOffset = (hash - Math.floor(hash)) > 0.55;
            const nextShouldOffset = (nextHash - Math.floor(nextHash)) > 0.55;

            const targetX = shouldOffset
              ? ((Math.sin(s * 43.3 + frame * 17.1) * 9999) % 1 - 0.5) * sunSize * 0.3
              : 0;
            const nextTargetX = nextShouldOffset
              ? ((Math.sin(s * 43.3 + (frame + 1) * 17.1) * 9999) % 1 - 0.5) * sunSize * 0.3
              : 0;

            const ease = frameFrac < 0.3 ? frameFrac / 0.3 : 1;
            const drift = Math.sin(elapsed * 5 + s * 2.3) * sunSize * 0.04;
            const offsetX = targetX + (nextTargetX - targetX) * ease * 0.25 + drift;

            ctx!.drawImage(
              logo,
              0, s * srcSliceH, logo.naturalWidth, srcSliceH,
              centerX - sunSize / 2 + offsetX, faceY + s * sliceH, sunSize, sliceH,
            );
          }

          // RGB channel separation — tween the offset
          const rgbShift = 3 + Math.sin(elapsed * 6) * 2;
          ctx!.globalCompositeOperation = 'lighter';
          ctx!.globalAlpha = 0.12 + Math.sin(elapsed * 9) * 0.05;
          ctx!.drawImage(logo, centerX - sunSize / 2 - rgbShift, faceY, sunSize, sunSize);
          ctx!.drawImage(logo, centerX - sunSize / 2 + rgbShift, faceY, sunSize, sunSize);
          ctx!.globalCompositeOperation = 'source-over';
          ctx!.globalAlpha = 1;
        } else {
          ctx!.drawImage(logo, centerX - sunSize / 2, faceY, sunSize, sunSize);
        }

        ctx!.restore();
      }

      // --- 3. Horizontal grid lines (scroll-synced) ---
      const lineSpacing = 0.07;
      const maxDepth = 60;
      const minDepth = 0.1;
      const focalLen = gridHeight * minDepth;
      const offset = (scrollOffset * 0.02) % lineSpacing;

      ctx!.strokeStyle = aquaRgba(1);
      ctx!.lineWidth = 1;

      for (let depth = minDepth; depth < maxDepth; depth += lineSpacing) {
        let d = depth - offset;
        if (d < minDepth) d += lineSpacing;

        const screenY = horizonY + focalLen / d;
        if (screenY > h + 2) continue;

        const t = (screenY - horizonY) / gridHeight;
        ctx!.globalAlpha = Math.min(t * 0.7, 0.5);
        ctx!.beginPath();
        ctx!.moveTo(0, screenY);
        ctx!.lineTo(w, screenY);
        ctx!.stroke();
      }

      // --- 4. Vertical grid lines ---
      const numVerticals = 16;
      const extendBeyond = w * 0.5;

      for (let i = -numVerticals; i <= numVerticals; i++) {
        const spread = i / numVerticals;
        const bottomX = centerX + spread * (w + extendBeyond);
        const horizonX = centerX + spread * w * 0.05;

        const t = Math.abs(spread);
        ctx!.globalAlpha = (1 - t * 0.5) * 0.35;
        ctx!.beginPath();
        ctx!.moveTo(horizonX, horizonY);
        ctx!.lineTo(bottomX, h);
        ctx!.stroke();
      }

      ctx!.globalAlpha = 1;

      // --- 6. Horizon glow ---
      const horizonGlowGrad = ctx!.createLinearGradient(0, horizonY - 4, 0, horizonY + 12);
      horizonGlowGrad.addColorStop(0, aquaRgba(0));
      horizonGlowGrad.addColorStop(0.4, aquaRgba(0.3));
      horizonGlowGrad.addColorStop(1, aquaRgba(0));
      ctx!.fillStyle = horizonGlowGrad;
      ctx!.fillRect(0, horizonY - 4, w, 16);

      animationId = requestAnimationFrame(draw);
    }

    animationId = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(animationId);
      observer.disconnect();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="not-prose"
      style={{
        display: 'block',
        width: '100vw',
        marginLeft: 'calc(-50vw + 50%)',
        height: '100vh',
        marginTop: '-60vh',
        position: 'sticky',
        bottom: 0,
        pointerEvents: 'none',
        zIndex: -1,
      }}
    />
  );
}
