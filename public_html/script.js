// ClawP2P — hop animation
// Respects prefers-reduced-motion. If motion is reduced, the static fallback stays visible.

(function () {
  const motionOK = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!motionOK) return;

  const hopSection = document.getElementById('hop');
  const hopAnimated = document.getElementById('hopAnimated');
  if (!hopSection || !hopAnimated) return;

  // Mark section so CSS can switch static → animated
  hopSection.classList.add('has-animation');
  hopAnimated.style.display = 'flex';

  const countA = document.getElementById('countA');
  const statusA = document.getElementById('statusA');
  const countB = document.getElementById('countB');
  const statusB = document.getElementById('statusB');
  const transitBundle = document.getElementById('transitBundle');
  const transitLabel = document.getElementById('transitLabel');
  const nodeABox = document.querySelector('.node-a .anim-node-box');
  const nodeBBox = document.querySelector('.node-b .anim-node-box');

  let hopCount = 0;
  let agentCount = 0;
  let running = false;
  let animTimeout = null;

  function resetState() {
    agentCount = 0;
    countA.textContent = `count: ${agentCount}`;
    statusA.textContent = 'running';
    countB.textContent = '—';
    statusB.textContent = 'waiting';
    transitBundle.style.left = '0';
    transitBundle.textContent = '📦';
    transitLabel.textContent = '—';
    nodeABox.classList.add('active');
    nodeABox.classList.remove('verifying');
    nodeBBox.classList.remove('active', 'verifying');
  }

  function delay(ms) {
    return new Promise(resolve => { animTimeout = setTimeout(resolve, ms); });
  }

  async function runCycle() {
    if (running) return;
    running = true;

    resetState();

    // Phase 1: Agent runs on Node A, count up to 5
    for (let i = 0; i <= 5; i++) {
      agentCount = i;
      countA.textContent = `count: ${agentCount}`;
      await delay(350);
    }

    // Phase 2: Checkpoint — agent decides to migrate
    statusA.textContent = 'checkpoint';
    countA.textContent = `count: ${agentCount} ✓`;
    nodeABox.classList.remove('active');
    transitBundle.textContent = '📦';
    transitLabel.textContent = 'transfer';
    await delay(700);

    // Phase 3: Bundle flies across
    transitBundle.style.transition = 'left 0.9s ease-in-out';
    transitBundle.style.left = 'calc(100% - 20px)';
    await delay(1000);

    // Phase 4: Verify on Node B
    nodeBBox.classList.add('verifying');
    transitBundle.textContent = '🔏';
    transitLabel.textContent = 'verify';
    countB.textContent = 'checking sig…';
    statusB.textContent = 'verifying';
    await delay(900);

    // Phase 5: Verified — resume
    nodeBBox.classList.remove('verifying');
    nodeBBox.classList.add('active');
    transitBundle.textContent = '✓';
    transitLabel.textContent = 'verified';
    countB.textContent = `count: ${agentCount}`;
    statusB.textContent = 'resuming…';
    await delay(600);

    // Phase 6: Agent resumes on Node B, keeps counting
    statusB.textContent = 'running';
    for (let i = agentCount + 1; i <= agentCount + 5; i++) {
      countB.textContent = `count: ${i}`;
      await delay(350);
    }

    hopCount++;
    statusB.textContent = `running (hop ${hopCount})`;

    await delay(1200);
    running = false;

    // Swap and do it again (agent now "lives" on B — simplify by restarting for demo)
    await delay(800);
    runCycle();
  }

  // Intersection Observer — only animate when section is visible
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting && !running) {
          runCycle();
        }
      });
    },
    { threshold: 0.4 }
  );

  observer.observe(hopSection);
})();
