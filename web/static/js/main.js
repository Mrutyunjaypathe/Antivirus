/* ─── SHIELDX main.js ─── */

// ────────────────────────────────────────────────
// Counter animation
// ────────────────────────────────────────────────
function animateCounter(el, target, duration = 1200) {
    if (target === 0) return;
    const start = performance.now();
    function step(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        el.textContent = Math.round(eased * target);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

// ────────────────────────────────────────────────
// Toast notifications
// ────────────────────────────────────────────────
function showToast(message, type = 'success', duration = 4000) {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// ────────────────────────────────────────────────
// Run on page load
// ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Auto-animate any visible stat counters
    document.querySelectorAll('.stat-value').forEach(el => {
        const val = parseInt(el.textContent, 10);
        if (!isNaN(val) && val > 0) animateCounter(el, val);
    });

    // Auto-dismiss flash messages after 4s
    document.querySelectorAll('.flash').forEach(flash => {
        setTimeout(() => {
            flash.style.opacity = '0';
            flash.style.transition = 'opacity 0.4s';
            setTimeout(() => flash.remove(), 400);
        }, 4000);
    });
});
