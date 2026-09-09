const revealElements = document.querySelectorAll('.reveal');

const observer = new IntersectionObserver(
    (entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    },
    { threshold: 0.15 }
);

revealElements.forEach((el) => observer.observe(el));

function initBeeFlight() {
    if (!document.body.classList.contains('home-body')) {
        return;
    }

    const bee = document.getElementById('bee-flyer');
    if (!bee) {
        return;
    }

    const beeImage = bee.querySelector('.bee-image');
    if (beeImage) {
        const enableImageMode = () => {
            if (beeImage.naturalWidth > 0) {
                bee.classList.add('has-image');
            }
        };

        if (beeImage.complete) {
            enableImageMode();
        }
        beeImage.addEventListener('load', enableImageMode);
        beeImage.addEventListener('error', () => {
            bee.classList.remove('has-image');
        });
    }

    let currentX = Math.max(80, window.innerWidth * 0.2);
    let currentY = Math.max(120, window.innerHeight * 0.35);

    const targetSelectors = [
        '.btn-outline-dark',
        '.btn-honey',
        '.product-card',
        '.catalog-link',
        '.feature-card',
        '.hero-stat-card'
    ];

    function clamp(val, min, max) {
        return Math.min(Math.max(val, min), max);
    }

    function getLandingTargets() {
        return targetSelectors
            .flatMap((selector) => Array.from(document.querySelectorAll(selector)))
            .filter((el) => {
                const rect = el.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            });
    }

    function beginLandingAndContinue() {
        bee.classList.remove('is-flying');
        bee.classList.add('is-landing');
        bee.style.setProperty('--bee-flutter', '0px');

        const restDuration = 800 + Math.floor(Math.random() * 1300);
        window.setTimeout(() => {
            bee.classList.remove('is-landing');
            flyToNextTarget();
        }, restDuration);
    }

    function orbitAroundTarget(centerX, centerY, done) {
        const loops = 1 + Math.floor(Math.random() * 2);
        const radius = 14 + Math.random() * 18;
        const duration = 1000 + Math.floor(Math.random() * 900);
        const direction = Math.random() < 0.5 ? -1 : 1;
        const start = performance.now();

        bee.style.transition = 'none';

        function tick(now) {
            const progress = Math.min((now - start) / duration, 1);
            const theta = direction * progress * Math.PI * 2 * loops;

            const x = centerX + Math.cos(theta) * radius;
            const y = centerY + Math.sin(theta) * radius * 0.65;
            const dx = -Math.sin(theta) * direction;
            const dy = Math.cos(theta) * 0.65 * direction;
            const angle = Math.atan2(dy, dx) * (180 / Math.PI);

            bee.style.transform = `translate(${x}px, ${y}px) rotate(${angle}deg)`;

            currentX = x;
            currentY = y;

            if (progress < 1) {
                window.requestAnimationFrame(tick);
                return;
            }

            done();
        }

        window.requestAnimationFrame(tick);
    }

    function flyToNextTarget() {
        const targets = getLandingTargets();
        if (!targets.length) {
            window.setTimeout(flyToNextTarget, 900);
            return;
        }

        const chosen = targets[Math.floor(Math.random() * targets.length)];
        const rect = chosen.getBoundingClientRect();

        const padding = 16;
        const targetX = clamp(
            rect.left + rect.width * (0.2 + Math.random() * 0.6),
            padding,
            window.innerWidth - 40
        );
        const targetY = clamp(
            rect.top + rect.height * (0.2 + Math.random() * 0.6),
            64,
            window.innerHeight - 36
        );

        const angle = Math.atan2(targetY - currentY, targetX - currentX) * (180 / Math.PI);
        const duration = 1800 + Math.floor(Math.random() * 1600);
        const flutterBlur = Math.max(0.08, Math.min(0.45, (3600 - duration) / 6400));

        bee.classList.remove('is-landing');
        bee.classList.add('is-flying');
        bee.style.setProperty('--bee-flutter', `${flutterBlur.toFixed(2)}px`);
        bee.style.transition = `transform ${duration}ms cubic-bezier(0.22, 0.8, 0.2, 1)`;
        bee.style.transform = `translate(${targetX}px, ${targetY}px) rotate(${angle}deg)`;

        currentX = targetX;
        currentY = targetY;

        window.setTimeout(() => {
            const shouldOrbit = Math.random() < 0.45;
            if (shouldOrbit) {
                orbitAroundTarget(targetX, targetY, beginLandingAndContinue);
                return;
            }

            beginLandingAndContinue();
        }, duration);
    }

    bee.style.transform = `translate(${currentX}px, ${currentY}px) rotate(0deg)`;
    window.setTimeout(flyToNextTarget, 700);

    window.addEventListener('resize', () => {
        currentX = clamp(currentX, 8, window.innerWidth - 40);
        currentY = clamp(currentY, 64, window.innerHeight - 36);
    });
}

initBeeFlight();

function initBehaviorTelemetry() {
    const body = document.body;
    const endpoint = body?.dataset?.telemetryEndpoint;
    const honeySessionId = body?.dataset?.honeySessionId;
    if (!endpoint) {
        return;
    }

    if (!honeySessionId) {
        return;
    }

    const pendingEvents = [];
    let lastMouseSample = 0;
    let lastScrollSample = 0;
    let idleTimer = null;

    function pushEvent(eventType, details) {
        pendingEvents.push({
            event_type: eventType,
            session_id: honeySessionId,
            path: window.location.pathname,
            timestamp: new Date().toISOString(),
            details,
        });

        if (pendingEvents.length >= 6) {
            flushEvents('batch');
        }
    }

    function canvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 260;
            canvas.height = 80;
            const ctx = canvas.getContext('2d');
            if (!ctx) {
                return null;
            }
            ctx.textBaseline = 'top';
            ctx.font = '16px Fraunces, serif';
            ctx.fillStyle = '#b86c1f';
            ctx.fillText('Honey Haven canvas', 8, 8);
            ctx.fillStyle = '#1f2933';
            ctx.fillText(navigator.userAgent, 8, 36);
            return canvas.toDataURL('image/png');
        } catch (error) {
            return null;
        }
    }

    function webglFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const context = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!context) {
                return null;
            }
            const debugInfo = context.getExtension('WEBGL_debug_renderer_info');
            return debugInfo ? context.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : context.getParameter(context.RENDERER);
        } catch (error) {
            return null;
        }
    }

    function collectFingerprint() {
        const fonts = ['Arial', 'Times New Roman', 'Courier New', 'Georgia', 'Fraunces', 'Manrope'].filter((font) => {
            try {
                return document.fonts ? document.fonts.check(`16px ${font}`) : true;
            } catch (error) {
                return false;
            }
        });

        return {
            kind: 'fingerprint',
            session_id: honeySessionId,
            screen: {
                width: window.screen.width,
                height: window.screen.height,
                colorDepth: window.screen.colorDepth,
                devicePixelRatio: window.devicePixelRatio,
            },
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            languages: navigator.languages || [],
            webdriver: Boolean(navigator.webdriver),
            plugins: Array.from(navigator.plugins || []).map((plugin) => plugin.name).slice(0, 10),
            hardwareConcurrency: navigator.hardwareConcurrency || null,
            deviceMemory: navigator.deviceMemory || null,
            canvas: canvasFingerprint(),
            webglRenderer: webglFingerprint(),
            fonts,
            userAgent: navigator.userAgent,
        };
    }

    function sendPayload(payload) {
        const bodyText = JSON.stringify(payload);
        if (navigator.sendBeacon) {
            return navigator.sendBeacon(endpoint, new Blob([bodyText], { type: 'application/json' }));
        }

        return fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: bodyText,
            keepalive: true,
            credentials: 'same-origin',
        }).catch(() => null);
    }

    function flushEvents(reason) {
        if (!pendingEvents.length) {
            return;
        }

        const batch = pendingEvents.splice(0, pendingEvents.length);
        sendPayload({
            kind: 'behavior',
            event_type: reason === 'fingerprint' ? 'FINGERPRINT_SIGNAL' : 'BEHAVIOR_SIGNAL',
            session_id: honeySessionId,
            events: batch,
            viewport: { width: window.innerWidth, height: window.innerHeight },
            url: window.location.href,
            referrer: document.referrer || '',
        });
    }

    function resetIdleTimer() {
        if (idleTimer) {
            window.clearTimeout(idleTimer);
        }
        idleTimer = window.setTimeout(() => {
            pushEvent('idle', { duration_ms: 30000 });
            flushEvents('idle');
        }, 30000);
    }

    window.addEventListener('mousemove', (event) => {
        const now = Date.now();
        if (now - lastMouseSample < 200) {
            return;
        }
        lastMouseSample = now;
        resetIdleTimer();
        pushEvent('mousemove', { x: event.clientX, y: event.clientY });
    }, { passive: true });

    window.addEventListener('scroll', () => {
        const now = Date.now();
        if (now - lastScrollSample < 400) {
            return;
        }
        lastScrollSample = now;
        resetIdleTimer();
        pushEvent('scroll', { x: window.scrollX, y: window.scrollY });
    }, { passive: true });

    window.addEventListener('click', (event) => {
        resetIdleTimer();
        pushEvent('click', {
            tag: event.target?.tagName || '',
            id: event.target?.id || '',
            className: event.target?.className || '',
        });
    }, { passive: true });

    window.addEventListener('keydown', (event) => {
        resetIdleTimer();
        pushEvent('keydown', { key: event.key, code: event.code, altKey: event.altKey, ctrlKey: event.ctrlKey, metaKey: event.metaKey });
    });

    window.addEventListener('paste', () => {
        resetIdleTimer();
        pushEvent('paste', { source: 'clipboard' });
    });

    document.addEventListener('visibilitychange', () => {
        pushEvent('visibilitychange', { state: document.visibilityState });
        if (document.visibilityState === 'hidden') {
            flushEvents('visibilitychange');
        }
    });

    window.addEventListener('beforeunload', () => {
        flushEvents('beforeunload');
    });

    pushEvent('fingerprint', collectFingerprint());
    flushEvents('fingerprint');
    resetIdleTimer();
}

initBehaviorTelemetry();
