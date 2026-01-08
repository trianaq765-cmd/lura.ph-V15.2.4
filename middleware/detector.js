// ===== DETECTOR MIDDLEWARE =====
// Mendeteksi dan memfilter request dari browser/bot

const SUSPICIOUS_USER_AGENTS = [
    'mozilla',
    'chrome',
    'safari',
    'firefox',
    'edge',
    'opera',
    'msie',
    'trident',
    'webkit',
    'gecko',
    'bot',
    'crawl',
    'spider',
    'curl',
    'wget',
    'python',
    'requests',
    'httpx',
    'aiohttp',
    'axios',
    'node-fetch',
    'postman',
    'insomnia',
    'discord',
    'telegram',
    'slack',
    'whatsapp'
];

const REQUIRED_HEADERS = [
    'x-executor-id',      // Custom header dari loader
    'x-script-version',   // Versi loader
    'x-hwid-hash'         // Hash HWID
];

// Daftar executor yang diizinkan
const ALLOWED_EXECUTORS = [
    'synapse',
    'script-ware',
    'fluxus',
    'krnl',
    'oxygen',
    'evon',
    'wave',
    'delta',
    'hydrogen',
    'arceus',
    'trigon',
    'comet'
];

function isBrowserOrBot(req) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const contentType = req.headers['content-type'] || '';
    const accept = req.headers['accept'] || '';
    const origin = req.headers['origin'] || '';
    const referer = req.headers['referer'] || '';
    
    // Check 1: User-Agent mengandung kata-kata browser/bot
    for (const keyword of SUSPICIOUS_USER_AGENTS) {
        if (userAgent.includes(keyword)) {
            return { 
                isSuspicious: true, 
                reason: `Suspicious User-Agent: contains "${keyword}"` 
            };
        }
    }
    
    // Check 2: Accept header mengandung text/html (browser)
    if (accept.includes('text/html')) {
        return { 
            isSuspicious: true, 
            reason: 'Accept header indicates browser' 
        };
    }
    
    // Check 3: Ada Origin header (biasanya dari browser/web)
    if (origin && origin !== '') {
        return { 
            isSuspicious: true, 
            reason: 'Origin header present' 
        };
    }
    
    // Check 4: Ada Referer header
    if (referer && referer !== '') {
        return { 
            isSuspicious: true, 
            reason: 'Referer header present' 
        };
    }
    
    // Check 5: Request dari browser biasanya punya header Accept-Language
    if (req.headers['accept-language']) {
        return { 
            isSuspicious: true, 
            reason: 'Accept-Language header present' 
        };
    }
    
    // Check 6: Cek header sec-fetch-* (Chrome/modern browser)
    if (req.headers['sec-fetch-mode'] || req.headers['sec-fetch-site']) {
        return { 
            isSuspicious: true, 
            reason: 'Sec-Fetch headers detected (browser)' 
        };
    }
    
    return { isSuspicious: false, reason: null };
}

function isValidExecutor(req) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const executorId = req.headers['x-executor-id'] || '';
    
    // Check custom headers
    let hasRequiredHeaders = true;
    for (const header of REQUIRED_HEADERS) {
        if (!req.headers[header]) {
            hasRequiredHeaders = false;
            break;
        }
    }
    
    // Check executor ID matches allowed list
    let isAllowedExecutor = false;
    for (const executor of ALLOWED_EXECUTORS) {
        if (executorId.toLowerCase().includes(executor) || 
            userAgent.includes(executor)) {
            isAllowedExecutor = true;
            break;
        }
    }
    
    return {
        valid: hasRequiredHeaders,
        hasRequiredHeaders,
        isAllowedExecutor,
        executorId
    };
}

// Main middleware
function detectorMiddleware(req, res, next) {
    const path = req.path;
    const method = req.method;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // Skip untuk health check
    if (path === '/health') {
        return next();
    }
    
    // Log semua request
    console.log(`[DETECTOR] ${method} ${path} from ${ip}`);
    console.log(`[DETECTOR] User-Agent: ${req.headers['user-agent'] || 'None'}`);
    
    // Check jika browser/bot
    const browserCheck = isBrowserOrBot(req);
    
    if (browserCheck.isSuspicious) {
        console.log(`[TRAP] Browser/Bot detected: ${browserCheck.reason}`);
        
        // Kirim HTML trap
        res.setHeader('Content-Type', 'text/html');
        return res.sendFile('trap.html', { root: './public' });
    }
    
    // Untuk endpoint API, validasi lebih ketat
    if (path.startsWith('/api/')) {
        const executorCheck = isValidExecutor(req);
        
        if (!executorCheck.valid) {
            console.log(`[REJECT] Invalid executor request`);
            
            // Random response untuk membingungkan
            const fakeResponses = [
                { error: 'Not Found' },
                { status: 'maintenance' },
                { message: 'Service unavailable' },
                { code: 503 },
                ''  // Empty response
            ];
            
            const fake = fakeResponses[Math.floor(Math.random() * fakeResponses.length)];
            
            // Random status code
            const codes = [400, 403, 404, 500, 502, 503];
            const code = codes[Math.floor(Math.random() * codes.length)];
            
            return res.status(code).json(fake);
        }
        
        // Tambahkan info executor ke request
        req.executorInfo = executorCheck;
    }
    
    next();
}

module.exports = { 
    detectorMiddleware, 
    isBrowserOrBot, 
    isValidExecutor,
    ALLOWED_EXECUTORS 
};
