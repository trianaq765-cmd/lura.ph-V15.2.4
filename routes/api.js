// ===== API ROUTES =====
const express = require('express');
const router = express.Router();
const crypto = require('crypto');

const { 
    sha256, 
    xorEncrypt, 
    aesEncrypt, 
    generateDynamicKey,
    generateNonce,
    hmacSign,
    hmacVerify
} = require('../utils/encryption');

const { 
    validateKey, 
    logAccess, 
    isIPBlacklisted,
    blacklistIP,
    resetHWID,
    disableKey,
    addKey,
    getLogs,
    generateKey
} = require('../utils/database');

// ===== STORAGE =====
const challenges = new Map();
const usedNonces = new Set();
const failedAttempts = new Map();
const rateLimits = new Map();

const SECRET = process.env.SECRET_KEY || 'DefaultSecretKey123!';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'AdminPass123!';

// ===== CONFIG =====
const CONFIG = {
    CHALLENGE_EXPIRY: 60 * 1000,        // 1 menit
    NONCE_EXPIRY: 5 * 60 * 1000,        // 5 menit
    MAX_FAILED_ATTEMPTS: 5,
    RATE_LIMIT_WINDOW: 60 * 1000,       // 1 menit
    RATE_LIMIT_MAX: 10,
    CHUNK_SIZE: 300
};

// ===== HELPER: Rate Limiter =====
function checkRateLimit(ip) {
    const now = Date.now();
    
    if (!rateLimits.has(ip)) {
        rateLimits.set(ip, { count: 1, start: now });
        return { allowed: true };
    }
    
    const data = rateLimits.get(ip);
    
    if (now - data.start > CONFIG.RATE_LIMIT_WINDOW) {
        rateLimits.set(ip, { count: 1, start: now });
        return { allowed: true };
    }
    
    data.count++;
    
    if (data.count > CONFIG.RATE_LIMIT_MAX) {
        return { allowed: false, retryAfter: CONFIG.RATE_LIMIT_WINDOW - (now - data.start) };
    }
    
    return { allowed: true };
}

// ===== HELPER: Failed Attempts Tracker =====
function trackFailed(ip) {
    if (!failedAttempts.has(ip)) {
        failedAttempts.set(ip, { count: 1, first: Date.now() });
    } else {
        const data = failedAttempts.get(ip);
        data.count++;
        
        if (data.count >= CONFIG.MAX_FAILED_ATTEMPTS) {
            blacklistIP(ip, 'Too many failed attempts');
            return true; // Blacklisted
        }
    }
    return false;
}

// ===== ROUTE: Health Check =====
router.get('/health', (req, res) => {
    res.json({ status: 'ok', time: Date.now() });
});

// ===== ROUTE: Init Handshake =====
router.post('/init', (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // Rate limit check
    const rateCheck = checkRateLimit(ip);
    if (!rateCheck.allowed) {
        return res.status(429).json({
            success: false,
            error: 'RATE_LIMITED',
            retryAfter: rateCheck.retryAfter
        });
    }
    
    // IP blacklist check
    if (isIPBlacklisted(ip)) {
        return res.status(403).json({ success: false, error: 'BLOCKED' });
    }
    
    const { hwid, fingerprint, timestamp, executorId } = req.body;
    
    if (!hwid || !timestamp) {
        trackFailed(ip);
        return res.status(400).json({ success: false, error: 'INVALID_REQUEST' });
    }
    
    // Validate timestamp (max 60 detik)
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > 60) {
        return res.json({ success: false, error: 'TIMESTAMP_EXPIRED' });
    }
    
    // Generate challenge
    const challenge = crypto.randomBytes(32).toString('hex');
    const serverTime = Math.floor(Date.now() / 1000);
    const sessionId = sha256(hwid + ip + serverTime).substring(0, 24);
    
    // Store challenge
    challenges.set(sessionId, {
        challenge,
        hwid,
        ip,
        createdAt: Date.now(),
        executorId: executorId || 'unknown'
    });
    
    // Auto cleanup
    setTimeout(() => challenges.delete(sessionId), CONFIG.CHALLENGE_EXPIRY);
    
    console.log(`[INIT] Session created: ${sessionId} from ${ip}`);
    
    res.json({
        success: true,
        sessionId: sessionId,
        challenge: challenge,
        serverTime: serverTime,
        algorithm: 'HMAC-SHA256'
    });
});

// ===== ROUTE: Validate Key =====
router.post('/validate', (req, res) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // Rate limit
    const rateCheck = checkRateLimit(ip);
    if (!rateCheck.allowed) {
        return res.status(429).json({ success: false, error: 'RATE_LIMITED' });
    }
    
    // Blacklist
    if (isIPBlacklisted(ip)) {
        return res.status(403).json({ success: false, error: 'BLOCKED' });
    }
    
    const { 
        sessionId,
        key, 
        hwid, 
        timestamp, 
        signature, 
        nonce 
    } = req.body;
    
    // Validate required fields
    if (!sessionId || !key || !hwid || !timestamp || !signature || !nonce) {
        trackFailed(ip);
        logAccess(key, hwid, ip, false, 'MISSING_PARAMS', 'Missing required parameters');
        return res.status(400).json({ success: false, error: 'MISSING_PARAMS' });
    }
    
    // Validate session
    const session = challenges.get(sessionId);
    if (!session) {
        trackFailed(ip);
        return res.json({ success: false, error: 'SESSION_EXPIRED' });
    }
    
    // Validate HWID matches session
    if (session.hwid !== hwid) {
        trackFailed(ip);
        return res.json({ success: false, error: 'SESSION_MISMATCH' });
    }
    
    // Validate IP matches session
    if (session.ip !== ip) {
        trackFailed(ip);
        return res.json({ success: false, error: 'IP_CHANGED' });
    }
    
    // Check nonce (anti-replay)
    if (usedNonces.has(nonce)) {
        trackFailed(ip);
        console.log(`[SECURITY] Replay attack detected from ${ip}`);
        return res.json({ success: false, error: 'REPLAY_DETECTED' });
    }
    usedNonces.add(nonce);
    setTimeout(() => usedNonces.delete(nonce), CONFIG.NONCE_EXPIRY);
    
    // Validate timestamp
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > 30) {
        return res.json({ success: false, error: 'REQUEST_EXPIRED' });
    }
    
    // Validate signature
    const signaturePayload = `${key}:${hwid}:${timestamp}:${session.challenge}:${nonce}`;
    const expectedSignature = hmacSign(signaturePayload, SECRET);
    
    try {
        if (!hmacVerify(signaturePayload, signature, SECRET)) {
            trackFailed(ip);
            console.log(`[SECURITY] Invalid signature from ${ip}`);
            logAccess(key, hwid, ip, false, 'INVALID_SIG', 'Signature mismatch');
            return res.json({ success: false, error: 'INVALID_SIGNATURE' });
        }
    } catch (e) {
        trackFailed(ip);
        return res.json({ success: false, error: 'SIGNATURE_ERROR' });
    }
    
    // Validate key in database
    const result = validateKey(key, hwid, ip);
    
    if (!result.valid) {
        if (trackFailed(ip)) {
            return res.status(403).json({ success: false, error: 'BLOCKED' });
        }
        logAccess(key, hwid, ip, false, result.code, result.message);
        return res.json({ 
            success: false, 
            error: result.code,
            message: result.message 
        });
    }
    
    // SUCCESS!
    console.log(`[SUCCESS] Key ${key} validated for HWID ${hwid.substring(0, 12)}...`);
    logAccess(key, hwid, ip, true, 'SUCCESS', 'Validation successful');
    
    // Delete used session
    challenges.delete(sessionId);
    
    // Prepare encrypted response
    const dynamicKey = generateDynamicKey(hwid, timestamp, SECRET);
    
    // Layer 1: XOR
    const xorEncrypted = xorEncrypt(result.script, dynamicKey);
    
    // Layer 2: AES
    const aesEncrypted = aesEncrypt(xorEncrypted, SECRET);
    
    // Layer 3: Chunk & Shuffle
    const chunks = [];
    for (let i = 0; i < aesEncrypted.length; i += CONFIG.CHUNK_SIZE) {
        chunks.push(aesEncrypted.substring(i, i + CONFIG.CHUNK_SIZE));
    }
    
    // Shuffle order
    const indices = chunks.map((_, i) => i);
    for (let i = indices.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    
    const shuffledChunks = indices.map(i => chunks[i]);
    const encryptedOrder = xorEncrypt(JSON.stringify(indices), dynamicKey);
    
    // Generate response token untuk heartbeat
    const responseToken = sha256(`${key}:${hwid}:${Date.now()}:${SECRET}`).substring(0, 32);
    
    res.json({
        success: true,
        plan: result.plan,
        expiresAt: result.expiresAt,
        payload: {
            chunks: shuffledChunks,
            order: encryptedOrder,
            count: chunks.length
        },
        meta: {
            token: responseToken,
            algorithm: 'XOR-AES-GCM-CHUNK',
            version: '2.0',
            timestamp: now
        }
    });
});

// ===== ADMIN ROUTES =====

router.post('/admin/status', (req, res) => {
    const { password } = req.body;
    
    if (password !== ADMIN_PASS) {
        return res.status(403).json({ success: false, error: 'UNAUTHORIZED' });
    }
    
    res.json({
        success: true,
        stats: {
            activeChallenges: challenges.size,
            usedNonces: usedNonces.size,
            failedAttempts: failedAttempts.size,
            rateLimits: rateLimits.size
        },
        logs: getLogs(20)
    });
});

router.post('/admin/reset-hwid', (req, res) => {
    const { password, key } = req.body;
    
    if (password !== ADMIN_PASS) {
        return res.status(403).json({ success: false, error: 'UNAUTHORIZED' });
    }
    
    const result = resetHWID(key);
    res.json({ success: result, message: result ? 'HWID reset' : 'Key not found' });
});

router.post('/admin/disable-key', (req, res) => {
    const { password, key, reason } = req.body;
    
    if (password !== ADMIN_PASS) {
        return res.status(403).json({ success: false, error: 'UNAUTHORIZED' });
    }
    
    const result = disableKey(key, reason || 'Admin action');
    res.json({ success: result, message: result ? 'Key disabled' : 'Key not found' });
});

router.post('/admin/add-key', (req, res) => {
    const { password, plan, expiresInDays } = req.body;
    
    if (password !== ADMIN_PASS) {
        return res.status(403).json({ success: false, error: 'UNAUTHORIZED' });
    }
    
    const newKey = generateKey(plan.toUpperCase().substring(0, 4));
    const result = addKey(newKey, plan, expiresInDays || null);
    
    res.json({ 
        success: result, 
        key: result ? newKey : null,
        message: result ? 'Key created' : 'Failed to create key'
    });
});

router.post('/admin/logs', (req, res) => {
    const { password, limit } = req.body;
    
    if (password !== ADMIN_PASS) {
        return res.status(403).json({ success: false, error: 'UNAUTHORIZED' });
    }
    
    res.json({ success: true, logs: getLogs(limit || 50) });
});

module.exports = router;
