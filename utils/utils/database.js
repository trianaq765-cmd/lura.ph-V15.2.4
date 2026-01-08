// ===== DATABASE MODULE =====
// Script disimpan di Environment Variables, bukan di code!

const { sha256 } = require('./encryption');

// ===== DATABASE KEYS (bisa dipindah ke MongoDB nanti) =====
const keys = {
    "PREMIUM-DEMO-001": {
        hwid: null,
        plan: "Premium",
        active: true,
        createdAt: Date.now(),
        expiresAt: null,
        usageCount: 0,
        lastUsed: null,
        lastIP: null
    },
    "BASIC-DEMO-001": {
        hwid: null,
        plan: "Basic",
        active: true,
        createdAt: Date.now(),
        expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 hari
        usageCount: 0,
        lastUsed: null,
        lastIP: null
    },
    "TEST-KEY-123": {
        hwid: null,
        plan: "Premium",
        active: true,
        createdAt: Date.now(),
        expiresAt: null,
        usageCount: 0,
        lastUsed: null,
        lastIP: null
    }
};

// ===== BLACKLIST =====
const blacklist = {
    ips: new Map(),
    hwids: new Map()
};

// ===== ACCESS LOGS =====
const accessLogs = [];

// ===== FUNGSI: Ambil Script dari Environment =====
function getScriptFromEnv(plan) {
    /*
     * SCRIPT DISIMPAN DI ENVIRONMENT VARIABLES!
     * 
     * Di Render.com, tambahkan:
     * - SCRIPT_PREMIUM = (isi script premium yang sudah di-Luraph)
     * - SCRIPT_BASIC = (isi script basic yang sudah di-Luraph)
     * 
     * Untuk script multi-line, encode dulu ke Base64:
     * 1. Luraph script Anda
     * 2. Encode hasil Luraph ke Base64
     * 3. Paste ke Environment Variable
     */
    
    const envKey = `SCRIPT_${plan.toUpperCase()}`;
    const scriptBase64 = process.env[envKey];
    
    if (!scriptBase64) {
        console.error(`[DATABASE] Script not found in ENV: ${envKey}`);
        return null;
    }
    
    // Decode dari Base64
    try {
        const script = Buffer.from(scriptBase64, 'base64').toString('utf8');
        return script;
    } catch (e) {
        console.error(`[DATABASE] Failed to decode script: ${e.message}`);
        return null;
    }
}

// ===== FUNGSI: Validasi Key =====
function validateKey(key, hwid, ip) {
    const user = keys[key];
    
    // Cek key exists
    if (!user) {
        return { valid: false, code: "INVALID_KEY", message: "Kunci tidak ditemukan!" };
    }
    
    // Cek active
    if (!user.active) {
        return { valid: false, code: "KEY_DISABLED", message: "Kunci telah dinonaktifkan!" };
    }
    
    // Cek expiry
    if (user.expiresAt && Date.now() > user.expiresAt) {
        return { valid: false, code: "KEY_EXPIRED", message: "Kunci sudah kadaluarsa!" };
    }
    
    // Cek HWID blacklist
    if (blacklist.hwids.has(hwid)) {
        return { valid: false, code: "HWID_BANNED", message: "Perangkat Anda diblokir!" };
    }
    
    // HWID Lock
    if (user.hwid === null) {
        user.hwid = hwid;
        console.log(`[DATABASE] Key ${key} bound to HWID: ${hwid.substring(0, 15)}...`);
    } else if (user.hwid !== hwid) {
        return { 
            valid: false, 
            code: "HWID_MISMATCH",
            message: "Kunci sudah digunakan di perangkat lain!" 
        };
    }
    
    // Update stats
    user.usageCount++;
    user.lastUsed = Date.now();
    user.lastIP = ip;
    
    // Ambil script dari ENV
    const script = getScriptFromEnv(user.plan);
    
    if (!script) {
        return { valid: false, code: "SCRIPT_ERROR", message: "Gagal memuat script!" };
    }
    
    return {
        valid: true,
        plan: user.plan,
        script: script,
        expiresAt: user.expiresAt
    };
}

// ===== FUNGSI: Admin =====
function resetHWID(key) {
    if (keys[key]) {
        keys[key].hwid = null;
        console.log(`[DATABASE] HWID reset for: ${key}`);
        return true;
    }
    return false;
}

function disableKey(key, reason) {
    if (keys[key]) {
        keys[key].active = false;
        console.log(`[DATABASE] Key disabled: ${key} - ${reason}`);
        return true;
    }
    return false;
}

function addKey(key, plan, expiresInDays = null) {
    if (keys[key]) {
        return false; // Already exists
    }
    
    keys[key] = {
        hwid: null,
        plan: plan,
        active: true,
        createdAt: Date.now(),
        expiresAt: expiresInDays ? Date.now() + (expiresInDays * 24 * 60 * 60 * 1000) : null,
        usageCount: 0,
        lastUsed: null,
        lastIP: null
    };
    console.log(`[DATABASE] Key added: ${key} - Plan: ${plan}`);
    return true;
}

function getKeyInfo(key) {
    return keys[key] || null;
}

// ===== FUNGSI: Blacklist =====
function isIPBlacklisted(ip) {
    return blacklist.ips.has(ip);
}

function isHWIDBlacklisted(hwid) {
    return blacklist.hwids.has(hwid);
}

function blacklistIP(ip, reason) {
    blacklist.ips.set(ip, { reason, addedAt: Date.now() });
    console.log(`[BLACKLIST] IP added: ${ip} - ${reason}`);
}

function blacklistHWID(hwid, reason) {
    blacklist.hwids.set(hwid, { reason, addedAt: Date.now() });
    console.log(`[BLACKLIST] HWID added: ${hwid} - ${reason}`);
}

// ===== FUNGSI: Logging =====
function logAccess(key, hwid, ip, success, code, message) {
    const entry = {
        timestamp: new Date().toISOString(),
        key: key || 'N/A',
        hwid: hwid ? hwid.substring(0, 12) + '...' : 'N/A',
        ip: ip,
        success: success,
        code: code,
        message: message
    };
    
    accessLogs.push(entry);
    
    // Keep last 500 logs
    if (accessLogs.length > 500) {
        accessLogs.shift();
    }
    
    return entry;
}

function getLogs(limit = 50) {
    return accessLogs.slice(-limit);
}

// ===== FUNGSI: Generate Key =====
function generateKey(prefix = "KEY") {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let result = prefix + "-";
    for (let i = 0; i < 16; i++) {
        if (i > 0 && i % 4 === 0) result += "-";
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

module.exports = {
    validateKey,
    resetHWID,
    disableKey,
    addKey,
    getKeyInfo,
    isIPBlacklisted,
    isHWIDBlacklisted,
    blacklistIP,
    blacklistHWID,
    logAccess,
    getLogs,
    generateKey,
    getScriptFromEnv
};
