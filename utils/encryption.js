// ===== ENCRYPTION MODULE =====
const crypto = require('crypto');

// SHA256 Hash
function sha256(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
}

// SHA512 Hash
function sha512(text) {
    return crypto.createHash('sha512').update(text).digest('hex');
}

// XOR Encryption dengan salt dinamis
function xorEncrypt(text, key) {
    const salt = sha256(key).substring(0, 8);
    const fullKey = salt + key + salt;
    
    let result = "";
    for (let i = 0; i < text.length; i++) {
        const charCode = text.charCodeAt(i) ^ fullKey.charCodeAt(i % fullKey.length);
        result += String.fromCharCode(charCode);
    }
    return Buffer.from(result, 'binary').toString('base64');
}

function xorDecrypt(encryptedBase64, key) {
    const salt = sha256(key).substring(0, 8);
    const fullKey = salt + key + salt;
    
    const encrypted = Buffer.from(encryptedBase64, 'base64').toString('binary');
    let result = "";
    for (let i = 0; i < encrypted.length; i++) {
        const charCode = encrypted.charCodeAt(i) ^ fullKey.charCodeAt(i % fullKey.length);
        result += String.fromCharCode(charCode);
    }
    return result;
}

// AES-256-GCM Encryption (lebih aman dari CBC)
function aesEncrypt(text, secretKey) {
    const key = crypto.createHash('sha256').update(secretKey).digest();
    const iv = crypto.randomBytes(12); // GCM uses 12 bytes IV
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag().toString('hex');
    
    // Format: iv:authTag:encryptedData
    return iv.toString('hex') + ':' + authTag + ':' + encrypted;
}

function aesDecrypt(encryptedData, secretKey) {
    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    
    const key = crypto.createHash('sha256').update(secretKey).digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

// Generate Dynamic Key berdasarkan waktu dan HWID
function generateDynamicKey(hwid, timestamp, secret) {
    const hour = Math.floor(timestamp / 3600); // Berubah setiap jam
    const payload = `${hwid}:${hour}:${secret}`;
    return sha256(payload).substring(0, 32);
}

// Generate Session Token
function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Generate Nonce
function generateNonce() {
    return crypto.randomBytes(16).toString('hex') + Date.now().toString(36);
}

// HMAC untuk signing
function hmacSign(data, secret) {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function hmacVerify(data, signature, secret) {
    const expected = hmacSign(data, secret);
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

module.exports = {
    sha256,
    sha512,
    xorEncrypt,
    xorDecrypt,
    aesEncrypt,
    aesDecrypt,
    generateDynamicKey,
    generateSessionToken,
    generateNonce,
    hmacSign,
    hmacVerify
};
