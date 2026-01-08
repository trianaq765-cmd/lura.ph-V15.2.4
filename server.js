// ===== ULTRA SECURE AUTH SERVER =====
// Script tersembunyi di Environment Variables
// Browser/Bot mendapat HTML trap

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const { detectorMiddleware } = require('./middleware/detector');
const apiRoutes = require('./routes/api');

const app = express();

// ===== SECURITY HEADERS =====
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// ===== MIDDLEWARE =====
app.use(cors());
app.use(bodyParser.json({ limit: '1mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Static files untuk trap
app.use('/static', express.static(path.join(__dirname, 'public')));

// ===== DETECTOR MIDDLEWARE (Harus sebelum routes!) =====
app.use(detectorMiddleware);

// ===== ROUTES =====
app.use('/api', apiRoutes);

// ===== CATCH-ALL: Semua path lain = trap =====
app.get('*', (req, res) => {
    console.log(`[TRAP] Catch-all triggered for: ${req.path}`);
    res.sendFile(path.join(__dirname, 'public', 'trap.html'));
});

app.post('*', (req, res) => {
    // Random fake response
    const responses = [
        { error: 'Method not allowed' },
        { status: 404 },
        { message: 'Service temporarily unavailable' },
        '',
        null
    ];
    res.status(400).json(responses[Math.floor(Math.random() * responses.length)]);
});

// ===== ERROR HANDLER =====
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log('╔═══════════════════════════════════════════════════╗');
    console.log('║     ULTRA SECURE SCRIPT AUTH SERVER               ║');
    console.log('║     Status: ONLINE                                ║');
    console.log(`║     Port: ${PORT}                                      ║`);
    console.log('║     Script Location: ENVIRONMENT VARIABLES        ║');
    console.log('║     Browser Access: TRAPPED                       ║');
    console.log(`║     Time: ${new Date().toISOString()}       ║`);
    console.log('╚═══════════════════════════════════════════════════╝');
    
    // Cek apakah script sudah di-set di ENV
    const premiumSet = !!process.env.SCRIPT_PREMIUM;
    const basicSet = !!process.env.SCRIPT_BASIC;
    
    console.log(`\n[ENV CHECK] SCRIPT_PREMIUM: ${premiumSet ? '✓ SET' : '✗ NOT SET'}`);
    console.log(`[ENV CHECK] SCRIPT_BASIC: ${basicSet ? '✓ SET' : '✗ NOT SET'}`);
    console.log(`[ENV CHECK] SECRET_KEY: ${process.env.SECRET_KEY ? '✓ SET' : '✗ USING DEFAULT'}`);
    console.log(`[ENV CHECK] ADMIN_PASSWORD: ${process.env.ADMIN_PASSWORD ? '✓ SET' : '✗ USING DEFAULT'}`);
});
