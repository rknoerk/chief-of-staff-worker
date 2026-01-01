/**
 * Chief of Staff - Cloudflare Worker
 * Full server implementation with KV storage
 */

// Helper functions
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
    },
  });
}

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

async function hashToken(token) {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Main handler
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
        },
      });
    }

    // Config from environment
    const GMAIL_CLIENT_ID = env.GMAIL_CLIENT_ID || '';
    const GMAIL_CLIENT_SECRET = env.GMAIL_CLIENT_SECRET || '';
    const GMAIL_ACCOUNTS = (env.GMAIL_ACCOUNTS || '').split(',').filter(e => e.trim());
    const API_KEY = env.API_KEY || '';
    const SERVER_URL = env.SERVER_URL || `https://${url.host}`;

    // Auth check function
    async function checkAuth(allowApiKey = false) {
      const token = url.searchParams.get('token') ||
                    (request.headers.get('Authorization') || '').replace('Bearer ', '');

      if (token) {
        const tokenHash = await hashToken(token);
        const devicesJson = await env.KV.get('devices');
        const devices = devicesJson ? JSON.parse(devicesJson) : { devices: [] };

        for (const device of devices.devices) {
          if (device.token_hash === tokenHash) {
            const expiresAt = new Date(device.expires_at);
            if (expiresAt > new Date()) {
              return true;
            }
          }
        }
      }

      if (allowApiKey && API_KEY) {
        if (url.searchParams.get('key') === API_KEY) return true;
        if (request.headers.get('X-API-Key') === API_KEY) return true;
      }

      return false;
    }

    // === PUBLIC ROUTES ===

    if (path === '/' || path === '') {
      return jsonResponse({ service: 'Chief of Staff', login: `${SERVER_URL}/login` });
    }

    if (path === '/health') {
      const tasks = JSON.parse(await env.KV.get('tasks') || '{"tasks":[]}');
      const notes = JSON.parse(await env.KV.get('notes') || '{"notes":[]}');
      const devices = JSON.parse(await env.KV.get('devices') || '{"devices":[]}');
      const context = JSON.parse(await env.KV.get('context') || '{"files":{}}');

      return jsonResponse({
        status: 'ok',
        storage: 'cloudflare-kv',
        tasks: tasks.tasks?.length || 0,
        notes: notes.notes?.length || 0,
        context_files: Object.keys(context.files || {}),
        gmail_accounts: GMAIL_ACCOUNTS.length,
        devices: devices.devices?.length || 0,
      });
    }

    // === GOOGLE SIGN-IN ===

    if (path === '/login') {
      const params = new URLSearchParams({
        client_id: GMAIL_CLIENT_ID,
        redirect_uri: `${SERVER_URL}/callback`,
        response_type: 'code',
        scope: 'openid email profile',
        access_type: 'online',
        prompt: 'select_account',
      });
      return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, 302);
    }

    if (path === '/callback') {
      const code = url.searchParams.get('code');
      const error = url.searchParams.get('error');

      if (error) return htmlResponse(`<h1>Login Failed</h1><p>${error}</p>`, 400);
      if (!code) return htmlResponse('<h1>Login Failed</h1><p>No code</p>', 400);

      try {
        // Exchange code for tokens
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            code,
            client_id: GMAIL_CLIENT_ID,
            client_secret: GMAIL_CLIENT_SECRET,
            redirect_uri: `${SERVER_URL}/callback`,
            grant_type: 'authorization_code',
          }),
        });
        const tokens = await tokenRes.json();

        if (!tokens.id_token) {
          return htmlResponse(`<h1>Error</h1><p>${JSON.stringify(tokens)}</p>`, 400);
        }

        // Decode JWT to get email (simple decode, not verified)
        const payload = JSON.parse(atob(tokens.id_token.split('.')[1]));
        const email = payload.email;
        const name = payload.name || 'User';

        if (!GMAIL_ACCOUNTS.includes(email)) {
          return htmlResponse(`
            <html><body style="font-family:system-ui;padding:40px;max-width:500px;margin:0 auto;">
            <h1>Access Denied</h1>
            <p>Email <strong>${email}</strong> is not authorized.</p>
            <p><a href="/login">Try another account</a></p>
            </body></html>
          `, 403);
        }

        // Create device token
        const deviceToken = generateToken();
        const tokenHash = await hashToken(deviceToken);

        const devicesJson = await env.KV.get('devices');
        const devices = devicesJson ? JSON.parse(devicesJson) : { devices: [] };

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 90);

        devices.devices.push({
          token_hash: tokenHash,
          email,
          device_name: 'Web Browser',
          created_at: new Date().toISOString(),
          expires_at: expiresAt.toISOString(),
        });

        await env.KV.put('devices', JSON.stringify(devices));

        return htmlResponse(`
          <html><head>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            body { font-family: -apple-system, sans-serif; padding: 40px; max-width: 500px; margin: 0 auto; background: #f5f5f5; }
            .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #1a73e8; margin-top: 0; }
            .token { background: #f0f0f0; padding: 15px; border-radius: 8px; word-break: break-all; font-family: monospace; font-size: 14px; margin: 20px 0; }
            .btn { background: #1a73e8; color: white; border: none; padding: 12px 24px; border-radius: 6px; font-size: 16px; cursor: pointer; width: 100%; }
          </style>
          </head><body>
          <div class="card">
            <h1>Welcome, ${name}!</h1>
            <p>Your token (valid 90 days):</p>
            <div class="token">${deviceToken}</div>
            <button class="btn" onclick="navigator.clipboard.writeText('${deviceToken}').then(()=>this.textContent='Copied!')">Copy Token</button>
          </div>
          </body></html>
        `);
      } catch (e) {
        return htmlResponse(`<h1>Error</h1><p>${e.message}</p>`, 500);
      }
    }

    if (path === '/auth/status') {
      const token = url.searchParams.get('token');
      if (token && await checkAuth()) {
        return jsonResponse({ authenticated: true });
      }
      return jsonResponse({ authenticated: false });
    }

    // === PROTECTED ROUTES ===

    // Tasks
    if (path === '/tasks') {
      if (method === 'POST') {
        if (!await checkAuth(true)) return jsonResponse({ error: 'Unauthorized' }, 401);
        const data = await request.json();
        await env.KV.put('tasks', JSON.stringify({
          tasks: data.tasks || [],
          syncedAt: data.syncedAt || Date.now(),
        }));
        return jsonResponse({ success: true, count: data.tasks?.length || 0 });
      }
      if (!await checkAuth()) return jsonResponse({ error: 'Unauthorized' }, 401);
      const tasks = JSON.parse(await env.KV.get('tasks') || '{"tasks":[],"syncedAt":null}');
      return jsonResponse(tasks);
    }

    if (path === '/tasks/open') {
      if (!await checkAuth()) return jsonResponse({ error: 'Unauthorized' }, 401);
      const data = JSON.parse(await env.KV.get('tasks') || '{"tasks":[]}');
      const open = data.tasks.filter(t => !t.completedAt && !t.dismissedAt);
      return jsonResponse({ tasks: open, syncedAt: data.syncedAt });
    }

    if (path === '/tasks/today') {
      if (!await checkAuth()) return jsonResponse({ error: 'Unauthorized' }, 401);
      const data = JSON.parse(await env.KV.get('tasks') || '{"tasks":[]}');
      const now = Date.now() / 1000;
      const today = data.tasks
        .filter(t => !t.completedAt && !t.dismissedAt && (!t.startAt || t.startAt <= now) && (!t.hideUntil || t.hideUntil <= now))
        .sort((a, b) => (b.score || 0) - (a.score || 0));
      return jsonResponse({ tasks: today, syncedAt: data.syncedAt });
    }

    // Notes
    if (path === '/notes') {
      if (method === 'POST') {
        if (!await checkAuth(true)) return jsonResponse({ error: 'Unauthorized' }, 401);
        const data = await request.json();
        await env.KV.put('notes', JSON.stringify({
          notes: data.notes || [],
          syncedAt: data.syncedAt || Date.now(),
        }));
        return jsonResponse({ success: true, count: data.notes?.length || 0 });
      }
      if (!await checkAuth()) return jsonResponse({ error: 'Unauthorized' }, 401);
      const notes = JSON.parse(await env.KV.get('notes') || '{"notes":[],"syncedAt":null}');
      return jsonResponse(notes);
    }

    if (path === '/notes/werkbank') {
      if (!await checkAuth()) return jsonResponse({ error: 'Unauthorized' }, 401);
      const data = JSON.parse(await env.KV.get('notes') || '{"notes":[]}');
      const werkbank = data.notes.filter(n => n.type === 'werkbank');
      return jsonResponse({ notes: werkbank, syncedAt: data.syncedAt });
    }

    if (path === '/notes/projects') {
      if (!await checkAuth()) return jsonResponse({ error: 'Unauthorized' }, 401);
      const data = JSON.parse(await env.KV.get('notes') || '{"notes":[]}');
      const projects = data.notes.filter(n => n.type === 'project');
      return jsonResponse({ notes: projects, syncedAt: data.syncedAt });
    }

    // Context
    if (path === '/context') {
      if (method === 'POST') {
        if (!await checkAuth(true)) return jsonResponse({ error: 'Unauthorized' }, 401);
        const data = await request.json();
        await env.KV.put('context', JSON.stringify({
          files: data.files || {},
          syncedAt: data.syncedAt || Date.now(),
        }));
        return jsonResponse({ success: true, files: Object.keys(data.files || {}) });
      }
      if (!await checkAuth()) return jsonResponse({ error: 'Unauthorized' }, 401);
      const context = JSON.parse(await env.KV.get('context') || '{"files":{},"syncedAt":null}');
      return jsonResponse(context);
    }

    // Gmail (placeholder - tokens need to be uploaded)
    if (path === '/emails/unread' || path === '/emails/recent') {
      if (!await checkAuth()) return jsonResponse({ error: 'Unauthorized' }, 401);
      // Gmail API requires more complex implementation
      return jsonResponse({
        emails: [{ error: 'Gmail not configured yet. Upload tokens via /gmail/token' }],
        fetchedAt: new Date().toISOString()
      });
    }

    if (path === '/gmail/token' && method === 'POST') {
      if (!await checkAuth(true)) return jsonResponse({ error: 'Unauthorized' }, 401);
      const data = await request.json();
      if (data.email && data.token) {
        await env.KV.put(`gmail_token_${data.email}`, JSON.stringify(data.token));
        return jsonResponse({ success: true });
      }
      return jsonResponse({ error: 'Missing email or token' }, 400);
    }

    if (path === '/gmail/status') {
      if (!await checkAuth()) return jsonResponse({ error: 'Unauthorized' }, 401);
      const status = {};
      for (const email of GMAIL_ACCOUNTS) {
        const token = await env.KV.get(`gmail_token_${email}`);
        status[email] = token ? 'token_uploaded' : 'not_configured';
      }
      return jsonResponse(status);
    }

    return jsonResponse({ error: 'Not found' }, 404);
  },
};
