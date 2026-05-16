// Tower Finance - Kariérny systém
// Worker handles login, session, data API, and serves static assets

const SESSION_COOKIE = 'tf_session';
const SESSION_TTL_DAYS = 30;

// Generate a random session token
function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Parse cookies from request
function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const cookies = Object.fromEntries(
    cookieHeader.split(';').map(c => {
      const [k, ...v] = c.trim().split('=');
      return [k, v.join('=')];
    })
  );
  return cookies[name];
}

// Check if request is authenticated and return user role
async function getSession(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const data = await env.DATA.get(`session:${token}`);
  if (!data) return null;
  try {
    return JSON.parse(data); // { role: 'admin' | 'user', created: timestamp }
  } catch {
    return null;
  }
}

// JSON response helper
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers }
  });
}

// Login handler
async function handleLogin(request, env) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON' }, 400);
  }
  const { password } = body;
  if (!password) return json({ error: 'Heslo je povinné' }, 400);

  // Check against env secrets
  const adminPwd = env.ADMIN_PASSWORD;
  const userPwd = env.USER_PASSWORD;

  let role = null;
  if (adminPwd && password === adminPwd) role = 'admin';
  else if (userPwd && password === userPwd) role = 'user';

  if (!role) return json({ error: 'Nesprávne heslo' }, 401);

  // Create session
  const token = generateToken();
  const session = { role, created: Date.now() };
  await env.DATA.put(`session:${token}`, JSON.stringify(session), {
    expirationTtl: SESSION_TTL_DAYS * 24 * 60 * 60
  });

  return json({ ok: true, role }, 200, {
    'Set-Cookie': `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_DAYS * 24 * 60 * 60}`
  });
}

// Logout handler
async function handleLogout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (token) await env.DATA.delete(`session:${token}`);
  return json({ ok: true }, 200, {
    'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
  });
}

// Get all data (everyone with session can read)
async function handleGetData(request, env, session) {
  const keys = ['imports', 'warnings', 'cesta', 'pozicie', 'bruto', 'poznamky', 'ev_poznamky', 'pb_dismissed'];
  const result = {};
  for (const k of keys) {
    const v = await env.DATA.get(`app:${k}`);
    result[k] = v ? JSON.parse(v) : null;
  }
  return json({ ok: true, data: result, role: session.role });
}

// Save data (only admin can write)
async function handleSaveData(request, env, session) {
  if (session.role !== 'admin') return json({ error: 'Iba admin môže meniť dáta' }, 403);
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON' }, 400);
  }
  const { key, value } = body;
  const allowedKeys = ['imports', 'warnings', 'cesta', 'pozicie', 'bruto', 'poznamky', 'ev_poznamky', 'pb_dismissed'];
  if (!allowedKeys.includes(key)) return json({ error: 'Neznámy kľúč' }, 400);
  await env.DATA.put(`app:${key}`, JSON.stringify(value));
  return json({ ok: true });
}

// Check session endpoint (used by frontend to verify login)
async function handleSession(request, env, session) {
  return json({ ok: true, role: session.role });
}

// Login page HTML
function loginPageHTML() {
  return `<!DOCTYPE html>
<html lang="sk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Prihlásenie · Tower Finance</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: 'Archivo', -apple-system, sans-serif;
  background: #0E3318;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.login-box {
  background: #fff;
  border-radius: 16px;
  padding: 48px 40px;
  width: 100%;
  max-width: 420px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.3);
}
.logo {
  display: block;
  margin: 0 auto 8px;
  max-width: 220px;
  height: auto;
}
.subtitle {
  text-align: center;
  font-size: 11px;
  color: #7aa388;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  font-weight: 600;
  margin-bottom: 32px;
}
h1 {
  font-size: 22px;
  font-weight: 700;
  color: #0E3318;
  text-align: center;
  margin-bottom: 24px;
}
.form-group { margin-bottom: 18px; }
label {
  display: block;
  font-size: 12px;
  font-weight: 600;
  color: #0E3318;
  margin-bottom: 6px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
input[type="password"] {
  width: 100%;
  padding: 12px 14px;
  border: 2px solid #e8e8e8;
  border-radius: 8px;
  font-family: 'Archivo', sans-serif;
  font-size: 15px;
  transition: border-color 0.2s;
}
input[type="password"]:focus {
  outline: none;
  border-color: #3CD64E;
}
button {
  width: 100%;
  padding: 14px;
  background: #0E3318;
  color: #3CD64E;
  border: none;
  border-radius: 8px;
  font-family: 'Archivo', sans-serif;
  font-size: 15px;
  font-weight: 700;
  cursor: pointer;
  text-transform: uppercase;
  letter-spacing: 1px;
  transition: background 0.2s;
  margin-top: 8px;
}
button:hover { background: #1a4128; }
button:disabled { opacity: 0.6; cursor: not-allowed; }
.error {
  background: #fee;
  border: 1px solid #fcc;
  color: #c00;
  padding: 10px 12px;
  border-radius: 6px;
  font-size: 13px;
  margin-bottom: 14px;
  display: none;
}
.error.show { display: block; }
.footer {
  text-align: center;
  margin-top: 24px;
  font-size: 11px;
  color: #999;
}
</style>
</head>
<body>
<div class="login-box">
  <img class="logo" src="/5_TF_2025_rgb.png" alt="Tower Finance" onerror="this.style.display='none'">
  <div class="subtitle">Kariérny systém</div>
  <h1>Prihlásenie</h1>
  <div class="error" id="error"></div>
  <form id="login-form">
    <div class="form-group">
      <label for="password">Heslo</label>
      <input type="password" id="password" name="password" required autofocus>
    </div>
    <button type="submit" id="submit-btn">Prihlásiť sa</button>
  </form>
  <div class="footer">© Tower Finance · 2026</div>
</div>
<script>
const form = document.getElementById('login-form');
const errorEl = document.getElementById('error');
const submitBtn = document.getElementById('submit-btn');
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorEl.classList.remove('show');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Prihlasujem...';
  const password = document.getElementById('password').value;
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await res.json();
    if (data.ok) {
      window.location.href = '/';
    } else {
      errorEl.textContent = data.error || 'Prihlásenie zlyhalo';
      errorEl.classList.add('show');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Prihlásiť sa';
    }
  } catch (err) {
    errorEl.textContent = 'Chyba spojenia. Skúste znova.';
    errorEl.classList.add('show');
    submitBtn.disabled = false;
    submitBtn.textContent = 'Prihlásiť sa';
  }
});
</script>
</body>
</html>`;
}

// Main fetch handler
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // API endpoints
    if (pathname === '/api/login') return handleLogin(request, env);
    if (pathname === '/api/logout') return handleLogout(request, env);

    // All other /api/* endpoints require session
    if (pathname.startsWith('/api/')) {
      const session = await getSession(request, env);
      if (!session) return json({ error: 'Neprihlásený' }, 401);

      if (pathname === '/api/session') return handleSession(request, env, session);
      if (pathname === '/api/data/get') return handleGetData(request, env, session);
      if (pathname === '/api/data/save') return handleSaveData(request, env, session);

      return json({ error: 'Neznámy endpoint' }, 404);
    }

    // Public assets (logo, favicon, fonts)
    const publicPaths = ['/5_TF_2025_rgb.png', '/favicon.ico'];
    if (publicPaths.includes(pathname)) {
      return env.ASSETS.fetch(request);
    }

    // Login page (if not authenticated)
    const session = await getSession(request, env);
    if (!session) {
      // Show login page for any route when not authenticated
      return new Response(loginPageHTML(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // Authenticated: serve the app (index.html and other assets)
    return env.ASSETS.fetch(request);
  }
};
