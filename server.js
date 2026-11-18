'use strict';

/**
 * Stellar Legacy — маленький сервер без зависимостей.
 *
 * Что делает:
 *  - отдаёт index.html и папку assets;
 *  - принимает вход через Google / GitHub / GitLab (OAuth 2.0);
 *  - создаёт и хранит аккаунты в data/users.json;
 *  - держит сессию в подписанной HttpOnly cookie.
 *
 * Запуск: node server.js  (или npm start)
 * Настройка провайдеров: см. AUTH-SETUP.md и .env.example
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;

function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  const text = fs.readFileSync(file, 'utf8');
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

loadEnv(path.join(ROOT, '.env'));

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSION_COOKIE = 'sl_session';
const STATE_COOKIE = 'sl_oauth_state';
const SESSION_DAYS = 30;
const IS_HTTPS = PUBLIC_URL.startsWith('https://');

const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',')
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);

const PROVIDERS = {
  google: {
    label: 'Google',
    clientId: process.env.GOOGLE_CLIENT_ID || '',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scope: 'openid email profile',
    extraAuth: { prompt: 'select_account', access_type: 'online' },
  },
  github: {
    label: 'GitHub',
    clientId: process.env.GITHUB_CLIENT_ID || '',
    clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    scope: 'read:user user:email',
  },
  gitlab: {
    label: 'GitLab',
    clientId: process.env.GITLAB_CLIENT_ID || '',
    clientSecret: process.env.GITLAB_CLIENT_SECRET || '',
    authorizeUrl: 'https://gitlab.com/oauth/authorize',
    tokenUrl: 'https://gitlab.com/oauth/token',
    scope: 'read_user',
  },
};

const PROVIDER_LABELS = {
  google: 'Google',
  github: 'GitHub',
  gitlab: 'GitLab',
};

function providerReady(provider) {
  const config = PROVIDERS[provider];
  return Boolean(config && config.clientId && config.clientSecret);
}

/* ------------------------------------------------------------------ */
/*  Пользователи                                                       */
/* ------------------------------------------------------------------ */

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readDb() {
  ensureDataDir();
  try {
    const parsed = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    if (Array.isArray(parsed.users)) return parsed;
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.error('Не удалось прочитать data/users.json:', error.message);
    }
  }
  return { users: [] };
}

function writeDb(db) {
  ensureDataDir();
  const temporary = `${USERS_FILE}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(db, null, 2));
  fs.renameSync(temporary, USERS_FILE);
}

let cachedSecret = null;

function sessionSecret() {
  if (cachedSecret) return cachedSecret;
  if (process.env.SESSION_SECRET) {
    cachedSecret = process.env.SESSION_SECRET;
    return cachedSecret;
  }
  ensureDataDir();
  const file = path.join(DATA_DIR, 'session-secret');
  try {
    const saved = fs.readFileSync(file, 'utf8').trim();
    if (saved) {
      cachedSecret = saved;
      return cachedSecret;
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  cachedSecret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(file, cachedSecret, { mode: 0o600 });
  return cachedSecret;
}

function signSession(payload) {
  return crypto.createHmac('sha256', sessionSecret()).update(payload).digest('base64url');
}

function makeSession(userId) {
  const payload = Buffer.from(
    JSON.stringify({ u: userId, exp: Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000 })
  ).toString('base64url');
  return `${payload}.${signSession(payload)}`;
}

function verifySession(token) {
  if (!token || typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const payload = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  const expected = signSession(payload);
  const given = Buffer.from(signature);
  const wanted = Buffer.from(expected);
  if (given.length !== wanted.length || !crypto.timingSafeEqual(given, wanted)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data.u || !data.exp || data.exp < Date.now()) return null;
    return data.u;
  } catch {
    return null;
  }
}

function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    try {
      cookies[key] = decodeURIComponent(value);
    } catch {
      cookies[key] = value;
    }
  }
  return cookies;
}

function currentUser(request) {
  const cookies = parseCookies(request.headers.cookie || '');
  const userId = verifySession(cookies[SESSION_COOKIE]);
  if (!userId) return null;
  return readDb().users.find((user) => user.id === userId) || null;
}

function publicUser(user) {
  if (!user) return null;
  const identities = user.identities || [];
  return {
    id: user.id,
    nick: user.nick,
    name: user.name || null,
    email: user.email || null,
    avatar: user.avatar || null,
    role: user.role || 'player',
    provider: identities[0] ? identities[0].provider : null,
    providers: identities.map((identity) => identity.provider),
    createdAt: user.createdAt || null,
  };
}

function uniqueNick(db, base) {
  const clean = String(base || 'player')
    .replace(/[^\p{L}\p{N}_.-]/gu, '')
    .slice(0, 24) || 'player';
  const taken = new Set(db.users.map((user) => String(user.nick).toLowerCase()));
  let candidate = clean;
  let index = 2;
  while (taken.has(candidate.toLowerCase())) {
    candidate = `${clean}${index}`;
    index += 1;
  }
  return candidate;
}

function upsertUser(profile) {
  const db = readDb();
  const identities = (user) => (Array.isArray(user.identities) ? user.identities : []);

  let user = db.users.find((candidate) =>
    identities(candidate).some(
      (identity) =>
        identity.provider === profile.provider && String(identity.id) === String(profile.providerId)
    )
  );

  let created = false;

  // Если почта подтверждена и такой аккаунт уже есть — привязываем новый способ входа.
  if (!user && profile.email && profile.emailVerified) {
    user = db.users.find(
      (candidate) =>
        candidate.email && candidate.email.toLowerCase() === profile.email.toLowerCase()
    );
    if (user) {
      const list = identities(user);
      if (
        !list.some(
          (identity) =>
            identity.provider === profile.provider &&
            String(identity.id) === String(profile.providerId)
        )
      ) {
        list.push({ provider: profile.provider, id: String(profile.providerId), login: profile.login });
        user.identities = list;
      }
    }
  }

  if (!user) {
    user = {
      id: crypto.randomUUID(),
      nick: uniqueNick(db, profile.login || profile.name || 'player'),
      name: profile.name || null,
      email: profile.email || null,
      avatar: profile.avatar || null,
      role:
        profile.email && ADMIN_EMAILS.includes(profile.email.toLowerCase()) ? 'admin' : 'player',
      createdAt: new Date().toISOString(),
      lastLoginAt: null,
      identities: [
        {
          provider: profile.provider,
          id: String(profile.providerId),
          login: profile.login || null,
        },
      ],
    };
    db.users.push(user);
    created = true;
  } else {
    if (profile.avatar) user.avatar = profile.avatar;
    if (profile.name) user.name = profile.name;
    if (!user.email && profile.email) user.email = profile.email;
    if (profile.email && ADMIN_EMAILS.includes(profile.email.toLowerCase())) user.role = 'admin';
    user.identities = identities(user);
    if (
      !user.identities.some(
        (identity) =>
          identity.provider === profile.provider &&
          String(identity.id) === String(profile.providerId)
      )
    ) {
      user.identities.push({
        provider: profile.provider,
        id: String(profile.providerId),
        login: profile.login || null,
      });
    }
  }

  user.lastLoginAt = new Date().toISOString();
  writeDb(db);
  return { user, created };
}

/* ------------------------------------------------------------------ */
/*  OAuth                                                              */
/* ------------------------------------------------------------------ */

function callbackUrl(provider) {
  return `${PUBLIC_URL}/auth/${provider}/callback`;
}

function buildAuthorizeUrl(provider, state) {
  const config = PROVIDERS[provider];
  const url = new URL(config.authorizeUrl);
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', callbackUrl(provider));
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', config.scope);
  url.searchParams.set('state', state);
  if (provider === 'github') url.searchParams.set('allow_signup', 'true');
  for (const [key, value] of Object.entries(config.extraAuth || {})) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

async function exchangeCode(provider, code) {
  const config = PROVIDERS[provider];
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    redirect_uri: callbackUrl(provider),
    grant_type: 'authorization_code',
  });
  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body,
  });
  const data = await response.json().catch(() => null);
  if (!response.ok || !data || !data.access_token) {
    throw new Error(`token_exchange_failed:${response.status}`);
  }
  return data.access_token;
}

async function fetchGoogleProfile(token) {
  const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error('google_profile_failed');
  const profile = await response.json();
  if (!profile.sub) throw new Error('google_profile_empty');
  return {
    provider: 'google',
    providerId: String(profile.sub),
    login: profile.email ? profile.email.split('@')[0] : profile.name || 'player',
    name: profile.name || null,
    email: profile.email ? profile.email.toLowerCase() : null,
    emailVerified: Boolean(profile.email_verified),
    avatar: profile.picture || null,
  };
}

async function fetchGitHubProfile(token) {
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': 'Stellar-Legacy-Portal',
  };
  const response = await fetch('https://api.github.com/user', { headers });
  if (!response.ok) throw new Error('github_profile_failed');
  const profile = await response.json();

  let email = profile.email ? String(profile.email).toLowerCase() : null;
  let emailVerified = Boolean(email);

  if (!email) {
    try {
      const emailsResponse = await fetch('https://api.github.com/user/emails', { headers });
      if (emailsResponse.ok) {
        const emails = await emailsResponse.json();
        const primary =
          emails.find((item) => item.primary && item.verified) ||
          emails.find((item) => item.verified);
        if (primary) {
          email = String(primary.email).toLowerCase();
          emailVerified = true;
        }
      }
    } catch {
      // GitHub может не отдать список почт — это не критично.
    }
  }

  return {
    provider: 'github',
    providerId: String(profile.id),
    login: profile.login || 'player',
    name: profile.name || null,
    email,
    emailVerified,
    avatar: profile.avatar_url || null,
  };
}

async function fetchGitLabProfile(token) {
  const response = await fetch('https://gitlab.com/api/v4/user', {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
      'User-Agent': 'Stellar-Legacy-Portal',
    },
  });
  if (!response.ok) throw new Error('gitlab_profile_failed');
  const profile = await response.json();
  if (!profile.id) throw new Error('gitlab_profile_empty');

  let avatar = profile.avatar_url || null;
  if (avatar && avatar.startsWith('/')) avatar = `https://gitlab.com${avatar}`;

  return {
    provider: 'gitlab',
    providerId: String(profile.id),
    login: profile.username || 'player',
    name: profile.name || null,
    email: profile.email ? String(profile.email).toLowerCase() : null,
    emailVerified: Boolean(profile.email),
    avatar,
  };
}

async function fetchProfile(provider, token) {
  if (provider === 'google') return fetchGoogleProfile(token);
  if (provider === 'github') return fetchGitHubProfile(token);
  if (provider === 'gitlab') return fetchGitLabProfile(token);
  throw new Error('unknown_provider');
}

/* ------------------------------------------------------------------ */
/*  HTTP                                                               */
/* ------------------------------------------------------------------ */

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.woff2': 'font/woff2',
};

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  response.end(body);
}

function redirect(response, location, cookies = []) {
  const headers = { Location: location, 'Cache-Control': 'no-store' };
  if (cookies.length) headers['Set-Cookie'] = cookies;
  response.writeHead(302, headers);
  response.end();
}

function sessionCookie(value, maxAgeSeconds) {
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (IS_HTTPS) parts.push('Secure');
  return parts.join('; ');
}

function stateCookie(value, maxAgeSeconds) {
  const parts = [
    `${STATE_COOKIE}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (IS_HTTPS) parts.push('Secure');
  return parts.join('; ');
}

function serveStatic(request, response, pathname) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    sendJson(response, 405, { error: 'method_not_allowed' });
    return;
  }

  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    sendJson(response, 400, { error: 'bad_path' });
    return;
  }

  if (decoded === '/' || decoded === '') decoded = '/index.html';

  const absolute = path.normalize(path.join(ROOT, decoded));
  const relative = path.relative(ROOT, absolute);
  const allowed = relative === 'index.html' || relative === 'intro.mp4' || relative.startsWith(`assets${path.sep}`);

  if (!allowed || relative.startsWith('..')) {
    sendJson(response, 404, { error: 'not_found' });
    return;
  }

  let stats;
  try {
    stats = fs.statSync(absolute);
  } catch {
    sendJson(response, 404, { error: 'not_found' });
    return;
  }
  if (!stats.isFile()) {
    sendJson(response, 404, { error: 'not_found' });
    return;
  }

  const extension = path.extname(absolute).toLowerCase();
  const contentType = MIME_TYPES[extension] || 'application/octet-stream';
  const cacheControl = extension === '.html' ? 'no-cache' : 'public, max-age=3600';

  // Safari/iOS просит видео кусками (Range) — без этого заставка может не играть.
  const rangeHeader = String(request.headers.range || '');
  const rangeMatch = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader);
  if (rangeMatch && (rangeMatch[1] || rangeMatch[2])) {
    let start = rangeMatch[1] ? Number(rangeMatch[1]) : null;
    let end = rangeMatch[2] ? Number(rangeMatch[2]) : null;

    if (start === null) {
      start = Math.max(0, stats.size - end);
      end = stats.size - 1;
    } else if (end === null || end >= stats.size) {
      end = stats.size - 1;
    }

    if (start >= stats.size || start > end) {
      response.writeHead(416, { 'Content-Range': `bytes */${stats.size}` });
      response.end();
      return;
    }

    response.writeHead(206, {
      'Content-Type': contentType,
      'Content-Length': end - start + 1,
      'Content-Range': `bytes ${start}-${end}/${stats.size}`,
      'Accept-Ranges': 'bytes',
      'Cache-Control': cacheControl,
    });
    if (request.method === 'HEAD') {
      response.end();
      return;
    }
    fs.createReadStream(absolute, { start, end }).pipe(response);
    return;
  }

  response.writeHead(200, {
    'Content-Type': contentType,
    'Content-Length': stats.size,
    'Accept-Ranges': 'bytes',
    'Cache-Control': cacheControl,
  });
  if (request.method === 'HEAD') {
    response.end();
    return;
  }
  fs.createReadStream(absolute).pipe(response);
}

async function handleAuthStart(request, response, provider) {
  if (!providerReady(provider)) {
    redirect(response, `/?auth_error=${provider}_not_configured`);
    return;
  }
  const state = crypto.randomBytes(24).toString('base64url');
  redirect(response, buildAuthorizeUrl(provider, state), [stateCookie(`${provider}:${state}`, 600)]);
}

async function handleAuthCallback(request, response, provider, url) {
  if (!providerReady(provider)) {
    redirect(response, `/?auth_error=${provider}_not_configured`);
    return;
  }

  const state = url.searchParams.get('state') || '';
  const code = url.searchParams.get('code') || '';
  const cookies = parseCookies(request.headers.cookie || '');
  const expectedState = cookies[STATE_COOKIE] || '';
  const clearState = stateCookie('', 0);

  if (!state || !expectedState || expectedState !== `${provider}:${state}`) {
    redirect(response, '/?auth_error=state', [clearState]);
    return;
  }
  if (!code) {
    redirect(response, '/?auth_error=cancelled', [clearState]);
    return;
  }

  try {
    const token = await exchangeCode(provider, code);
    const profile = await fetchProfile(provider, token);
    const { user, created } = upsertUser(profile);
    const session = makeSession(user.id);
    console.log(`Вход: ${PROVIDER_LABELS[provider]} → ${user.nick} (${created ? 'новый' : 'существующий'})`);
    redirect(response, `/?auth=${created ? 'created' : 'ok'}`, [
      clearState,
      sessionCookie(session, SESSION_DAYS * 24 * 60 * 60),
    ]);
  } catch (error) {
    console.error(`OAuth ${provider}:`, error.message);
    redirect(response, '/?auth_error=provider', [clearState]);
  }
}

function createServer() {
  return http.createServer(async (request, response) => {
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.setHeader('X-Frame-Options', 'DENY');

    try {
      const url = new URL(request.url || '/', PUBLIC_URL);
      const pathname = url.pathname;

      if (pathname === '/api/config' && request.method === 'GET') {
        sendJson(response, 200, {
          server: true,
          providers: {
            google: providerReady('google'),
            github: providerReady('github'),
            gitlab: providerReady('gitlab'),
          },
        });
        return;
      }

      if (pathname === '/api/me' && request.method === 'GET') {
        sendJson(response, 200, { user: publicUser(currentUser(request)) });
        return;
      }

      if (pathname === '/api/logout' && request.method === 'POST') {
        response.setHeader('Set-Cookie', sessionCookie('', 0));
        sendJson(response, 200, { ok: true });
        return;
      }

      const authMatch = pathname.match(/^\/auth\/(google|github|gitlab)(\/callback)?$/);
      if (authMatch) {
        const provider = authMatch[1];
        if (authMatch[2]) {
          await handleAuthCallback(request, response, provider, url);
        } else {
          await handleAuthStart(request, response, provider);
        }
        return;
      }

      serveStatic(request, response, pathname);
    } catch (error) {
      console.error('Ошибка запроса:', error);
      if (!response.headersSent) {
        sendJson(response, 500, { error: 'server_error' });
      } else {
        response.end();
      }
    }
  });
}

function startServer(port = PORT) {
  const server = createServer();
  server.listen(port, () => {
    const actualPort = server.address().port;
    const address = PUBLIC_URL || `http://localhost:${actualPort}`;
    console.log('');
    console.log(`  ✧ Stellar Legacy — сервер запущен`);
    console.log(`  → ${address}`);
    console.log('');
    console.log(`  OAuth: Google ${providerReady('google') ? '✓' : '—'}   GitHub ${providerReady('github') ? '✓' : '—'}   GitLab ${providerReady('gitlab') ? '✓' : '—'}`);
    if (!providerReady('google') && !providerReady('github') && !providerReady('gitlab')) {
      console.log('  Провайдеры не настроены: заполни .env (см. AUTH-SETUP.md)');
    }
    console.log('');
  });
  return server;
}

module.exports = {
  createServer,
  startServer,
  upsertUser,
  publicUser,
  readDb,
  verifySession,
  makeSession,
  PROVIDERS,
  providerReady,
  DATA_DIR,
  USERS_FILE,
};

if (require.main === module) {
  startServer();
}
