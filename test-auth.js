'use strict';

/**
 * Проверка OAuth-логики без настоящих Google/GitLab/GitHub:
 * сеть подменяется, но сервер, cookie, state и создание аккаунтов — настоящие.
 *
 * Запуск: npm test
 */

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stellar-auth-'));
process.env.DATA_DIR = tempDir;
process.env.PUBLIC_URL = 'http://localhost:3000';
process.env.SESSION_SECRET = 'test-secret-do-not-use-in-production';
process.env.GOOGLE_CLIENT_ID = 'google-id';
process.env.GOOGLE_CLIENT_SECRET = 'google-secret';
process.env.GITHUB_CLIENT_ID = 'github-id';
process.env.GITHUB_CLIENT_SECRET = 'github-secret';
process.env.GITLAB_CLIENT_ID = 'gitlab-id';
process.env.GITLAB_CLIENT_SECRET = 'gitlab-secret';

const { startServer, readDb } = require('./server');

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const profiles = {
  google: {
    sub: 'google-1',
    name: 'Зоя',
    email: 'zoe@example.com',
    email_verified: true,
    picture: 'https://example.com/zoe.png',
  },
  github: {
    id: 42,
    login: 'zoe-gh',
    name: 'Зоя ГХ',
    email: 'zoe@example.com',
    avatar_url: 'https://example.com/gh.png',
  },
  gitlab: {
    id: 7,
    username: 'zoe_gl',
    name: 'Зоя ГЛ',
    email: 'zoe.gl@example.com',
    avatar_url: '/uploads/zoe.png',
  },
};

global.fetch = async (url, options = {}) => {
  const target = String(url);

  if (target.includes('oauth2.googleapis.com/token')) return json({ access_token: 'google-token' });
  if (target.includes('www.googleapis.com/oauth2/v3/userinfo')) return json(profiles.google);

  if (target.includes('github.com/login/oauth/access_token')) return json({ access_token: 'github-token' });
  if (target.includes('api.github.com/user/emails')) return json([]);
  if (target.includes('api.github.com/user')) return json(profiles.github);

  if (target.includes('gitlab.com/oauth/token')) return json({ access_token: 'gitlab-token' });
  if (target.includes('gitlab.com/api/v4/user')) return json(profiles.gitlab);

  throw new Error(`Неожиданный внешний запрос: ${target}`);
};

function request(port, pathname, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: pathname,
        method: options.method || 'GET',
        headers: options.headers || {},
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          })
        );
      }
    );
    req.on('error', reject);
    req.end(options.body);
  });
}

function cookieValue(headers, name) {
  const list = headers['set-cookie'];
  if (!list) return null;
  for (const cookie of list) {
    if (cookie.startsWith(`${name}=`)) {
      return decodeURIComponent(cookie.slice(name.length + 1).split(';')[0]);
    }
  }
  return null;
}

async function login(port, provider) {
  const start = await request(port, `/auth/${provider}`);
  assert.strictEqual(start.status, 302, `${provider}: старт должен редиректить`);

  const authorizeUrl = new URL(start.headers.location);
  const state = authorizeUrl.searchParams.get('state');
  assert.ok(state, `${provider}: нет state в authorize URL`);
  assert.strictEqual(authorizeUrl.searchParams.get('redirect_uri'), `http://localhost:3000/auth/${provider}/callback`);

  const stateCookie = cookieValue(start.headers, 'sl_oauth_state');
  assert.strictEqual(stateCookie, `${provider}:${state}`, `${provider}: state cookie не совпал`);

  const callback = await request(
    port,
    `/auth/${provider}/callback?code=test-code&state=${encodeURIComponent(state)}`,
    { headers: { Cookie: `sl_oauth_state=${encodeURIComponent(`${provider}:${state}`)}` } }
  );
  assert.strictEqual(callback.status, 302, `${provider}: callback должен редиректить`);
  return { callback, session: cookieValue(callback.headers, 'sl_session') };
}

(async () => {
  const server = startServer(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const port = server.address().port;

  try {
    const index = await request(port, '/');
    assert.strictEqual(index.status, 200);
    assert.match(index.body, /Stellar Legacy/);

    const config = JSON.parse((await request(port, '/api/config')).body);
    assert.strictEqual(config.server, true);
    assert.deepStrictEqual(config.providers, { google: true, github: true, gitlab: true });

    const anonymous = JSON.parse((await request(port, '/api/me')).body);
    assert.strictEqual(anonymous.user, null);

    const google = await login(port, 'google');
    assert.strictEqual(google.callback.headers.location, '/?auth=created');
    assert.ok(google.session, 'Google: сессия не выставлена');

    const googleMe = JSON.parse(
      (await request(port, '/api/me', { headers: { Cookie: `sl_session=${encodeURIComponent(google.session)}` } })).body
    );
    assert.strictEqual(googleMe.user.nick, 'zoe');
    assert.strictEqual(googleMe.user.provider, 'google');
    assert.strictEqual(googleMe.user.email, 'zoe@example.com');

    const github = await login(port, 'github');
    assert.strictEqual(github.callback.headers.location, '/?auth=ok', 'GitHub должен привязаться к аккаунту по email');

    const gitlab = await login(port, 'gitlab');
    assert.strictEqual(gitlab.callback.headers.location, '/?auth=created');

    const db = readDb();
    assert.strictEqual(db.users.length, 2, 'Ожидается 2 аккаунта: общий Google+GitHub и отдельный GitLab');
    const linked = db.users.find((user) => user.email === 'zoe@example.com');
    assert.deepStrictEqual(
      linked.identities.map((identity) => identity.provider).sort(),
      ['github', 'google']
    );
    const gitlabUser = db.users.find((user) => user.email === 'zoe.gl@example.com');
    assert.ok(gitlabUser);
    assert.strictEqual(gitlabUser.avatar, 'https://gitlab.com/uploads/zoe.png');

    const logout = await request(port, '/api/logout', {
      method: 'POST',
      headers: { Cookie: `sl_session=${encodeURIComponent(google.session)}` },
    });
    assert.strictEqual(logout.status, 200);
    assert.match(logout.headers['set-cookie'][0], /Max-Age=0/);

    console.log('OK: OAuth, state, cookie, создание аккаунта и привязка по email работают.');
    console.log(`Тестовых аккаунтов: ${db.users.length}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error('FAIL:', error);
  process.exitCode = 1;
});
