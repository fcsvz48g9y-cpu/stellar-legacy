# Вход через Google, GitHub и GitLab

Вход работает по-настоящему: OAuth 2.0, аккаунт создаётся на сервере и хранится
в `data/users.json`. Пароли не хранятся — их вообще нет, вход подтверждает сам сервис.

## Почему нельзя просто открыть index.html

OAuth требует адрес `http://` или `https://` и сервер, который обменивает код на токен.
Через `file://` кнопки входа покажут подсказку. Поэтому сайт запускается так:

```bash
npm start
```

или двойным кликом по `start.bat`. Открывать нужно `http://localhost:3000`.

Если Node.js ещё не установлен — поставь LTS с https://nodejs.org.

## 1. Создай `.env`

Скопируй `.env.example` в `.env` (в той же папке). Дальше заполняешь ключи.

`PUBLIC_URL` — адрес, по которому открывается сайт. Для локальной проверки:
`http://localhost:3000`. Для настоящего сайта — твой домен с `https://`.

## 2. Google

1. Открой https://console.cloud.google.com/apis/credentials
2. Создай проект (или выбери существующий).
3. `OAuth consent screen` → External → заполни название и почту.
   Пока приложение в режиме Testing, войти смогут только добавленные Test users.
   Чтобы пускать всех — опубликуй приложение (Publish app).
4. `Credentials` → `Create credentials` → `OAuth client ID` → тип **Web application**.
5. `Authorized redirect URIs`:
   - для локальной проверки: `http://localhost:3000/auth/google/callback`
   - для сайта: `https://твой-домен/auth/google/callback`
6. Скопируй Client ID и Client secret в `.env`:

```env
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

## 3. GitHub

1. Открой https://github.com/settings/developers → `OAuth Apps` → `New OAuth App`.
2. `Homepage URL`: `http://localhost:3000` (или твой домен).
3. `Authorization callback URL`: `http://localhost:3000/auth/github/callback`
4. Создай приложение и скопируй `Client ID`.
5. Нажми `Generate a new client secret` и сразу скопируй секрет.
6. Добавь в `.env`:

```env
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
```

## 4. GitLab

1. Открой https://gitlab.com/-/user_settings/applications
2. `New application`, название любое.
3. `Redirect URI`: `http://localhost:3000/auth/gitlab/callback`
4. `Confidential`: включено.
5. Scopes: только `read_user`.
6. Скопируй `Application ID` и `Secret` в `.env`:

```env
GITLAB_CLIENT_ID=...
GITLAB_CLIENT_SECRET=...
```

## 5. Перезапусти сервер

```bash
npm start
```

В консоли увидишь:

```
OAuth: Google ✓   GitHub ✓   GitLab ✓
```

Кнопки в окне входа станут активными. При первом входе создаётся аккаунт,
при следующих — тот же аккаунт находится по ID провайдера (или по подтверждённой почте).

## Админка

Впиши свою почту в `.env`:

```env
ADMIN_EMAILS=you@gmail.com
```

Перезапусти сервер и войди заново — в разделе «Новости» появится кнопка публикации.

## Что хранится

- `data/users.json` — id, ник, имя, email, аватар, способ входа, дата регистрации.
- Сессия — в HttpOnly cookie, подписана `SESSION_SECRET`, живёт 30 дней.
- Пароли, токены провайдеров и платёжные данные не сохраняются.

Файл `data/` и `.env` добавлены в `.gitignore` — не выкладывай их в публичный репозиторий.

## Частые ошибки

- `redirect_uri_mismatch` — адрес в настройках приложения не совпадает с
  `PUBLIC_URL` + `/auth/<provider>/callback`. Проверь символы и `http/https`.
- `invalid_client` — неверный Client ID/Secret или ключи не попали в `.env`.
- `provider_not_configured` — соответствующая пара ключей пустая, сервер нужно перезапустить.
- `state` — истекла или не совпала сессия входа. Попробуй ещё раз.
- Открыл `index.html` двойным кликом — OAuth не сможет работать, нужен `http://localhost:3000`.

## Публикация

Подойдёт любой хостинг с Node.js (VPS, Render, Railway и т.п.). Важно:

1. Задай `PUBLIC_URL=https://твой-домен` и `SESSION_SECRET` в переменных окружения.
2. Пропиши production-callback URL у всех трёх провайдеров.
3. Папка `data/` должна переживать перезапуски (постоянный диск).
4. HTTPS обязателен — иначе cookie с `Secure` и OAuth-редиректы будут вести себя плохо.
