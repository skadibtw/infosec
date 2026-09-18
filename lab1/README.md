# Лабораторная работа 1: защищённый REST API с интеграцией в CI/CD

REST API на Python/Flask с аутентификацией по JWT и хранением данных в SQLite. Пользователи публикуют короткие посты и читают их список. При каждом push и pull request в GitHub Actions автоматически запускаются проверки безопасности: SAST (bandit) и SCA (OWASP Dependency-Check).

## Стек

- Python 3, Flask 3.1
- SQLite (модуль `sqlite3` из стандартной библиотеки)
- PyJWT: выпуск и проверка JWT
- bcrypt: хэширование паролей
- GitHub Actions: bandit, OWASP Dependency-Check

## Запуск

```bash
cd lab1
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
ADMIN_PASSWORD=secret JWT_SECRET=$(openssl rand -hex 32) .venv/bin/flask --app app run
```

| Переменная | Назначение |
|---|---|
| `ADMIN_PASSWORD` | пароль пользователя `admin`. Пользователь создаётся при старте, только если переменная задана |
| `JWT_SECRET` | ключ подписи JWT. Если не задан, генерируется случайно при каждом запуске |
| `DB_PATH` | путь к файлу БД, по умолчанию `app.db` |

## API

### `POST /auth/login`: аутентификация

Принимает логин и пароль и возвращает JWT, действительный 1 час.

```bash
curl -X POST http://127.0.0.1:5000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"secret"}'
```

| Код | Ответ |
|---|---|
| 200 | `{"token": "<jwt>"}` |
| 400 | `{"error": "username and password required"}` |
| 401 | `{"error": "invalid credentials"}` |

### `GET /api/data`: список постов (нужен токен)

```bash
curl http://127.0.0.1:5000/api/data -H "Authorization: Bearer $TOKEN"
```

| Код | Ответ |
|---|---|
| 200 | `[{"id": 1, "author": "admin", "text": "..."}]` |
| 401 | `{"error": "unauthorized"}`: токена нет, он неверный или истёк |

### `POST /api/posts`: создать пост (нужен токен)

```bash
curl -X POST http://127.0.0.1:5000/api/posts \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"text":"Hello"}'
```

| Код | Ответ |
|---|---|
| 201 | `{"id": 1, "author": "admin", "text": "Hello"}` |
| 400 | `{"error": "text required"}` |
| 401 | `{"error": "unauthorized"}` |

Автором поста становится пользователь из токена (`sub`). Указать автора в теле запроса нельзя.

## Меры защиты

### SQL Injection (OWASP A03:2021 Injection)

Все SQL-запросы параметризованные. Пользовательские значения передаются драйверу `sqlite3` отдельно от текста запроса через плейсхолдеры `?`, а конкатенация и f-строки в SQL не используются:

```python
c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
c.execute("INSERT INTO posts (author, text) VALUES (?, ?)", (g.user, text))
```

Драйвер передаёт значение как данные, а не как часть SQL, поэтому ввод вида `admin' OR '1'='1` просто ищется как имя пользователя и не меняет запрос:

```bash
curl -X POST http://127.0.0.1:5000/auth/login -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin' OR '1'='1\",\"password\":\"x\"}"
# {"error":"invalid credentials"} 401
```

Дополнительно проверяется тип входных данных: `username`, `password` и `text` должны быть строками, иначе возвращается 400.

### XSS (OWASP A03:2021 Injection)

Все пользовательские данные (`author`, `text`), которые попадают в ответы API, экранируются функцией `html.escape` из стандартной библиотеки. Она заменяет `<`, `>`, `&`, `"`, `'` на HTML-сущности, и даже если клиент вставит ответ в страницу через `innerHTML`, скрипт не выполнится:

```bash
curl -X POST http://127.0.0.1:5000/api/posts -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"text":"<script>alert(1)</script>"}'
# {"author":"admin","id":1,"text":"&lt;script&gt;alert(1)&lt;/script&gt;"} 201
```

Кроме того, Flask отдаёт ответы через `jsonify` с заголовком `Content-Type: application/json`, поэтому браузер не интерпретирует их как HTML.

### Broken Authentication (OWASP A07:2021 Identification and Authentication Failures)

**Хранение паролей.** Пароли хранятся только в виде bcrypt-хэшей (`bcrypt.hashpw` с солью от `bcrypt.gensalt()`). bcrypt намеренно медленный, и у каждого хэша своя соль, поэтому перебор и радужные таблицы по утёкшей базе неэффективны. При входе пароль сверяется через `bcrypt.checkpw`. Пароль администратора в коде не хранится, он берётся из переменной окружения.

**Ответ на неудачный вход.** Для несуществующего пользователя и для неверного пароля возвращается одинаковая ошибка `invalid credentials`, поэтому по ответу нельзя узнать, какие логины существуют.

**JWT.** После успешного входа сервер выдаёт токен, подписанный HMAC-SHA256 секретным ключом `JWT_SECRET`. В payload лежат `sub` (имя пользователя) и `exp` (время истечения, +1 час).

**Проверка токена (middleware).** Защищённые эндпоинты обёрнуты декоратором `auth_required`, который выполняется до обработчика:

```python
def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        try:
            g.user = jwt.decode(token, SECRET, algorithms=["HS256"])["sub"]
        except jwt.PyJWTError:
            return jsonify(error="unauthorized"), 401
        return f(*args, **kwargs)
    return wrapper
```

`jwt.decode` проверяет подпись и срок действия. Список алгоритмов задан явно (`["HS256"]`), так что атаки с подменой алгоритма (`alg: none`) не проходят. Если токена нет, он подделан или истёк, возвращается 401, и обработчик не вызывается.

```bash
curl http://127.0.0.1:5000/api/data
# {"error":"unauthorized"} 401
```

### Прочее

- Приложение запускается без `debug=True`, поэтому интерактивный отладчик Werkzeug недоступен.
- Версии зависимостей зафиксированы в `requirements.txt`.

## CI/CD

Workflow `.github/workflows/ci.yml` запускается на каждый `push` и `pull_request`:

1. **SAST, [bandit](https://github.com/PyCQA/bandit).** Статический анализ исходного кода: ищет захардкоженные секреты, SQL, собранный конкатенацией строк, включённый debug, небезопасные вызовы и т.п.
2. **SCA, [OWASP Dependency-Check](https://github.com/dependency-check/DependencyCheck).** Анализирует `requirements.txt` (Python-анализатор включается флагом `--enableExperimental`), сопоставляет пакеты с CPE и ищет известные CVE в базе NVD. При уязвимости с CVSS ≥ 7 (`--failOnCVSS 7`) шаг падает. Отчёт в форматах HTML и JSON сохраняется как артефакт `dependency-check-report` запуска. База NVD кэшируется между запусками через `actions/cache`. Если в секретах репозитория задан `NVD_API_KEY`, он используется, и загрузка базы идёт быстрее.

Если какой-либо сканер находит проблему, шаг завершается с ненулевым кодом, и pipeline падает.

Последний успешный запуск: https://github.com/skadibtw/infosec/actions/runs/35318824925

### Отчёт SAST (bandit)

![bandit](screenshots/bandit.png)

### Отчёт SCA (OWASP Dependency-Check)

![dependency-check](screenshots/dependency-check.png)
