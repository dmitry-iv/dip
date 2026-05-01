# SecurityCourse (Spring Boot)

Учебное приложение с **аутентификацией/авторизацией**, UI на **Thymeleaf** и REST API с **JWT**.

## Что уже сделано (уровень «отлично»)

- **Роли USER/ADMIN**, разграничение доступа (web + API).
- **Регистрация** и вход (form login), + JWT `/api/auth/login`.
- **Политика пароля** (валидация на стороне сервера).
- **Защита от брутфорса**: ограничение попыток + временная блокировка.
- **Аудит** (таблица `audit_log`): логины/ошибки/логаут и админские действия.
- **Flyway** управляет схемой БД, Hibernate работает в режиме `validate`.

## Быстрый старт

### 1) База данных

По умолчанию приложение ожидает PostgreSQL (подойдёт локальный Docker):

```bash
docker compose up -d
```

### 2) Запуск

```bash
mvn spring-boot:run
```

Открой: `http://localhost:8080`

### 3) Дефолтный админ (для демо)

Создаётся при старте, если не существует (можно отключить):

- login: `admin`
- password: `Admin123!`

Настройки (через env или `application.properties`):

- `app.bootstrap.admin.enabled` (true/false)
- `BOOTSTRAP_ADMIN_USERNAME`
- `BOOTSTRAP_ADMIN_PASSWORD`
- `BOOTSTRAP_ADMIN_EMAIL`

## Важно про Flyway и «checksum mismatch»

**Нельзя** менять уже применённые миграции. Если это случилось в процессе разработки, Flyway может ругнуться на несовпадение checksum.

Для удобства в этом проекте включён dev-флаг:

- `app.flyway.auto-repair=true`

Он автоматически делает `repair` и повторяет `migrate`.

Для более строгого поведения выключи:

- `app.flyway.auto-repair=false`
