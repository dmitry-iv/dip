# CorpSec — корпоративная система управления доступом и мониторинга инцидентов ИБ

Дипломный проект. Spring Boot 4 + PostgreSQL.

Реализует **трёхуровневую модель доступа** с разделением ролей USER / MANAGER (SOC-аналитик) / ADMIN, **tamper-evident журнал аудита** на хеш-цепочке SHA-256, **корреляционный движок** с правилами MITRE ATT&CK, обязательное 2FA для внешних пользователей и email-алерты для критичных инцидентов.

## Технологический стек

| Слой | Технология |
|---|---|
| Backend | Spring Boot 4.0.3, Java 17, Spring Security 6, Spring Data JPA |
| Database | PostgreSQL 17, Flyway 10 (миграции) |
| Frontend | Thymeleaf, Bootstrap 5.3, Chart.js 4.4 |
| Auth | JWT (jjwt 0.12.6), TOTP RFC 6238 (samstevens 1.7.1) |
| Crypto | Argon2id (Spring Security), AES-GCM-256 (JCE), SHA-256 (JCE) |
| Email | Spring Mail + Yandex SMTP / любой STARTTLS-провайдер |
| Test | JUnit 5, Mockito 5 |

Java сервисы: **82 файла**, ~7000 строк. Шаблоны: **20 файлов**, ~3200 строк. Миграции: **9 SQL**, ~220 строк. **42 unit-теста** покрывают критичную логику.

## Ключевые возможности

### Аутентификация и доступ
- **Argon2id** для паролей (победитель PHC, рекомендация OWASP)
- **2FA TOTP** с QR-кодом для настройки в любом authenticator-приложении
- **10 backup-кодов** при включении 2FA — на случай потери устройства
- **Принудительное 2FA для EXTERNAL-пользователей** — реализовано через `MfaEnforcementFilter`, нельзя пропустить или отключить
- **Политика паролей**: 12+ символов, заглавные/строчные/цифры/спецсимволы, blacklist распространённых паролей (NIST SP 800-63B), детектор последовательностей
- **JWT для API** с typ=mfa_pending для двухэтапного входа
- **Revocation list** для отозванных JWT
- **Lockout-механизм** при 5+ неудачных попытках входа

### Трёхуровневый RBAC

| Возможность | USER | MANAGER | ADMIN |
|---|:-:|:-:|:-:|
| Личная активность (/me) | ✅ | ✅ | ✅ |
| SOC-панель (/soc) | ❌ | ✅ | ✅ |
| Список и карточки инцидентов | ❌ | ✅ | ✅ |
| Назначить инцидент / закрыть | ❌ | ✅ | ✅ |
| Журнал аудита и проверка целостности | ❌ | ✅ | ✅ |
| Сводный отчёт + экспорт CSV/PDF | ❌ | ✅ | ✅ |
| Управление пользователями | ❌ | ❌ | ✅ |
| Настройки SMTP/алертов | ❌ | ❌ | ✅ |
| Демо-генератор данных | ❌ | ❌ | ✅ |

Главная страница `/` редиректит на нужный интерфейс по роли. Меню навигации динамически меняется.

### SOC-панель аналитика (`/soc`)
- **Очередь NEW** — упорядочена по severity (5 → 1), затем по времени
- **Кнопка «Взять»** — назначает инцидент на аналитика, переводит в IN_PROGRESS
- **«Решить» / «Ложное срабатывание»** — закрытие с комментарием
- **«Передать другому аналитику»** — для передачи смены
- **KPI**: моя очередь, в работе у меня, решено за 24ч, high-severity 24ч

### Журнал аудита и hash-цепочка
- **35+ типов событий** в 8 категориях (AUTH, ACCESS, USER_MGMT, DATA, CONFIG, NETWORK, INCIDENT, SYSTEM)
- **5-уровневая шкала severity** (Info → Critical)
- **Каждая запись содержит SHA-256(prev_hash || canonical_content)** — формирует криптографическую цепочку
- **Row-level lock** на `audit_chain_state` при записи → строгая последовательность даже при параллельных транзакциях
- **Монотонно растущий timestamp** через `nextMonotonicTimestamp()` с AtomicReference → корректная сортировка при async-обработке
- **Tamper-detection**: любая модификация записи в БД обнаруживается при `verifyChain()` — выдаёт ID первой повреждённой записи
- **AUDIT_TAMPERING** — автоматический инцидент критичной severity при детекции разрыва цепочки

### Корреляционный движок
7 правил с привязкой к MITRE ATT&CK:

| Правило | Severity | MITRE | Логика |
|---|:-:|:-:|---|
| BRUTE_FORCE | 5 | T1110 | 5+ LOGIN_FAILURE с одного IP за 5 минут |
| CREDENTIAL_STUFFING | 4 | T1110.004 | 5+ разных users с одного IP за 10 минут |
| MFA_BYPASS_ATTEMPT | 4 | T1621 | 5+ неверных TOTP подряд |
| PRIVILEGE_ESCALATION | 4 | T1098 | Назначение роли ADMIN |
| MASS_EXPORT | 3 | T1567 | 10+ операций экспорта за 10 минут |
| OFF_HOURS_LOGIN | 3 | T1078 | Успешный вход в 20:00–07:00 |
| AUDIT_TAMPERING | 5 | T1070 | Детекция разрыва hash-цепочки |

- **Async обработка** через `@EventListener` + dedicated executor — корреляция не блокирует основной поток
- **Дедупликация инцидентов** в окне 15 минут (одно правило + один user/IP)
- **Сохранение связанных событий аудита** (`relatedLogIds`) для аналитика

### Email-алерты
- Настраиваются из админки (`/admin/alert-settings`)
- **SMTP-пароль хранится зашифрованным AES-GCM-256** в БД (`EncryptionService`)
- Фильтр по минимальной severity
- Throttle (защита от спама) — не чаще раза в N секунд на одно правило
- Шаблон письма содержит severity, MITRE, описание, ссылку на карточку инцидента
- Тестирование подключения и отправки прямо из админки

### Безопасные HTTP-заголовки
- **Content Security Policy** — строгий whitelist для CDN
- **HSTS** (Strict-Transport-Security) — 1 год, includeSubDomains
- **X-Frame-Options: DENY** — защита от clickjacking
- **Referrer-Policy: strict-origin-when-cross-origin**
- **Permissions-Policy** — отключение camera/microphone/geolocation/payment
- **X-Content-Type-Options: nosniff**

### CSRF
Включён для всех web-форм через стандартный механизм Spring Security. Отключён только для `/api/**` (stateless JWT-контур).

## Соответствие OWASP Top 10:2021

| Категория | Покрытие |
|---|---|
| **A01: Broken Access Control** | Двухконтурный SecurityConfig, `@PreAuthorize` на сервисах и контроллерах, RBAC с 3 ролями, `MfaEnforcementFilter` |
| **A02: Cryptographic Failures** | Argon2id, AES-GCM-256, SHA-256, CSPRNG для IV, шифрование секретов в БД, master key из env |
| **A03: Injection** | Параметризованные запросы (JPA, native queries), bean-validation, escaping в Thymeleaf |
| **A04: Insecure Design** | Threat modeling (см. правила корреляции), defense in depth, fail-secure defaults |
| **A05: Security Misconfiguration** | CSP, HSTS, X-Frame, Permissions-Policy, продакшен `ddl-auto=validate` (рекомендуется при деплое), переменные окружения для секретов |
| **A07: Auth Failures** | Argon2id вместо BCrypt, 2FA TOTP, backup-коды, lockout, blacklist паролей, секретные сессии |
| **A08: Software & Data Integrity Failures** | Hash-цепочка аудита (SHA-256 chain), AUDIT_TAMPERING правило, Maven dependency pinning |
| **A09: Security Logging & Monitoring Failures** | 35+ типов событий, real-time correlation, immutable журнал, email-алерты, SOC-панель |
| **A10: SSRF** | Не применимо (нет outbound HTTP-запросов в коде, кроме SMTP) |

## Установка и запуск

### Требования

* Java Development Kit версии 17 или выше
* Apache Maven версии 3.9 или выше
* PostgreSQL версии 17 (с любой свежей версией драйвера)

### Подготовка базы данных

Создать пользователя и базу данных:

```sql
CREATE USER securitycourse WITH PASSWORD 'securitycourse';
CREATE DATABASE securitycourse OWNER securitycourse;
GRANT ALL PRIVILEGES ON DATABASE securitycourse TO securitycourse;

### Первый запуск

В каталоге проекта выполнить:
mvn clean install
mvn spring-boot:run

### Запуск автоматических тестов

Команда запускает 42 unit-теста для критичной логики: шифрование, политика паролей, хеш-цепочка, правила корреляции. Среднее время прогона — около 3 секунд.

## Структура исходного кода

src/main/java/com/example/securitycourse/
audit/         — перечисления категорий и действий аудита, событие AuditEventCreated
config/        — конфигурация безопасности, инициализация данных, обработчик системных событий
controller/    — REST- и web-контроллеры
api/       — JSON API для интеграции (защищено JWT)
web/       — Thymeleaf-страницы для UI
correlation/   — движок корреляции и реализация семи правил
domain/        — JPA-сущности
dto/           — Data Transfer Objects для REST API
exception/     — глобальные обработчики исключений
repository/    — репозитории Spring Data JPA
security/      — реализация JWT-фильтра, обработчиков аутентификации, фильтра принудительной 2FA
service/       — бизнес-логика
src/main/resources/
db/migration/  — SQL-скрипты Flyway
templates/     — шаблоны Thymeleaf
src/test/java/     — unit-тесты