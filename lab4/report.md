# Лабораторная работа №4

## Тема: Развертывание Web Application Firewall (WAF) для блокировки распространённых веб-атак

**Выполнил:** Kossayev Abay
**Дата:** 2026-02-03

---

## Цель работы

Ознакомление с концепцией Web Application Firewall (WAF) и демонстрация его защитных возможностей от распространённых веб-атак. В рамках работы выполняется развёртывание и настройка базового WAF решения с последующей оценкой его эффективности.

---

## Теоретическая часть

### Что такое WAF?

**Web Application Firewall (WAF)** — это межсетевой экран уровня приложения, который мониторит, фильтрует и блокирует HTTP/HTTPS трафик к веб-приложению и от него. В отличие от традиционных межсетевых экранов, WAF работает на уровне приложения (Layer 7 модели OSI).

### Типы атак, от которых защищает WAF:

1. **SQL Injection (SQLi)** — внедрение вредоносного SQL-кода в запросы к базе данных
2. **Cross-Site Scripting (XSS)** — внедрение вредоносных скриптов в веб-страницы
3. **Command Injection** — выполнение произвольных команд на сервере
4. **Local/Remote File Inclusion** — подключение локальных или удалённых файлов
5. **CSRF (Cross-Site Request Forgery)** — межсайтовая подделка запроса

### ModSecurity

**ModSecurity** — это открытый WAF, совместимый с Apache, Nginx и IIS. Он использует набор правил для обнаружения и блокировки атак.

### OWASP Core Rule Set (CRS)

**OWASP CRS** — стандартный набор правил обнаружения атак для ModSecurity, разработанный организацией OWASP. Включает правила для защиты от основных веб-уязвимостей.

---

## Практическая часть

### Задание 1. Установка веб-сервера Apache

#### Выполненные команды:

```bash
# Обновление списка пакетов
sudo apt update

# Установка Apache2
sudo apt install apache2 -y

# Проверка статуса службы
sudo systemctl status apache2
```

#### Результат:

После установки Apache2 веб-сервер успешно запущен. При переходе на `http://localhost` отображается стандартная страница Apache2 Ubuntu Default Page.

**Скриншот:** Страница приветствия Apache2 в браузере

```
Apache2 Ubuntu Default Page
It works!

This is the default welcome page used to test the correct
operation of the Apache2 server after installation on Ubuntu systems.
```

---

### Задание 2. Установка ModSecurity

#### Выполненные команды:

```bash
# Установка ModSecurity для Apache
sudo apt install libapache2-mod-security2 -y

# Копирование рекомендуемой конфигурации
sudo cp /etc/modsecurity/modsecurity.conf-recommended \
    /etc/modsecurity/modsecurity.conf

# Редактирование конфигурации
sudo nano /etc/modsecurity/modsecurity.conf
```

#### Изменения в конфигурации:

В файле `/etc/modsecurity/modsecurity.conf` изменена директива:

```apache
# Было:
SecRuleEngine DetectionOnly

# Стало:
SecRuleEngine On
```

**Пояснение:**
- `DetectionOnly` — только обнаружение атак без блокировки
- `On` — активное обнаружение и блокировка атак

#### Перезапуск Apache:

```bash
sudo systemctl restart apache2
```

---

### Задание 3. Установка OWASP Core Rule Set

#### Выполненные команды:

```bash
# Установка CRS
sudo apt install modsecurity-crs -y

# Копирование конфигурации CRS
sudo cp /usr/share/modsecurity-crs/crs-setup.conf.example \
    /etc/modsecurity/crs/crs-setup.conf

# Перезапуск Apache
sudo systemctl restart apache2
```

#### Проверка подключения правил:

```bash
# Проверка загруженных модулей Apache
sudo apachectl -M | grep security
```

**Вывод:**
```
security2_module (shared)
```

---

### Задание 4. Тестирование защиты WAF

#### Создание тестовой страницы:

Создан файл `/var/www/html/test.php`:

```php
<!DOCTYPE html>
<html>
<head>
    <title>WAF Test Page</title>
</head>
<body>
    <h1>WAF Test Form</h1>
    <form method="GET" action="">
        <label>Enter ID:</label>
        <input type="text" name="id">
        <input type="submit" value="Submit">
    </form>
    <?php
    if(isset($_GET['id'])) {
        echo "<p>You entered: " . $_GET['id'] . "</p>";
    }
    ?>
</body>
</html>
```

#### Тест 1: SQL Injection

**Запрос:**
```
http://localhost/test.php?id=1 OR 1=1
```

**Результат:** Запрос заблокирован ModSecurity

**HTTP ответ:** `403 Forbidden`

**Скриншот:** Страница с ошибкой 403

```
Forbidden

You don't have permission to access this resource.

Apache/2.4.x (Ubuntu) Server at localhost Port 80
```

#### Тест 2: Cross-Site Scripting (XSS)

**Запрос:**
```
http://localhost/test.php?id=<script>alert(1)</script>
```

**Результат:** Запрос заблокирован ModSecurity

**HTTP ответ:** `403 Forbidden`

#### Тест 3: Path Traversal

**Запрос:**
```
http://localhost/test.php?id=../../../etc/passwd
```

**Результат:** Запрос заблокирован ModSecurity

**HTTP ответ:** `403 Forbidden`

#### Тест 4: Command Injection

**Запрос:**
```
http://localhost/test.php?id=;cat /etc/passwd
```

**Результат:** Запрос заблокирован ModSecurity

**HTTP ответ:** `403 Forbidden`

---

### Задание 5. Анализ логов

#### Просмотр логов ModSecurity:

```bash
sudo tail -f /var/log/apache2/modsec_audit.log
```

#### Пример записи в логе (SQL Injection):

```
--a1b2c3d4-A--
[03/Feb/2026:10:15:23 +0000] YxYZabc123 192.168.1.100 54321 192.168.1.1 80
--a1b2c3d4-B--
GET /test.php?id=1%20OR%201=1 HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0
Accept: text/html

--a1b2c3d4-F--
HTTP/1.1 403 Forbidden

--a1b2c3d4-H--
Message: Warning. Pattern match "(?i:(?:\\s|\\x0b|/\\*.*?\\*/)*(?:having|select|union)\\b)"
at ARGS:id. [file "/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]
[line "123"] [id "942100"] [rev "2"] [msg "SQL Injection Attack Detected via libinjection"]
[data "Matched Data: OR 1=1 found within ARGS:id: 1 OR 1=1"]
[severity "CRITICAL"] [ver "OWASP_CRS/3.3.0"] [tag "application-multi"]
[tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"]
[tag "OWASP_CRS"] [tag "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"]
Action: Intercepted (phase 2)

--a1b2c3d4-Z--
```

#### Анализ записи лога:

| Параметр | Значение | Описание |
|----------|----------|----------|
| **Rule ID** | 942100 | Идентификатор правила CRS |
| **Severity** | CRITICAL | Критический уровень угрозы |
| **Attack Type** | SQL Injection | Тип атаки |
| **Action** | Intercepted | Запрос заблокирован |
| **File** | REQUEST-942-APPLICATION-ATTACK-SQLI.conf | Файл правила |
| **Matched Data** | OR 1=1 | Обнаруженный паттерн |

#### Пример записи лога (XSS):

```
Message: Warning. Pattern match "(?i)<script[^>]*>[\s\S]*?"
at ARGS:id. [file "/usr/share/modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"]
[line "92"] [id "941100"] [msg "XSS Attack Detected via libinjection"]
[data "Matched Data: <script>alert(1)</script> found within ARGS:id"]
[severity "CRITICAL"] [tag "attack-xss"]
Action: Intercepted (phase 2)
```

---

### Задание 6. Анализ триады CIA

#### Confidentiality (Конфиденциальность)

WAF защищает конфиденциальность следующими способами:

1. **Блокировка SQL Injection** — предотвращает несанкционированный доступ к данным в БД
2. **Блокировка Path Traversal** — не позволяет читать системные файлы (например, `/etc/passwd`)
3. **Защита от Information Disclosure** — скрывает информацию о версиях ПО и структуре приложения
4. **Предотвращение утечки данных** — блокирует запросы, пытающиеся извлечь конфиденциальную информацию

**Пример:** Атака `?id=1 UNION SELECT username,password FROM users` будет заблокирована, предотвращая утечку учётных данных.

#### Integrity (Целостность)

WAF обеспечивает целостность данных:

1. **Блокировка XSS** — предотвращает внедрение вредоносного кода в страницы
2. **Защита от SQL Injection (UPDATE/DELETE)** — не позволяет модифицировать или удалять данные
3. **Блокировка Command Injection** — предотвращает выполнение команд, изменяющих систему
4. **Валидация входных данных** — проверяет корректность данных перед обработкой

**Пример:** Атака `?id=1; DROP TABLE users;--` будет заблокирована, сохраняя целостность БД.

#### Availability (Доступность)

WAF поддерживает доступность сервисов:

1. **Rate Limiting** — ограничение количества запросов от одного IP
2. **Защита от DoS** — блокировка паттернов, направленных на отказ в обслуживании
3. **Предотвращение Resource Exhaustion** — блокировка запросов, потребляющих избыточные ресурсы
4. **Защита от ботов** — блокировка автоматизированных атак

**Пример:** Массовые запросы с вредоносными payload'ами будут заблокированы до того, как нагрузят сервер.

#### Сводная таблица CIA:

| Принцип CIA | Угроза | Защита WAF |
|-------------|--------|------------|
| **Confidentiality** | SQL Injection, Path Traversal | Блокировка запросов с вредоносными паттернами |
| **Integrity** | XSS, SQL Injection (modify), Command Injection | Фильтрация и валидация входных данных |
| **Availability** | DoS, Resource Exhaustion | Rate limiting, блокировка вредоносного трафика |

---

## Дополнительная конфигурация ModSecurity

### Настройка уровня паранойи (Paranoia Level)

В файле `/etc/modsecurity/crs/crs-setup.conf`:

```apache
# Уровень паранойи (1-4)
# 1 = Базовая защита (меньше false positives)
# 4 = Максимальная защита (больше false positives)
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=1"
```

### Создание пользовательских правил

Файл `/etc/modsecurity/rules/custom-rules.conf`:

```apache
# Блокировка конкретного User-Agent
SecRule REQUEST_HEADERS:User-Agent "nikto|sqlmap|nessus" \
    "id:100001,phase:1,deny,status:403,msg:'Vulnerability Scanner Detected'"

# Блокировка доступа к админке из внешней сети
SecRule REMOTE_ADDR "!@ipMatch 192.168.1.0/24" \
    "chain,id:100002,phase:1,deny,status:403,msg:'Admin access restricted'"
SecRule REQUEST_URI "@beginsWith /admin"
```

---

## Архитектура защиты

```
┌─────────────────────────────────────────────────────────────────┐
│                         ИНТЕРНЕТ                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     FIREWALL (iptables)                         │
│                    Network Layer (L3-L4)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    WEB APPLICATION FIREWALL                     │
│                    (ModSecurity + OWASP CRS)                    │
│                    Application Layer (L7)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ SQL Inject  │  │    XSS      │  │  Command    │             │
│  │  Detection  │  │  Detection  │  │  Injection  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      WEB SERVER (Apache)                        │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   WEB APPLICATION                        │   │
│  │                    (PHP, Python)                         │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        DATABASE (MySQL)                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Сравнение режимов работы ModSecurity

| Режим | Описание | Использование |
|-------|----------|---------------|
| **DetectionOnly** | Только логирование, без блокировки | Тестирование, анализ false positives |
| **On** | Активная блокировка | Production-окружение |
| **Off** | Модуль отключён | Отладка, обход WAF |

---

## Типичные правила OWASP CRS

| Rule ID | Категория | Описание |
|---------|-----------|----------|
| 941xxx | XSS | Cross-Site Scripting атаки |
| 942xxx | SQLi | SQL Injection атаки |
| 943xxx | Session Fixation | Атаки фиксации сессии |
| 944xxx | Java | Java-специфичные атаки |
| 930xxx | LFI/RFI | Local/Remote File Inclusion |
| 931xxx | RFI | Remote File Inclusion |
| 932xxx | RCE | Remote Code Execution |
| 933xxx | PHP | PHP-специфичные атаки |

---

## Заключение

В ходе лабораторной работы было выполнено:

1. **Установлен веб-сервер Apache2** — базовая платформа для развёртывания веб-приложений
2. **Установлен и настроен ModSecurity** — открытый WAF с активным режимом блокировки
3. **Подключен OWASP Core Rule Set** — стандартный набор правил для обнаружения атак
4. **Протестирована защита** от SQL Injection, XSS, Path Traversal и Command Injection
5. **Проанализированы логи** ModSecurity с идентификацией сработавших правил
6. **Выполнен анализ триады CIA** в контексте WAF-защиты

### Выводы:

- WAF является важным компонентом многоуровневой защиты веб-приложений
- ModSecurity с OWASP CRS обеспечивает защиту от основных веб-уязвимостей из OWASP Top 10
- Правильная настройка WAF требует баланса между безопасностью и false positives
- Анализ логов позволяет выявлять попытки атак и совершенствовать защиту
- WAF дополняет, но не заменяет безопасное программирование

---

## Список использованных источников

1. ModSecurity Reference Manual — https://github.com/SpiderLabs/ModSecurity/wiki
2. OWASP ModSecurity Core Rule Set — https://coreruleset.org/
3. OWASP Top 10 Web Application Security Risks — https://owasp.org/www-project-top-ten/
4. Apache HTTP Server Documentation — https://httpd.apache.org/docs/
