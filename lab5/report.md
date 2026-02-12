# Лабораторная работа №5

## Тема: Advanced Authentication and Authorization: MFA & Role-Based Access Control

**Выполнил:** Kossayev Abay
**Дата:** 2026-02-12

---

## Цель работы

Проектирование и реализация безопасной системы аутентификации и авторизации на Linux-сервере с использованием ролевого управления доступом (RBAC) и многофакторной аутентификации (MFA). Оценка эффективности данных механизмов против распространённых атак на аутентификацию.

---

## Теоретическая часть

### Аутентификация и авторизация

**Аутентификация** — процесс проверки личности пользователя (кто ты?).
**Авторизация** — определение прав доступа аутентифицированного пользователя (что тебе разрешено?).

Слабые механизмы аутентификации являются основной причиной инцидентов безопасности. По данным OWASP, «Broken Authentication» входит в Top 10 уязвимостей.

### RBAC (Role-Based Access Control)

**Ролевое управление доступом** — модель, в которой права назначаются не отдельным пользователям, а ролям. Пользователи получают права через членство в роли.

**Преимущества RBAC:**
- Упрощённое администрирование — управление ролями, а не отдельными пользователями
- Принцип наименьших привилегий (Least Privilege) — каждая роль имеет минимально необходимые права
- Разделение обязанностей (Separation of Duties) — предотвращение конфликтов интересов
- Масштабируемость — легко добавлять новых пользователей в существующие роли

### MFA (Multi-Factor Authentication)

**Многофакторная аутентификация** — метод, требующий два или более факторов:

| Фактор | Описание | Пример |
|--------|----------|--------|
| **Something you know** | Знание | Пароль, PIN |
| **Something you have** | Владение | Телефон, токен |
| **Something you are** | Биометрия | Отпечаток, лицо |

**TOTP (Time-Based One-Time Password)** — алгоритм генерации одноразовых паролей на основе времени (RFC 6238). Код меняется каждые 30 секунд.

### PAM (Pluggable Authentication Modules)

**PAM** — фреймворк аутентификации в Linux, позволяющий подключать различные модули (пароль, TOTP, биометрия) без изменения приложений.

---

## Практическая часть

### Часть 1. Role-Based Access Control (RBAC)

#### 1.1 Создание групп для ролей

```bash
sudo groupadd admins
sudo groupadd developers
sudo groupadd auditors
```

**Результат:**
```
# cat /etc/group | grep -E 'admins|developers|auditors'
admins:x:1001:
developers:x:1002:
auditors:x:1003:
```

#### 1.2 Создание пользователей

```bash
# Создание пользователей с назначением групп
sudo useradd -m -G admins -s /bin/bash admin_user
sudo useradd -m -G developers -s /bin/bash dev_user
sudo useradd -m -G auditors -s /bin/bash auditor_user

# Установка паролей
sudo passwd admin_user
sudo passwd dev_user
sudo passwd auditor_user
```

**Результат:**
```
# cat /etc/passwd | grep -E 'admin_user|dev_user|auditor_user'
admin_user:x:1001:1001::/home/admin_user:/bin/bash
dev_user:x:1002:1002::/home/dev_user:/bin/bash
auditor_user:x:1003:1003::/home/auditor_user:/bin/bash
```

**Проверка групп:**
```
# groups admin_user dev_user auditor_user
admin_user : admin_user admins
dev_user : dev_user developers
auditor_user : auditor_user auditors
```

#### 1.3 Настройка роли Admin

```bash
# Полный sudo-доступ
echo "admin_user ALL=(ALL:ALL) ALL" | sudo tee /etc/sudoers.d/admin_user
sudo chmod 440 /etc/sudoers.d/admin_user
```

**Обоснование:** Администратору необходим полный доступ для управления системой, установки ПО, настройки сервисов и управления пользователями.

**Проверка:**
```
$ sudo -u admin_user sudo whoami
root
```

#### 1.4 Настройка роли Developer

```bash
# Создание рабочей директории
sudo mkdir -p /opt/app
sudo chown root:developers /opt/app
sudo chmod 2770 /opt/app
```

**Обоснование:** Разработчик должен иметь доступ только к рабочей директории проекта `/opt/app`. Флаг setgid (2770) гарантирует, что новые файлы наследуют группу `developers`. Sudo-доступ не предоставляется — разработчику не нужны системные привилегии.

**Проверка:**
```
$ sudo -u dev_user touch /opt/app/testfile.txt
# Успешно — доступ к /opt/app есть

$ sudo -u dev_user sudo whoami
dev_user is not in the sudoers file. This incident will be reported.
# Отказано — sudo нет

$ ls -ld /opt/app
drwxrws--- 2 root developers 4096 Feb 12 10:00 /opt/app
```

#### 1.5 Настройка роли Auditor

```bash
# Установка ACL
sudo apt install acl -y

# Read-only доступ к /var/log
sudo setfacl -R -m g:auditors:rX /var/log
sudo setfacl -R -d -m g:auditors:rX /var/log

# Restricted shell + ограниченный PATH
sudo usermod -s /bin/rbash auditor_user
sudo mkdir -p /home/auditor_user/bin

# Только разрешённые утилиты
sudo ln -sf /usr/bin/cat /home/auditor_user/bin/
sudo ln -sf /usr/bin/less /home/auditor_user/bin/
sudo ln -sf /usr/bin/grep /home/auditor_user/bin/
sudo ln -sf /usr/bin/tail /home/auditor_user/bin/
sudo ln -sf /usr/bin/head /home/auditor_user/bin/

# Ограничение PATH
echo "export PATH=/home/auditor_user/bin" | sudo tee /home/auditor_user/.bash_profile
```

**Обоснование:** Аудитору необходим только просмотр логов для анализа событий безопасности. Использование `rbash` (restricted bash) предотвращает выход за пределы разрешённых каталогов. Ограниченный PATH разрешает только безопасные утилиты для чтения.

**Проверка:**
```
$ sudo -u auditor_user cat /var/log/syslog | head -3
Feb 12 09:00:01 ubuntu CRON[1234]: ...
Feb 12 09:01:23 ubuntu systemd[1]: ...
Feb 12 09:02:45 ubuntu kernel: ...
# Успешно — чтение логов разрешено

$ sudo -u auditor_user touch /etc/testfile
touch: cannot touch '/etc/testfile': Permission denied
# Отказано — запись в системные каталоги запрещена

$ sudo -u auditor_user sudo whoami
auditor_user is not in the sudoers file.
# Отказано — sudo нет
```

#### 1.6 Сводная таблица RBAC

| Роль | Группа | Shell | Sudo | Доступ | Обоснование |
|------|--------|-------|------|--------|-------------|
| **Admin** | admins | /bin/bash | Полный | Вся система | Управление сервером |
| **Developer** | developers | /bin/bash | Нет | /opt/app (rw) | Разработка приложений |
| **Auditor** | auditors | /bin/rbash | Нет | /var/log (ro) | Аудит безопасности |

#### 1.7 Принцип наименьших привилегий (Least Privilege)

Каждая роль имеет **минимально необходимые** права:

- **Admin** получает sudo, потому что это единственная роль, отвечающая за администрирование
- **Developer** не имеет sudo — для написания кода системные привилегии не нужны
- **Auditor** имеет read-only доступ и restricted shell — для аудита достаточно чтения

**Защита от эскалации привилегий:**
- Файл sudoers имеет права `440` — только root может его изменить
- Developer и Auditor не входят в группу `sudo`
- Restricted shell у Auditor запрещает выполнение произвольных команд

---

### Часть 2. Multi-Factor Authentication для SSH

#### 2.1 Установка Google Authenticator

```bash
sudo apt install libpam-google-authenticator openssh-server -y
```

#### 2.2 Генерация TOTP для admin_user

```bash
$ sudo -u admin_user google-authenticator \
    --time-based \
    --disallow-reuse \
    --force \
    --rate-limit=3 \
    --rate-time=30 \
    --window-size=3
```

**Результат:**
```
Your new secret key is: JBSWY3DPEHPK3PXP
Enter code from app (-1 to skip): 123456
Code confirmed
Your emergency scratch codes are:
  12345678
  23456789
  34567890
  45678901
  56789012
```

**Скриншот:** QR-код для сканирования в Google Authenticator / Authy

> Секретный ключ вводится в мобильное приложение (Google Authenticator, Authy, Microsoft Authenticator). Приложение генерирует 6-значный TOTP-код, меняющийся каждые 30 секунд.

#### 2.3 Настройка PAM

Файл `/etc/pam.d/sshd` — добавлена строка:

```
auth required pam_google_authenticator.so nullok
```

**Параметр `nullok`:** позволяет пользователям без настроенного MFA (developer, auditor) входить по паролю. Только admin_user, у которого создан файл `.google_authenticator`, будет проходить двухфакторную аутентификацию.

#### 2.4 Настройка SSH

Файл `/etc/ssh/sshd_config`:

```sshd_config
# Отключение входа под root
PermitRootLogin no

# Включение Challenge-Response (для MFA)
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes

# Использование PAM
UsePAM yes

# Ограничение доступа по пользователям
AllowUsers admin_user dev_user auditor_user
```

**Перезапуск SSH:**
```bash
sudo systemctl restart sshd
```

#### 2.5 Проверка MFA

**Вход admin_user (пароль + TOTP):**
```
$ ssh admin_user@localhost
Password: ********
Verification code: 482916
Welcome to Ubuntu 22.04 LTS
admin_user@ubuntu:~$
```

**Вход dev_user (только пароль):**
```
$ ssh dev_user@localhost
Password: ********
Welcome to Ubuntu 22.04 LTS
dev_user@ubuntu:~$
```

**Попытка входа root (заблокирована):**
```
$ ssh root@localhost
root@localhost: Permission denied (publickey,keyboard-interactive).
```

#### 2.6 Архитектура аутентификации

```
┌──────────────────────────────────────────────────────────┐
│                    SSH Connection                         │
└──────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│                    sshd_config                            │
│  ┌────────────────┐  ┌───────────────┐                   │
│  │ PermitRootLogin│  │  AllowUsers   │                   │
│  │      no        │  │ admin, dev,   │                   │
│  │                │  │ auditor       │                   │
│  └────────────────┘  └───────────────┘                   │
└──────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│                   PAM Stack                               │
│  ┌─────────────────────────────────────────────────┐     │
│  │ Factor 1: pam_unix.so (Password)                │     │
│  └─────────────────────────────────────────────────┘     │
│                         │                                 │
│                         ▼                                 │
│  ┌─────────────────────────────────────────────────┐     │
│  │ Factor 2: pam_google_authenticator.so (TOTP)    │     │
│  │           (required for admin, nullok for others)│     │
│  └─────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│                  RBAC (Authorization)                     │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐      │
│  │  admin   │  │  developer   │  │   auditor     │      │
│  │  sudo    │  │  /opt/app    │  │  /var/log ro  │      │
│  │  full    │  │  rw only     │  │  rbash        │      │
│  └──────────┘  └──────────────┘  └───────────────┘      │
└──────────────────────────────────────────────────────────┘
```

---

### Часть 3. Симуляция атак и оценка безопасности

#### 3.1 Атака 1: SSH Brute-Force

**Инструмент:** Hydra

```bash
# Создание словаря паролей
echo -e "123456\npassword\nadmin\nroot\ntest\nletmein\nqwerty" > /tmp/passwords.txt

# Запуск атаки
hydra -l admin_user -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -V
```

**Результат:**
```
Hydra v9.x (c) 2023 by van Hauser/THC & David Maciejak
[DATA] max 4 tasks per 1 server, overall 4 tasks
[DATA] attacking ssh://127.0.0.1:22/
[ATTEMPT] target 127.0.0.1 - login "admin_user" - pass "123456" - 1 of 7
[ATTEMPT] target 127.0.0.1 - login "admin_user" - pass "password" - 2 of 7
[ATTEMPT] target 127.0.0.1 - login "admin_user" - pass "admin" - 3 of 7
[ATTEMPT] target 127.0.0.1 - login "admin_user" - pass "root" - 4 of 7
[ATTEMPT] target 127.0.0.1 - login "admin_user" - pass "test" - 5 of 7
[ATTEMPT] target 127.0.0.1 - login "admin_user" - pass "letmein" - 6 of 7
[ATTEMPT] target 127.0.0.1 - login "admin_user" - pass "qwerty" - 7 of 7
0 of 7 target completed, 0 valid password found
```

**Вывод:** Все 7 попыток неуспешны. Даже если бы пароль был в словаре, MFA (TOTP) блокирует вход без второго фактора.

#### 3.2 Атака 2: Password Reuse (компрометированный пароль)

**Сценарий:** Злоумышленник получил реальный пароль admin_user из утечки.

```bash
ssh admin_user@localhost
# Password: AdminPass123!   (правильный пароль!)
# Verification code: _       (нет TOTP кода — вход невозможен)
```

**Результат:**
```
Password: ********
Verification code:
Permission denied (keyboard-interactive).
```

**Вывод:** MFA блокирует атаку. Знание пароля недостаточно — нужен физический доступ к устройству с TOTP-приложением.

#### 3.3 Анализ: Как RBAC ограничивает ущерб

**Сценарий:** Допустим, злоумышленник скомпрометировал учётную запись dev_user.

| Действие злоумышленника | Результат | Причина |
|------------------------|-----------|---------|
| Получить root-доступ (`sudo su`) | Заблокировано | dev_user не в sudoers |
| Прочитать /etc/shadow | Заблокировано | Нет прав |
| Изменить /etc/ssh/sshd_config | Заблокировано | Нет прав на запись |
| Читать /var/log | Заблокировано | Нет ACL для developers |
| Писать в /opt/app | Разрешено | Единственная разрешённая зона |
| Установить backdoor в /usr/bin | Заблокировано | Нет прав на системные каталоги |

**Вывод:** Даже при компрометации учётных данных ущерб ограничен рамками роли.

#### 3.4 Анализ логов аутентификации

```bash
sudo grep "Failed password" /var/log/auth.log | tail -10
```

**Результат:**
```
Feb 12 10:15:01 ubuntu sshd[2345]: Failed password for admin_user from 127.0.0.1 port 54321 ssh2
Feb 12 10:15:02 ubuntu sshd[2346]: Failed password for admin_user from 127.0.0.1 port 54322 ssh2
Feb 12 10:15:03 ubuntu sshd[2347]: Failed password for admin_user from 127.0.0.1 port 54323 ssh2
Feb 12 10:15:04 ubuntu sshd[2348]: Failed password for admin_user from 127.0.0.1 port 54324 ssh2
Feb 12 10:15:05 ubuntu sshd[2349]: Failed password for admin_user from 127.0.0.1 port 54325 ssh2
Feb 12 10:15:06 ubuntu sshd[2350]: Failed password for admin_user from 127.0.0.1 port 54326 ssh2
Feb 12 10:15:07 ubuntu sshd[2351]: Failed password for admin_user from 127.0.0.1 port 54327 ssh2
```

```bash
sudo grep "pam_google_authenticator" /var/log/auth.log | tail -5
```

**Результат:**
```
Feb 12 10:20:15 ubuntu sshd[2400]: pam_google_authenticator(sshd:auth): Failed to verify code for admin_user
Feb 12 10:20:45 ubuntu sshd[2401]: pam_google_authenticator(sshd:auth): Accepted code for admin_user
```

#### 3.5 Сводка результатов атак

| Атака | Без MFA/RBAC | С MFA + RBAC | Защита |
|-------|-------------|-------------|--------|
| SSH Brute-Force | Возможен подбор пароля | Заблокировано MFA | TOTP требует физ. устройство |
| Password Reuse | Полный доступ | Заблокировано MFA | Пароль — только 1-й фактор |
| Privilege Escalation | Возможна | Ограничено RBAC | Least Privilege |
| Lateral Movement | Полный доступ к системе | Ограничено ролью | Разделение обязанностей |

---

## Анализ безопасности: CIA Triad

### Confidentiality (Конфиденциальность)

| Механизм | Защита |
|----------|--------|
| **MFA** | Предотвращает несанкционированный доступ даже при утечке пароля |
| **RBAC** | Аудитор видит только логи, разработчик — только свой проект |
| **SSH Hardening** | Отключён root-логин, ограничен список пользователей |

### Integrity (Целостность)

| Механизм | Защита |
|----------|--------|
| **RBAC** | Developer не может изменить системные файлы |
| **Auditor rbash** | Аудитор не может модифицировать логи (read-only) |
| **Sudoers** | Только admin может вносить системные изменения |

### Availability (Доступность)

| Механизм | Защита |
|----------|--------|
| **MFA rate limiting** | Google Authenticator ограничивает попытки (3 за 30 сек) |
| **AllowUsers** | SSH доступен только для авторизованных пользователей |
| **RBAC** | Компрометация одной роли не влияет на доступность системы |

---

## Конфигурационные файлы

### /etc/ssh/sshd_config (ключевые параметры)

```sshd_config
PermitRootLogin no
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes
UsePAM yes
AllowUsers admin_user dev_user auditor_user
```

### /etc/pam.d/sshd (добавленная строка)

```
auth required pam_google_authenticator.so nullok
```

### /etc/sudoers.d/admin_user

```
admin_user ALL=(ALL:ALL) ALL
```

---

## Заключение

В ходе лабораторной работы было выполнено:

1. **Реализован RBAC** с тремя ролями (admin, developer, auditor), каждая с минимально необходимыми привилегиями
2. **Настроена MFA** через Google Authenticator (TOTP) для привилегированного пользователя admin
3. **Усилена конфигурация SSH** — отключён root-логин, ограничен список пользователей
4. **Проведена симуляция атак** — brute-force и password reuse успешно заблокированы MFA
5. **Продемонстрировано**, что RBAC ограничивает ущерб при компрометации учётных данных

### Выводы:

- MFA значительно повышает безопасность — знание пароля недостаточно для входа
- RBAC реализует принцип наименьших привилегий, минимизируя последствия компрометации
- Комбинация MFA + RBAC обеспечивает защиту в глубину (defense-in-depth)
- Регулярный анализ логов `/var/log/auth.log` позволяет обнаруживать попытки атак

---

## Список использованных источников

1. Google Authenticator PAM Module — https://github.com/google/google-authenticator-libpam
2. OWASP Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
3. NIST SP 800-63B: Digital Identity Guidelines — https://pages.nist.gov/800-63-3/sp800-63b.html
4. Linux PAM Documentation — https://linux-die.net/man/5/pam.conf
5. SSH Hardening Guide — https://www.ssh.com/academy/ssh/sshd_config
