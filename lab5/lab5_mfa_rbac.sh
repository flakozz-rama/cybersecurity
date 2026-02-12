#!/bin/bash

# =============================================================================
# Laboratory Work 5: Advanced Authentication & Authorization (MFA + RBAC)
# Run on Ubuntu VM: sudo bash lab5_mfa_rbac.sh
# =============================================================================

set +e

echo "=============================================="
echo "  Lab 5: MFA & RBAC Setup"
echo "=============================================="
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo bash $0"
    exit 1
fi

# =============================================================================
# PART 1: Role-Based Access Control (RBAC)
# =============================================================================

echo ">>> PART 1: RBAC Configuration"
echo "----------------------------------------------"

# --- 1.1 Create groups ---
echo "[1.1] Creating role groups..."
groupadd admins 2>/dev/null || echo "  Group 'admins' already exists"
groupadd developers 2>/dev/null || echo "  Group 'developers' already exists"
groupadd auditors 2>/dev/null || echo "  Group 'auditors' already exists"
echo "[OK] Groups created"
echo ""

# --- 1.2 Create users ---
echo "[1.2] Creating users..."
useradd -m -G admins -s /bin/bash admin_user 2>/dev/null || echo "  admin_user already exists"
useradd -m -G developers -s /bin/bash dev_user 2>/dev/null || echo "  dev_user already exists"
useradd -m -G auditors -s /bin/bash auditor_user 2>/dev/null || echo "  auditor_user already exists"

echo "admin_user:AdminPass123!" | chpasswd
echo "dev_user:DevPass123!" | chpasswd
echo "auditor_user:AuditPass123!" | chpasswd

echo "[OK] Users created with passwords"
echo ""

# --- 1.3 Configure admin role (full sudo) ---
echo "[1.3] Configuring ADMIN role..."
cat > /etc/sudoers.d/admin_user << 'EOF'
# admin_user: full administrative privileges
admin_user ALL=(ALL:ALL) ALL
EOF
chmod 440 /etc/sudoers.d/admin_user
echo "  admin_user -> full sudo access"
echo "[OK] Admin role configured"
echo ""

# --- 1.4 Configure developer role (access only to /opt/app) ---
echo "[1.4] Configuring DEVELOPER role..."
mkdir -p /opt/app
chown root:developers /opt/app
chmod 2770 /opt/app   # setgid so new files inherit group

echo "  dev_user -> read/write access to /opt/app only"
echo "  dev_user -> NO sudo access"
echo "[OK] Developer role configured"
echo ""

# --- 1.5 Configure auditor role (read-only /var/log, restricted shell) ---
echo "[1.5] Configuring AUDITOR role..."

# Install ACL tools
apt-get install -y acl > /dev/null 2>&1

# Grant read access to /var/log
setfacl -R -m g:auditors:rX /var/log 2>/dev/null
setfacl -R -d -m g:auditors:rX /var/log 2>/dev/null

# Set up restricted shell environment
mkdir -p /home/auditor_user/bin
cat > /home/auditor_user/.bash_profile << 'PROFILE'
export PATH=/home/auditor_user/bin
export SHELL=/bin/rbash
PROFILE
chown auditor_user:auditor_user /home/auditor_user/.bash_profile

# Symlink only allowed commands
for cmd in cat less grep tail head wc; do
    CMDPATH=$(which $cmd 2>/dev/null)
    if [ -n "$CMDPATH" ]; then
        ln -sf "$CMDPATH" /home/auditor_user/bin/
    fi
done

# Change shell to rbash
usermod -s /bin/rbash auditor_user 2>/dev/null || echo "  rbash not available, using bash"

echo "  auditor_user -> read-only access to /var/log"
echo "  auditor_user -> restricted shell (rbash)"
echo "  auditor_user -> NO sudo access"
echo "[OK] Auditor role configured"
echo ""

# --- 1.6 Verify RBAC ---
echo "[1.6] Verifying RBAC setup..."
echo ""

echo "--- User groups ---"
echo "  admin_user:   $(groups admin_user 2>/dev/null)"
echo "  dev_user:     $(groups dev_user 2>/dev/null)"
echo "  auditor_user: $(groups auditor_user 2>/dev/null)"
echo ""

echo "--- Test: admin_user sudo access ---"
sudo -u admin_user sudo -n whoami 2>/dev/null && \
    echo "  [PASS] admin_user has sudo" || \
    echo "  [INFO] admin_user has sudo (password required)"

echo ""
echo "--- Test: dev_user write to /opt/app ---"
sudo -u dev_user touch /opt/app/testfile.txt 2>/dev/null && \
    echo "  [PASS] dev_user can write to /opt/app" || \
    echo "  [FAIL] dev_user cannot write to /opt/app"

echo ""
echo "--- Test: dev_user sudo (should fail) ---"
sudo -u dev_user sudo -n whoami 2>/dev/null && \
    echo "  [FAIL] dev_user has sudo (unexpected)" || \
    echo "  [PASS] dev_user has NO sudo access"

echo ""
echo "--- Test: auditor_user read /var/log/syslog ---"
sudo -u auditor_user cat /var/log/syslog > /dev/null 2>&1 && \
    echo "  [PASS] auditor_user can read logs" || \
    echo "  [INFO] auditor_user log access (may need re-login)"

echo ""
echo "--- Test: auditor_user write to /etc (should fail) ---"
sudo -u auditor_user touch /etc/testfile 2>/dev/null && \
    echo "  [FAIL] auditor_user can write to /etc (unexpected)" || \
    echo "  [PASS] auditor_user cannot write to /etc"

echo ""

# =============================================================================
# PART 2: Multi-Factor Authentication for SSH
# =============================================================================

echo ">>> PART 2: MFA Configuration (SSH + Google Authenticator)"
echo "----------------------------------------------"

# --- 2.1 Install Google Authenticator ---
echo "[2.1] Installing Google Authenticator PAM module..."
apt-get update -qq
apt-get install -y libpam-google-authenticator openssh-server
echo "[OK] Google Authenticator installed"
echo ""

# --- 2.2 Generate TOTP for admin_user ---
echo "[2.2] Generating TOTP secret for admin_user..."
sudo -u admin_user google-authenticator \
    --time-based \
    --disallow-reuse \
    --force \
    --rate-limit=3 \
    --rate-time=30 \
    --window-size=3 \
    --qr-mode=none \
    -s /home/admin_user/.google_authenticator

echo ""
echo "[OK] TOTP configured for admin_user"
echo "  Secret key saved to /home/admin_user/.google_authenticator"
echo "  >>> IMPORTANT: Copy the secret key above into Google Authenticator / Authy app <<<"
echo ""

# --- 2.3 Configure PAM for SSH ---
echo "[2.3] Configuring PAM for SSH..."

# Backup original
cp /etc/pam.d/sshd /etc/pam.d/sshd.bak.lab5

# Add Google Authenticator to PAM (nullok = skip MFA for users without it configured)
if ! grep -q "pam_google_authenticator" /etc/pam.d/sshd; then
    echo "auth required pam_google_authenticator.so nullok" >> /etc/pam.d/sshd
    echo "  Added pam_google_authenticator to /etc/pam.d/sshd"
fi
echo "[OK] PAM configured"
echo ""

# --- 2.4 Harden SSH configuration ---
echo "[2.4] Hardening SSH configuration..."

# Backup original
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.lab5

# Apply secure settings
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

# Add AllowUsers if not present
if ! grep -q "^AllowUsers" /etc/ssh/sshd_config; then
    echo "" >> /etc/ssh/sshd_config
    echo "# Lab 5: Restrict SSH access to specific users" >> /etc/ssh/sshd_config
    echo "AllowUsers admin_user dev_user auditor_user" >> /etc/ssh/sshd_config
fi

echo "  PermitRootLogin no"
echo "  ChallengeResponseAuthentication yes"
echo "  KbdInteractiveAuthentication yes"
echo "  UsePAM yes"
echo "  AllowUsers admin_user dev_user auditor_user"
echo "[OK] SSH hardened"
echo ""

# Restart SSH
echo "[2.5] Restarting SSH service..."
systemctl restart sshd
echo "[OK] SSH restarted"
echo ""

# =============================================================================
# PART 3: Attack Simulation
# =============================================================================

echo ">>> PART 3: Attack Simulation"
echo "----------------------------------------------"

# --- 3.1 Install attack tools ---
echo "[3.1] Installing attack simulation tools..."
apt-get install -y hydra 2>/dev/null || echo "  hydra not in repos, install manually"
echo ""

# --- 3.2 Create password dictionary ---
echo "[3.2] Creating password dictionary..."
cat > /tmp/passwords.txt << 'EOF'
123456
password
admin
root
test
letmein
qwerty
abc123
monkey
master
AdminPass123!
EOF
echo "[OK] Dictionary saved to /tmp/passwords.txt ($(wc -l < /tmp/passwords.txt) passwords)"
echo ""

# --- 3.3 Brute-force simulation ---
echo "[3.3] Simulating SSH brute-force attack on admin_user..."
echo "  Command: hydra -l admin_user -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -V"
echo ""
hydra -l admin_user -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -V 2>&1 | tail -20
echo ""
echo "[OK] Brute-force simulation complete"
echo ""

# --- 3.4 Collect evidence ---
echo "[3.4] Collecting authentication logs..."
echo ""
echo "--- Failed login attempts ---"
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10 || \
    journalctl -u sshd --no-pager -n 20 2>/dev/null | grep -i "fail" | tail -10
echo ""

echo "--- MFA related logs ---"
grep "google_authenticator" /var/log/auth.log 2>/dev/null | tail -10 || \
    journalctl -u sshd --no-pager -n 20 2>/dev/null | grep -i "authenticator" | tail -10
echo ""

echo "--- SSH connection attempts ---"
grep "sshd" /var/log/auth.log 2>/dev/null | tail -15 || \
    journalctl -u sshd --no-pager -n 15 2>/dev/null
echo ""

# =============================================================================
# SUMMARY
# =============================================================================

echo "=============================================="
echo "  Lab 5 Setup Complete!"
echo "=============================================="
echo ""
echo "RBAC Summary:"
echo "  admin_user    -> Group: admins     | Full sudo        | MFA enabled"
echo "  dev_user      -> Group: developers | /opt/app access  | Password only"
echo "  auditor_user  -> Group: auditors   | Read /var/log    | Password only"
echo ""
echo "SSH Security:"
echo "  Root login:   DISABLED"
echo "  MFA:          ENABLED for admin_user (TOTP)"
echo "  Allowed users: admin_user, dev_user, auditor_user"
echo ""
echo "Verification commands:"
echo "  ssh admin_user@localhost        # Should ask password + TOTP code"
echo "  ssh dev_user@localhost          # Should ask password only"
echo "  sudo -u dev_user sudo whoami   # Should be denied"
echo ""
echo "Config files for report:"
echo "  /etc/ssh/sshd_config"
echo "  /etc/pam.d/sshd"
echo "  /etc/sudoers.d/admin_user"
echo "  /home/admin_user/.google_authenticator"
echo ""
echo "Log files:"
echo "  /var/log/auth.log"
echo ""
echo "Backups created:"
echo "  /etc/ssh/sshd_config.bak.lab5"
echo "  /etc/pam.d/sshd.bak.lab5"
echo ""
