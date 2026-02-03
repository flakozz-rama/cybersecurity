#!/bin/bash

# =============================================================================
# WAF Setup Script for Laboratory Work 4
# Installs Apache, ModSecurity, and OWASP Core Rule Set
# =============================================================================

set -e

echo "=============================================="
echo "  WAF Setup Script - Laboratory Work 4"
echo "=============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Task 1: Install Apache
echo "[Task 1] Installing Apache Web Server..."
apt update
apt install -y apache2

# Verify Apache is running
systemctl start apache2
systemctl enable apache2
echo "[OK] Apache installed and running"
echo ""

# Task 2: Install ModSecurity
echo "[Task 2] Installing ModSecurity..."
apt install -y libapache2-mod-security2

# Copy recommended configuration
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Enable ModSecurity (change DetectionOnly to On)
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

echo "[OK] ModSecurity installed and enabled"
echo ""

# Task 3: Install OWASP Core Rule Set
echo "[Task 3] Installing OWASP Core Rule Set..."
apt install -y modsecurity-crs

# Copy CRS setup configuration
if [ -f /usr/share/modsecurity-crs/crs-setup.conf.example ]; then
    mkdir -p /etc/modsecurity/crs
    cp /usr/share/modsecurity-crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
fi

echo "[OK] OWASP CRS installed"
echo ""

# Create test page
echo "[Task 4] Creating test page..."
cat > /var/www/html/test.php << 'PHPEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WAF Test Page</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .container { background: #f5f5f5; padding: 30px; border-radius: 10px; }
        h1 { color: #333; }
        input[type="text"] { width: 300px; padding: 10px; margin: 10px 0; }
        input[type="submit"] { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .result { background: #e9ecef; padding: 15px; margin-top: 20px; border-radius: 5px; }
        .payloads { margin-top: 30px; background: #fff; padding: 20px; border-radius: 5px; }
        code { background: #e9ecef; padding: 2px 6px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>WAF Test Page</h1>
        <form method="GET">
            <label>Enter ID:</label><br>
            <input type="text" name="id" placeholder="Test input...">
            <input type="submit" value="Submit">
        </form>
        <?php if(isset($_GET['id'])): ?>
        <div class="result">
            <strong>Input:</strong> <?php echo htmlspecialchars($_GET['id']); ?>
        </div>
        <?php endif; ?>
        <div class="payloads">
            <h3>Test Payloads:</h3>
            <ul>
                <li>SQL Injection: <code>1 OR 1=1</code></li>
                <li>XSS: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
                <li>Path Traversal: <code>../../../etc/passwd</code></li>
                <li>Command Injection: <code>; cat /etc/passwd</code></li>
            </ul>
        </div>
    </div>
</body>
</html>
PHPEOF

# Install PHP if not present
apt install -y php libapache2-mod-php

echo "[OK] Test page created at /var/www/html/test.php"
echo ""

# Restart Apache
echo "[*] Restarting Apache..."
systemctl restart apache2

echo ""
echo "=============================================="
echo "  Setup Complete!"
echo "=============================================="
echo ""
echo "Verification steps:"
echo "1. Open browser: http://localhost"
echo "2. Test page: http://localhost/test.php"
echo "3. Try SQL Injection: http://localhost/test.php?id=1%20OR%201=1"
echo "4. Check logs: sudo tail -f /var/log/apache2/modsec_audit.log"
echo ""
echo "If attacks are blocked with 403 Forbidden, WAF is working!"
echo ""
