#!/bin/bash

set -e

echo "=============================================="
echo "Laboratory Work №2: DAC and MAC in Linux"
echo "=============================================="

echo ""
echo ">>> TASK 1: DAC Implementation"
echo "----------------------------------------------"

echo "[1.1] Creating users: user1 and user2"
sudo useradd -m user1 2>/dev/null || echo "user1 already exists"
sudo useradd -m user2 2>/dev/null || echo "user2 already exists"

echo "user1:password1" | sudo chpasswd
echo "user2:password2" | sudo chpasswd

echo "Users created successfully."
echo "Verify with: cat /etc/passwd | grep -E 'user1|user2'"
cat /etc/passwd | grep -E 'user1|user2' || true

echo ""
echo "[1.2] Creating test file"
sudo mkdir -p /home/user1
echo "This is a secret file owned by user1." | sudo tee /home/user1/secret.txt

echo ""
echo "[1.3] Setting ownership and permissions"
sudo chown user1:user1 /home/user1/secret.txt
sudo chmod 600 /home/user1/secret.txt

echo "File permissions set: rw------- (600)"
echo "Verify with: ls -l /home/user1/secret.txt"
ls -l /home/user1/secret.txt

echo ""
echo "[1.4] Verifying access control"

echo "Testing user1 access (should succeed):"
sudo -u user1 cat /home/user1/secret.txt && echo "SUCCESS: user1 can read the file"

echo ""
echo "Testing user2 access (should fail):"
sudo -u user2 cat /home/user1/secret.txt 2>&1 && echo "UNEXPECTED: user2 could read" || echo "SUCCESS: user2 cannot read (Permission denied)"

echo ""
echo ">>> TASK 2: DAC using ACLs"
echo "----------------------------------------------"

echo "[2.1] Installing ACL tools"
sudo apt-get update -qq
sudo apt-get install -y acl

echo ""
echo "[2.2] Granting read access to user2 via ACL"
sudo setfacl -m u:user2:r /home/user1/secret.txt
echo "ACL entry added: user2 has read permission"

echo ""
echo "[2.3] Verifying ACL permissions"
echo "File ACL (getfacl):"
getfacl /home/user1/secret.txt

echo ""
echo "File permissions (ls -l) - note the '+' indicating ACL:"
ls -l /home/user1/secret.txt

echo ""
echo "Testing user2 access (should now succeed):"
sudo -u user2 cat /home/user1/secret.txt && echo "SUCCESS: user2 can now read the file"

echo ""
echo ">>> TASK 3: MAC Implementation (AppArmor)"
echo "----------------------------------------------"

echo "[3.1] Checking AppArmor status"
sudo systemctl status apparmor --no-pager || echo "AppArmor service status check"
sudo aa-status

echo ""
echo "[3.2] Listing AppArmor profiles"
ls /etc/apparmor.d/ | head -20

echo ""
echo "[3.3] AppArmor profile enforcement demonstration"

if [ -f /etc/apparmor.d/usr.sbin.tcpdump ]; then
    echo "Checking tcpdump profile status:"
    sudo aa-status | grep tcpdump || echo "tcpdump profile not loaded"

    echo ""
    echo "To put a profile in enforce mode, use:"
    echo "  sudo aa-enforce /etc/apparmor.d/usr.sbin.tcpdump"
fi

echo ""
echo "[3.4] Creating a sample AppArmor profile for demonstration"

echo '#!/bin/bash
echo "Hello from test script"
cat /etc/passwd > /dev/null
echo "Read /etc/passwd successfully"
' | sudo tee /usr/local/bin/test_apparmor.sh
sudo chmod +x /usr/local/bin/test_apparmor.sh

sudo tee /etc/apparmor.d/usr.local.bin.test_apparmor.sh << 'EOF'
#include <tunables/global>

/usr/local/bin/test_apparmor.sh {
  #include <abstractions/base>

  /usr/local/bin/test_apparmor.sh r,

  deny /etc/passwd r,

  /bin/bash ix,
  /usr/bin/bash ix,
  /bin/cat ix,
  /usr/bin/cat ix,
}
EOF

echo "AppArmor profile created."

echo ""
echo "[3.5] Loading and enforcing the AppArmor profile"
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.test_apparmor.sh 2>/dev/null || \
sudo apparmor_parser -a /etc/apparmor.d/usr.local.bin.test_apparmor.sh

echo ""
echo "[3.6] Testing MAC restrictions"
echo "Running test script (access to /etc/passwd should be denied by AppArmor):"
/usr/local/bin/test_apparmor.sh 2>&1 || echo "Script execution completed (may have restrictions)"

echo ""
echo "Check AppArmor denials in audit log:"
sudo dmesg | grep -i apparmor | tail -5 || echo "No recent AppArmor messages"

echo ""
echo "=============================================="
echo "Laboratory Work №2 Complete!"
echo "=============================================="
