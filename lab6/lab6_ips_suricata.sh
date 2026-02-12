#!/bin/bash

# =============================================================================
# Laboratory Work 6: IPS with Suricata (Inline Detection & Blocking)
# Run on Ubuntu VM: sudo bash lab6_ips_suricata.sh
#
# Topology (single VM):
#   Attacker (localhost) --> [Suricata IPS + NFQUEUE] --> Protected services
#
# For 2-VM setup, change HOME_NET and run attacks from the second VM.
# =============================================================================

set +e

echo "=============================================="
echo "  Lab 6: IPS Deployment (Suricata)"
echo "=============================================="
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo bash $0"
    exit 1
fi

# =============================================================================
# PART 1: IPS Deployment (Inline Mode)
# =============================================================================

echo ">>> PART 1: IPS Deployment"
echo "----------------------------------------------"

# --- 1.1 Install dependencies ---
echo "[1.1] Installing Suricata and dependencies..."

# Fix any broken dpkg state from previous runs
dpkg --configure -a 2>/dev/null

apt-get update -qq
add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
apt-get update -qq

# Note: suricata 8.x bundles suricata-update, do NOT install it separately
apt-get install -y -o Dpkg::Options::="--force-overwrite" suricata jq

echo "[OK] Suricata installed"
echo ""

# --- 1.2 Enable IP forwarding ---
echo "[1.2] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
echo "[OK] IP forwarding enabled"
echo ""

# --- 1.3 Detect network configuration ---
echo "[1.3] Detecting network configuration..."
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
LOCAL_NET=$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | grep inet | awk '{print $2}')
echo "  Default interface: $DEFAULT_IFACE"
echo "  Local network:     $LOCAL_NET"
echo ""

# --- 1.4 Configure Suricata ---
echo "[1.4] Configuring Suricata for IPS mode..."

# Locate the actual suricata.yaml (may vary by version/distro)
SURICATA_CONF=""
for candidate in /etc/suricata/suricata.yaml /usr/local/etc/suricata/suricata.yaml; do
    if [ -f "$candidate" ]; then
        SURICATA_CONF="$candidate"
        break
    fi
done

if [ -z "$SURICATA_CONF" ]; then
    # Config missing — try to regenerate from dpkg or locate
    echo "  [INFO] Config not found, attempting to regenerate..."
    dpkg --configure -a 2>/dev/null
    apt-get install -y --reinstall -o Dpkg::Options::="--force-overwrite" suricata 2>/dev/null

    for candidate in /etc/suricata/suricata.yaml /usr/local/etc/suricata/suricata.yaml; do
        if [ -f "$candidate" ]; then
            SURICATA_CONF="$candidate"
            break
        fi
    done
fi

if [ -z "$SURICATA_CONF" ]; then
    echo "  [ERROR] Cannot find suricata.yaml. Generating minimal config..."
    mkdir -p /etc/suricata/rules
    SURICATA_CONF="/etc/suricata/suricata.yaml"
    cat > "$SURICATA_CONF" << 'YAMLEOF'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"

default-log-dir: /var/log/suricata/
stats:
  enabled: yes
  interval: 8

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: true
      types:
        - alert:
            tagged-packets: yes
        - stats:
            totals: yes
            threads: no

nfq:
  mode: accept
  repeat-mark: 1
  repeat-mask: 1
  route-queue: 2
  batchcount: 20
  fail-open: yes

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - custom.rules

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
YAMLEOF

    # Create classification.config if missing
    if [ ! -f /etc/suricata/classification.config ]; then
        cat > /etc/suricata/classification.config << 'CLASSEOF'
config classification: attempted-recon,Attempted Information Leak,2
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: attempted-dos,Attempted Denial of Service,2
CLASSEOF
    fi

    # Create reference.config if missing
    if [ ! -f /etc/suricata/reference.config ]; then
        touch /etc/suricata/reference.config
    fi
fi

echo "  Using config: $SURICATA_CONF"

# Backup original config
cp "$SURICATA_CONF" "${SURICATA_CONF}.bak.lab6" 2>/dev/null

# Set HOME_NET
if [ -n "$LOCAL_NET" ]; then
    HOME_NET_CIDR=$(echo "$LOCAL_NET" | sed 's|/[0-9]*|/24|')
    sed -i "s|HOME_NET:.*|HOME_NET: \"[$HOME_NET_CIDR]\"|" "$SURICATA_CONF"
    echo "  HOME_NET set to [$HOME_NET_CIDR]"
else
    echo "  HOME_NET: using default [192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
fi

# Enable community-id for log correlation
sed -i 's/community-id: false/community-id: true/' "$SURICATA_CONF" 2>/dev/null

echo "[OK] Suricata configured"
echo ""

# --- 1.5 Update default rules ---
echo "[1.5] Updating Suricata rule sets..."
suricata-update 2>&1 | tail -5
echo "[OK] Rules updated"
echo ""

# =============================================================================
# PART 2: Custom Rule Engineering
# =============================================================================

echo ">>> PART 2: Custom IPS Rules"
echo "----------------------------------------------"

echo "[2.1] Creating custom rules file..."

# Determine rules directory from config
RULES_DIR=$(grep "default-rule-path" "$SURICATA_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
if [ -z "$RULES_DIR" ]; then
    RULES_DIR="/var/lib/suricata/rules"
fi
mkdir -p "$RULES_DIR"
mkdir -p /etc/suricata/rules 2>/dev/null

cat > "${RULES_DIR}/custom.rules" << 'RULES'
# =============================================================================
# Custom IPS Rules - Laboratory Work 6
# =============================================================================

# -----------------------------------------------------------------------------
# Rule 1: Nmap SYN Port Scan Detection
# Logic: Detects >20 SYN packets from the same source within 5 seconds.
#        Nmap SYN scan sends SYN flags without completing the TCP handshake.
# Limitation: May trigger on legitimate services opening many connections.
# -----------------------------------------------------------------------------
drop tcp any any -> $HOME_NET any ( \
    msg:"CUSTOM LAB6: Nmap SYN Port Scan Detected"; \
    flags:S,12; \
    threshold:type both, track by_src, count 20, seconds 5; \
    classtype:attempted-recon; \
    sid:9000001; rev:1; \
)

# -----------------------------------------------------------------------------
# Rule 2: Nmap XMAS Scan Detection
# Logic: Detects packets with FIN+PSH+URG flags set simultaneously.
#        This combination is never used in legitimate traffic.
# Limitation: Only catches XMAS scan specifically, not other scan types.
# -----------------------------------------------------------------------------
drop tcp any any -> $HOME_NET any ( \
    msg:"CUSTOM LAB6: Nmap XMAS Scan Detected"; \
    flags:FPU,12; \
    threshold:type both, track by_src, count 3, seconds 10; \
    classtype:attempted-recon; \
    sid:9000002; rev:1; \
)

# -----------------------------------------------------------------------------
# Rule 3: SSH Brute-Force Detection
# Logic: Detects >5 SSH connection attempts from the same source within 60s.
#        Brute-force attacks generate rapid repeated login attempts.
# Limitation: May block legitimate users with typos; threshold tuning needed.
# -----------------------------------------------------------------------------
drop tcp any any -> $HOME_NET 22 ( \
    msg:"CUSTOM LAB6: SSH Brute-Force Attempt"; \
    flow:to_server,established; \
    content:"SSH"; depth:4; \
    threshold:type both, track by_src, count 5, seconds 60; \
    classtype:attempted-admin; \
    sid:9000003; rev:1; \
)

# -----------------------------------------------------------------------------
# Rule 4: ICMP Flood Detection
# Logic: Detects >50 ICMP echo requests from one source in 10 seconds.
#        Normal ping sends 1 packet/sec; flood sends hundreds/sec.
# Limitation: Does not catch distributed ICMP floods from many sources.
# -----------------------------------------------------------------------------
drop icmp any any -> $HOME_NET any ( \
    msg:"CUSTOM LAB6: ICMP Flood Detected"; \
    itype:8; \
    threshold:type both, track by_src, count 50, seconds 10; \
    classtype:attempted-dos; \
    sid:9000004; rev:1; \
)

# -----------------------------------------------------------------------------
# Rule 5: ICMP Large Packet (Ping of Death variant)
# Logic: Detects ICMP packets larger than 1000 bytes.
#        Normal ping uses 64 bytes; oversized packets may indicate attack.
# Limitation: Some legitimate tools use large ICMP for MTU testing.
# -----------------------------------------------------------------------------
drop icmp any any -> $HOME_NET any ( \
    msg:"CUSTOM LAB6: Oversized ICMP Packet Detected"; \
    itype:8; \
    dsize:>1000; \
    classtype:attempted-dos; \
    sid:9000005; rev:1; \
)
RULES

echo "[OK] Custom rules created at ${RULES_DIR}/custom.rules"
echo ""

# --- 2.2 Register custom rules in config ---
echo "[2.2] Registering custom rules in Suricata config..."
if ! grep -q "custom.rules" "$SURICATA_CONF"; then
    # Add custom.rules to the rule-files section
    sed -i '/rule-files:/a\  - custom.rules' "$SURICATA_CONF" 2>/dev/null
fi
# Ensure custom rules exist in the default-rule-path directory
if [ -d /var/lib/suricata/rules ] && [ "$RULES_DIR" != "/var/lib/suricata/rules" ]; then
    cp "${RULES_DIR}/custom.rules" /var/lib/suricata/rules/custom.rules
fi
echo "[OK] Custom rules registered"
echo ""

# --- 2.3 Validate configuration ---
echo "[2.3] Validating Suricata configuration..."
suricata -T -c "$SURICATA_CONF" 2>&1 | tail -5
echo ""

# --- 2.4 Set up NFQUEUE for inline mode ---
echo "[2.4] Setting up iptables NFQUEUE rules..."

# Clear any previous lab rules
iptables -D INPUT -j NFQUEUE --queue-num 0 2>/dev/null
iptables -D FORWARD -j NFQUEUE --queue-num 0 2>/dev/null

# Add NFQUEUE rules
iptables -I INPUT -j NFQUEUE --queue-num 0
iptables -I FORWARD -j NFQUEUE --queue-num 0

echo "  iptables INPUT  -> NFQUEUE 0"
echo "  iptables FORWARD -> NFQUEUE 0"
echo "[OK] NFQUEUE configured"
echo ""

# --- 2.5 Start Suricata in IPS mode ---
echo "[2.5] Starting Suricata in IPS (inline) mode..."

# Stop if already running
systemctl stop suricata 2>/dev/null
pkill -f "suricata" 2>/dev/null
sleep 2

# Start in IPS mode with NFQUEUE
suricata -c "$SURICATA_CONF" -q 0 -D
sleep 3

if pgrep -x suricata > /dev/null; then
    echo "[OK] Suricata is running in IPS mode (PID: $(pgrep -x suricata))"
else
    echo "[WARN] Suricata may not have started. Check: suricata -c $SURICATA_CONF -q 0"
fi
echo ""

# --- 2.6 Verify legitimate traffic ---
echo "[2.6] Verifying legitimate traffic passes through..."
ping -c 3 127.0.0.1 > /dev/null 2>&1 && \
    echo "  [PASS] Legitimate ICMP traffic passes" || \
    echo "  [WARN] ICMP blocked - check Suricata config"
echo ""

# =============================================================================
# PART 3: Attack Simulation & Evaluation
# =============================================================================

echo ">>> PART 3: Attack Simulation"
echo "----------------------------------------------"

# --- 3.1 Install attack tools ---
echo "[3.1] Installing attack tools..."
apt-get install -y nmap hydra hping3 2>/dev/null || \
    echo "  Some tools may need manual installation"
echo ""

# Clear logs before testing
echo "" > /var/log/suricata/fast.log 2>/dev/null
echo ""

# --- 3.2 Attack 1: Nmap Port Scan ---
echo "[3.2] Attack 1: Nmap SYN Scan..."
echo "  Command: nmap -sS -T4 127.0.0.1"
echo ""
timeout 30 nmap -sS -T4 127.0.0.1 2>&1 | tail -15
echo ""

echo "  Suricata alerts (Nmap):"
grep -i "nmap\|scan\|recon" /var/log/suricata/fast.log 2>/dev/null | tail -5 || \
    echo "  (checking eve.json...)" && \
    cat /var/log/suricata/eve.json 2>/dev/null | jq -r 'select(.event_type=="alert") | select(.alert.signature | test("scan|nmap";"i")) | "\(.timestamp) [\(.alert.action)] \(.alert.signature)"' 2>/dev/null | tail -5
echo ""

# --- 3.3 Attack 2: SSH Brute-Force ---
echo "[3.3] Attack 2: SSH Brute-Force..."
echo "  Command: hydra -l root -P /tmp/passwords.txt ssh://127.0.0.1 -t 4"
echo ""

# Create password list if not exists
cat > /tmp/passwords.txt << 'EOF'
123456
password
admin
root
test
letmein
qwerty
abc123
EOF

timeout 30 hydra -l root -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -V 2>&1 | tail -15
echo ""

echo "  Suricata alerts (SSH):"
grep -i "ssh\|brute" /var/log/suricata/fast.log 2>/dev/null | tail -5
echo ""

# --- 3.4 Attack 3: ICMP Flood ---
echo "[3.4] Attack 3: ICMP Flood..."
echo "  Command: ping -f -c 200 127.0.0.1"
echo ""
timeout 15 ping -f -c 200 127.0.0.1 2>&1 || true
echo ""

# Alternative with hping3 if available
if command -v hping3 &> /dev/null; then
    echo "  Also testing with hping3..."
    echo "  Command: hping3 --icmp --flood -c 300 127.0.0.1"
    timeout 10 hping3 --icmp --flood -c 300 127.0.0.1 2>&1 | tail -5 || true
    echo ""
fi

echo "  Suricata alerts (ICMP):"
grep -i "icmp\|flood\|dos" /var/log/suricata/fast.log 2>/dev/null | tail -5
echo ""

# =============================================================================
# PART 4: Evidence Collection
# =============================================================================

echo ">>> PART 4: Evidence Collection"
echo "----------------------------------------------"
echo ""

echo "=== All Suricata Alerts (fast.log) ==="
echo ""
cat /var/log/suricata/fast.log 2>/dev/null | head -40 || echo "  No alerts in fast.log"
echo ""

echo "=== Suricata Alerts (eve.json - structured) ==="
echo ""
if [ -f /var/log/suricata/eve.json ]; then
    cat /var/log/suricata/eve.json | \
        jq -r 'select(.event_type=="alert") | "\(.timestamp) [\(.alert.action)] \(.alert.signature) | \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port)"' 2>/dev/null | tail -20
else
    echo "  eve.json not found"
fi
echo ""

echo "=== Suricata Stats ==="
echo ""
if [ -f /var/log/suricata/stats.log ]; then
    tail -30 /var/log/suricata/stats.log
else
    echo "  stats.log not found"
fi
echo ""

echo "=== System Resource Usage ==="
echo ""
echo "  Suricata process:"
ps aux | grep "[s]uricata" | awk '{printf "  PID: %s | CPU: %s%% | MEM: %s%% | RSS: %s KB\n", $2, $3, $4, $6}'
echo ""

# =============================================================================
# SUMMARY
# =============================================================================

echo "=============================================="
echo "  Lab 6 Setup Complete!"
echo "=============================================="
echo ""
echo "IPS Architecture:"
echo "  Mode:     Inline (NFQUEUE)"
echo "  Engine:   Suricata"
echo "  Rules:    Default + 5 custom rules"
echo ""
echo "Custom Rules:"
echo "  SID 9000001 - Nmap SYN Scan      (>20 SYN/5s)"
echo "  SID 9000002 - Nmap XMAS Scan     (FPU flags)"
echo "  SID 9000003 - SSH Brute-Force    (>5 attempts/60s)"
echo "  SID 9000004 - ICMP Flood         (>50 echo/10s)"
echo "  SID 9000005 - Oversized ICMP     (>1000 bytes)"
echo ""
echo "Config files for report:"
echo "  $SURICATA_CONF"
echo "  ${RULES_DIR}/custom.rules"
echo ""
echo "Log files for report:"
echo "  /var/log/suricata/fast.log   (human-readable alerts)"
echo "  /var/log/suricata/eve.json   (structured JSON logs)"
echo "  /var/log/suricata/stats.log  (performance stats)"
echo ""
echo "Manual testing commands:"
echo "  nmap -sS -T4 <target_ip>                  # Port scan"
echo "  hydra -l root -P /tmp/passwords.txt ssh://<target_ip>  # SSH brute"
echo "  ping -f -c 200 <target_ip>                # ICMP flood"
echo ""
echo "Monitor alerts in real-time:"
echo "  tail -f /var/log/suricata/fast.log"
echo ""
echo "To stop IPS and restore normal traffic:"
echo "  pkill suricata"
echo "  iptables -D INPUT -j NFQUEUE --queue-num 0"
echo "  iptables -D FORWARD -j NFQUEUE --queue-num 0"
echo ""
echo "Backup created:"
echo "  ${SURICATA_CONF}.bak.lab6"
echo ""
