# Laboratory Work №2

## Topic: Implementing Mandatory Access Control (MAC) and Discretionary Access Control (DAC) in Linux

**Student:** [Your Name]
**Group:** [Your Group]
**Date:** [Date]

---

## 1. Purpose of the Laboratory Work

The purpose of this laboratory work is to study and compare two fundamental access control models — Discretionary Access Control (DAC) and Mandatory Access Control (MAC) — through practical implementation in a Linux operating system.

---

## 2. Theoretical Overview

### 2.1 Discretionary Access Control (DAC)

DAC is an access control model where the **owner of a resource** decides who can access it. In Linux, DAC is implemented through:

- **File permissions (rwx):** Read, Write, Execute for Owner, Group, Others
- **Ownership:** Each file has an owner (user) and a group
- **Access Control Lists (ACLs):** Extended permissions for specific users/groups

**Characteristics:**
- User-controlled
- Flexible but less secure
- Can be modified by resource owner
- Examples: chmod, chown, setfacl

### 2.2 Mandatory Access Control (MAC)

MAC is an access control model where **system-wide security policies** are enforced by the operating system kernel. Users cannot override these policies, even with root privileges.

**Implementations in Linux:**
- **SELinux** (Security-Enhanced Linux) - used in RHEL/CentOS/Fedora
- **AppArmor** - used in Ubuntu/Debian

**Characteristics:**
- System-controlled (kernel-enforced)
- Centralized security policies
- Cannot be bypassed by users (including root)
- Provides defense-in-depth

### 2.3 Relation to CIA Triad

| CIA Component | DAC | MAC |
|---------------|-----|-----|
| **Confidentiality** | Basic (owner-controlled) | Strong (policy-enforced) |
| **Integrity** | Limited protection | Strong protection |
| **Availability** | High (flexible access) | Controlled (strict policies) |

---

## 3. Laboratory Tasks and Results

### Task 1: DAC Implementation

#### Step 1.1: Create Users

```bash
sudo useradd -m user1
sudo useradd -m user2
```

**Screenshot:** [Insert screenshot showing user creation]

**Output:**
```
# cat /etc/passwd | grep -E 'user1|user2'
user1:x:1001:1001::/home/user1:/bin/bash
user2:x:1002:1002::/home/user2:/bin/bash
```

#### Step 1.2: Create Test File

```bash
echo "This is a secret file owned by user1." | sudo tee /home/user1/secret.txt
```

#### Step 1.3: Set Ownership and Permissions

```bash
sudo chown user1:user1 /home/user1/secret.txt
sudo chmod 600 /home/user1/secret.txt
```

**Screenshot:** [Insert screenshot showing file permissions]

**Output:**
```
# ls -l /home/user1/secret.txt
-rw------- 1 user1 user1 38 Jan 27 12:00 /home/user1/secret.txt
```

**Permission Breakdown:**
- `-rw-------` = 600
- Owner (user1): read + write
- Group: no permissions
- Others: no permissions

#### Step 1.4: Verify Access

**user1 access (SUCCESS):**
```bash
sudo -u user1 cat /home/user1/secret.txt
# Output: This is a secret file owned by user1.
```

**user2 access (DENIED):**
```bash
sudo -u user2 cat /home/user1/secret.txt
# Output: cat: /home/user1/secret.txt: Permission denied
```

**Screenshot:** [Insert screenshot showing access test]

#### Explanation: Why user2 Cannot Access the File

user2 cannot access the file because:
1. The file has permissions `600` (rw-------)
2. Only the **owner** (user1) has read/write access
3. user2 is **not** the owner
4. user2 is **not** in the user1 group
5. The "others" permission bits are set to `---` (no access)

This demonstrates **DAC**: the owner controls who can access the resource.

---

### Task 2: DAC using Access Control Lists (ACL)

#### Step 2.1: Install ACL Tools

```bash
sudo apt-get install acl
```

#### Step 2.2: Grant Read Access to user2

```bash
sudo setfacl -m u:user2:r /home/user1/secret.txt
```

#### Step 2.3: Verify Permissions

**ACL Output:**
```bash
getfacl /home/user1/secret.txt
```

```
# file: home/user1/secret.txt
# owner: user1
# group: user1
user::rw-
user:user2:r--
group::---
mask::r--
other::---
```

**Screenshot:** [Insert screenshot showing ACL permissions]

**File listing (note the + indicating ACL):**
```
-rw-r-----+ 1 user1 user1 38 Jan 27 12:00 /home/user1/secret.txt
```

**user2 access (NOW SUCCEEDS):**
```bash
sudo -u user2 cat /home/user1/secret.txt
# Output: This is a secret file owned by user1.
```

#### Explanation: How ACL Extends Standard DAC

| Feature | Standard Permissions | ACL |
|---------|---------------------|-----|
| Granularity | 3 categories (owner, group, others) | Specific users/groups |
| Flexibility | Limited | High |
| Notation | rwxrwxrwx | Extended attributes |
| Command | chmod | setfacl/getfacl |

ACL allows us to grant user2 read permission **without**:
- Changing file ownership
- Adding user2 to user1's group
- Giving access to all "others"

This provides **fine-grained access control** while maintaining DAC principles.

---

### Task 3: MAC Implementation (AppArmor)

#### Step 3.1: Check AppArmor Status

```bash
sudo aa-status
```

**Screenshot:** [Insert screenshot showing AppArmor status]

**Output:**
```
apparmor module is loaded.
X profiles are loaded.
X profiles are in enforce mode.
X profiles are in complain mode.
X processes are running with profiles.
```

#### Step 3.2: List AppArmor Profiles

```bash
ls /etc/apparmor.d/
```

Common profiles include:
- `usr.bin.firefox`
- `usr.sbin.tcpdump`
- `usr.bin.man`

#### Step 3.3: Enforce Mode Demonstration

**Put a profile in enforce mode:**
```bash
sudo aa-enforce /etc/apparmor.d/usr.sbin.tcpdump
```

**Or create a custom profile:**
```bash
sudo aa-genprof /path/to/application
```

#### Step 3.4: Observe MAC Restrictions

**AppArmor audit log:**
```bash
sudo dmesg | grep apparmor
```

**Example denial message:**
```
[12345.678] audit: type=1400 audit(1234567890.123:456): apparmor="DENIED"
operation="open" profile="/usr/local/bin/test" name="/etc/passwd"
pid=1234 comm="test" requested_mask="r" denied_mask="r"
```

**Screenshot:** [Insert screenshot showing AppArmor enforcement]

#### Explanation: How MAC Applies Even to Root

| Aspect | DAC | MAC |
|--------|-----|-----|
| Root bypass | Root can access anything | Root **cannot** bypass MAC |
| Policy control | User/owner | System administrator/kernel |
| Enforcement | File system | Kernel (LSM) |

**Key Points:**
1. MAC policies are enforced at the **kernel level** via Linux Security Modules (LSM)
2. Even root cannot modify running MAC policies without proper permissions
3. AppArmor uses **path-based** profiles defining allowed operations
4. This provides **defense-in-depth**: even if an attacker gains root, MAC limits damage

---

## 4. Comparative Analysis

| Feature | DAC | MAC |
|---------|:---:|:---:|
| **Controlled by user** | + | - |
| **Centralized policy** | - | + |
| **Flexibility** | High | Low |
| **Security level** | Basic | High |
| **Can be bypassed by root** | + | - |
| **Implementation complexity** | Low | High |
| **Performance overhead** | Minimal | Low-Moderate |
| **Use case** | General file sharing | High-security environments |

### Detailed Comparison

**DAC Advantages:**
- Simple to understand and configure
- Flexible for collaborative environments
- No additional software required
- Users can share resources easily

**DAC Disadvantages:**
- Owner can make mistakes (accidentally grant access)
- Vulnerable to privilege escalation
- No protection against root compromise
- Difficult to enforce organization-wide policies

**MAC Advantages:**
- Kernel-enforced security
- Protection against privilege escalation
- Centralized policy management
- Defense-in-depth security model

**MAC Disadvantages:**
- Complex to configure
- May break applications if misconfigured
- Requires administrator expertise
- Less flexible for end-users

---

## 5. Conclusion

This laboratory work demonstrated the fundamental differences between DAC and MAC:

1. **DAC** provides basic access control where resource owners decide permissions. It's flexible but can be bypassed by privileged users.

2. **ACLs** extend DAC by allowing fine-grained permissions for specific users and groups without modifying ownership or group membership.

3. **MAC (AppArmor)** enforces system-wide security policies at the kernel level. Even root cannot bypass these restrictions, providing defense-in-depth.

4. For high-security environments, **combining DAC and MAC** is recommended:
   - DAC for day-to-day file management
   - MAC for critical system protection

The CIA triad is better supported by MAC:
- **Confidentiality**: MAC prevents unauthorized access even by compromised processes
- **Integrity**: MAC restricts what programs can modify
- **Availability**: While MAC may restrict access, it protects against denial-of-service from malicious processes

---

## References

1. Linux man pages: chmod(1), chown(1), setfacl(1), getfacl(1)
2. AppArmor Documentation: https://apparmor.net/
3. Ubuntu Security Documentation: https://ubuntu.com/security/apparmor
