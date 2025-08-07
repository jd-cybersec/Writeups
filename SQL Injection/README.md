
# SQL Injection Fundamentals – HTB Academy Skill Assessment

This repository contains a comprehensive walkthrough of the **SQL Injection Fundamentals** skill assessment on Hack The Box Academy.

## 🧠 Assessment Scenario

The target is a public-facing web application for **Inlanefreight**, an organization concerned about potential SQL Injection vulnerabilities following a competitor breach. The objective was to assess the site from a grey-box perspective and determine the presence and exploitability of any SQLi flaws, ultimately achieving **Remote Code Execution (RCE)**.

---

## 📄 Write-Up

The write-up includes:

- SQLi-based login bypass
- Column enumeration using `UNION SELECT`
- Dumping schema and table data
- Privilege enumeration (`@@version`, `USER()`, `user_privileges`)
- Discovery of file write vectors using `INTO OUTFILE`
- Bypassing limitations with `FROM_BASE64()` encoded web shell
- Final RCE and flag retrieval

---

## 🔍 Key Techniques Used

- **Login Bypass via SQL Injection**
- **Database Enumeration (Information_Schema)**
- **Privilege Escalation via Root Account Misconfiguration**
- **Payload Delivery with `INTO OUTFILE`**
- **Command Execution via Web Shell**
- **Encoding Bypass using `FROM_BASE64()`**

---

## 🛡️ Mitigation Recommendations

To prevent similar vulnerabilities in real-world applications:

- Use **parameterized queries** or **prepared statements** (e.g., PDO, MySQLi)
- Implement **input sanitization and validation** on both client and server side
- Restrict **database user privileges**, never use `root` in production apps
- Set **secure permissions** on sensitive directories (e.g., `/var/www/html`)
- Disable `LOAD_FILE`, `INTO OUTFILE`, and other dangerous SQL functions if not needed
- Employ **Web Application Firewalls (WAF)** to monitor and block malicious queries
- Log and alert on suspicious query patterns and failed logins

---

## 📌 Takeaways

This assessment demonstrates the real-world impact of SQL injection vulnerabilities when misconfigured:

- A simple login form flaw escalated to full **system compromise**
- Default configurations and weak privilege separation led to **root-level access**
- Encoding and smart payload delivery allowed **filter evasion and code execution**

---

## 👤 Author

**Jordan Davis**  
Offensive Security Student | Penetration Testing Enthusiast  

---

## ⚠️ Disclaimer

This repository is for **educational purposes only**. All actions performed were done in a controlled, ethical environment provided by Hack The Box Academy.
