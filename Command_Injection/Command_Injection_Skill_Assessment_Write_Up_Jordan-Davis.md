# Hack The Box Academy - Command Injection Skill Assessment Write-Up

This repository contains my complete professional write-up for the **Command Injection Skill Assessment** from Hack The Box Academy. In this assessment, I was contracted to perform a penetration test for a company, during which I discovered a file manager web application that appeared to execute backend system commands. My objective was to detect and exploit a command injection vulnerability, bypass any filters in place, and retrieve a sensitive flag from the target server.

---

## 📌 Assessment Overview

- **Module**: Command Injections
- **Skill Level**: Intermediate
- **Objective**: Detect and exploit a command injection vulnerability to achieve Remote Code Execution (RCE) and retrieve the flag.
- **Scenario**: The target application was a file manager with multiple features such as file viewing, searching, and moving files between directories. The "move file" function was found to be vulnerable to command injection, allowing arbitrary command execution on the server.

---

## 🧠 Key Concepts Demonstrated

- Command Injection discovery and exploitation
- Identification of filtered and allowed special characters
- Use of URL encoding and Base64 encoding for payload delivery
- Filter evasion techniques for blacklisted characters and commands
- Using Bash with Base64 decoding to execute arbitrary commands
- Retrieving sensitive files and data from the target server

---

## 🛠 Step-by-Step Exploitation

### 1️⃣ Initial Reconnaissance
- Logged into the file manager using provided credentials.
- Explored `.txt` files and directories; found no sensitive data in their plain text.
- Observed that the application’s `to` and `view` GET parameters controlled file paths and displayed contents from `/var/www/html/files`.
- Attempted basic injections with `&&`, `/`, and `../` in `to` parameter—no errors or abnormal responses, suggesting filtering of special characters.

### 2️⃣ Testing Other Application Features
- Discovered an "Advanced Search" POST request, but payload manipulation yielded no differences in response—deemed non-exploitable.
- Investigated the "Copy To" / "Move" functionality, which triggered a `mv` command on the backend. This appeared promising for command injection.

### 3️⃣ Command Injection Discovery
- Intercepted the request for moving a file:
  ```http
  GET /index.php?to=tmp&from=test.txt&finish=1&move=1 HTTP/1.1
  ```
- Identified blacklisted characters: `||`, `;`, `/`, and space (`%20`).
- Noticed that `&&` was not filtered, making it a viable chain operator.
- Successfully executed commands by URL-encoding payloads and using tab characters (`%09`) instead of spaces.

### 4️⃣ Achieving RCE
- Working test payload:
  ```
  GET /index.php?to=tmp%09%26%26%09bash<<<$(base64%09-d<<<e2xzLC1sYX0=)&from=51459716.txt&finish=1&move=1
  ```
  - This decoded a Base64-encoded `ls -la` command via Bash.

### 5️⃣ Retrieving the Flag
- Final payload to extract the flag:
  ```
  GET /index.php?to=tmp%09%26%26%09bash<<<$(base64%09-d<<<Y2F0IC4uLy4uLy4uLy4uLy4uLy4uLy4uL2ZsYWcudHh0)&from=605311066.txt&finish=1&move=1
  ```
  - Base64 decoded `cat ../../../../../../flag.txt`.
  - Successfully retrieved the flag.

---

## 🔒 Defense Remediation Summary

To prevent vulnerabilities like this:

- Validate and sanitize **all** user input before processing.
- Use parameterized system calls or safer language constructs that avoid direct command execution.
- Implement an **allowlist** for file and directory names rather than blacklisting characters.
- Avoid passing user input directly to shell commands; use language-native file handling functions.
- Disable dangerous PHP functions such as `exec()`, `system()`, `shell_exec()` where not explicitly needed.
- Apply the principle of **least privilege** to the web server user—deny write or execution permissions where not necessary.

---

## 🔗 Author & Profiles

📧 **Author**: Jordan Davis  
🔗 [LinkedIn – jordan-davis47](https://www.linkedin.com/in/jordan-davis47/)  
💻 [GitHub – jd-cybersec](https://github.com/jd-cybersec)

---

## 🏁 Final Thoughts

This assessment reinforced advanced command injection techniques and filter evasion methods. The key takeaway was the importance of persistence and creativity when faced with input filtering, as well as understanding how to safely and effectively chain encoded payloads to achieve the objective.

