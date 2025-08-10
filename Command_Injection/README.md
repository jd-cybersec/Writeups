# Hack The Box Academy - Command Injection Skill Assessment Write-Up

This repository contains my complete professional write-up for the **Command Injection Skill Assessment** from Hack The Box Academy.  
In this assessment, I was tasked with identifying and exploiting a command injection vulnerability in a file manager application to retrieve a sensitive flag from the target system.

---

## 📌 Assessment Overview

- **Module**: Command Injections  
- **Skill Level**: Intermediate  
- **Objective**: Detect and exploit a command injection vulnerability to gain arbitrary command execution and retrieve the flag.  
- **Scenario**: During a simulated penetration test, a file manager application was found. Investigation revealed that file move operations executed system-level commands on the backend, which were vulnerable to injection.

---

## 🧠 Key Concepts Demonstrated

- Command Injection Discovery & Exploitation  
- Bypassing Input Filters and Blacklists  
- Obfuscation & Encoding Techniques (Base64, encoded operators)  
- Using HTTP Parameter Manipulation for Payload Delivery  
- File Path Traversal for Flag Retrieval  

---

## 📂 Write-Up Contents

The detailed write-up includes:

- Step-by-step exploitation methodology and payloads used  
- Analysis of blacklist restrictions and how they were bypassed  
- Encoding strategies for successful command execution  
- Retrieval of the flag from restricted directories  
- Defense remediations to protect against command injection  

---

## 🔒 Defense Remediation Summary

To prevent vulnerabilities like this:

- Sanitize and validate all user inputs before using them in system commands.  
- Use secure API functions or language-native file operations instead of shell commands.  
- Implement strict allowlists for expected values in parameters like file paths.  
- Disable dangerous shell functions in production environments.  
- Apply least-privilege permissions to the application’s execution context.  

---

## 🔗 Author & Profiles

📧 **Author**: Jordan Davis  
🔗 [LinkedIn – jordan-davis47](https://www.linkedin.com/in/jordan-davis47/)  
💻 [GitHub – jd-cybersec](https://github.com/jd-cybersec)

---

## 🏁 Final Thoughts

This assessment reinforced critical concepts in identifying and exploiting command injection vulnerabilities, especially when dealing with limited feedback and strict input filters. It also demonstrated the importance of careful payload crafting and encoding techniques to bypass security restrictions.

---
