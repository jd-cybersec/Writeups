
# Hack The Box Academy - LFI Skill Assessment Write-Up

This repository contains my complete professional write-up for the **Local File Inclusion (LFI) Skill Assessment** from Hack The Box Academy. In this assessment, I was tasked with identifying and exploiting a local file inclusion vulnerability to achieve remote code execution and ultimately retrieve a sensitive flag from the target server.

---

## 📌 Assessment Overview

- **Module**: File Inclusion
- **Skill Level**: Intermediate
- **Objective**: Exploit an LFI vulnerability to gain RCE and retrieve the flag.
- **Scenario**: A vulnerable admin panel exposed access to log files, which were leveraged to inject and execute malicious PHP code via access log poisoning.

---

## 🧠 Key Concepts Demonstrated

- Local File Inclusion (LFI)
- Directory Traversal
- Log File Poisoning for Remote Code Execution
- Web Server Detection (Nginx vs Apache)
- Manual and Automated Recon (with tools like `ffuf`)
- Payload Encoding (Base64)
- Command Injection via Web Shell

---

## 📂 Write-Up Contents

The detailed write-up includes:

- Step-by-step methodology and payloads used
- Reasoning behind each attack vector
- Debugging and troubleshooting process
- Lessons learned
- Real-world remediations to defend against LFI and RCE

---

## 🔒 Defense Remediation Summary

To prevent vulnerabilities like this:

- Avoid dynamic file inclusion where possible.
- Sanitize and validate all user input, especially file paths.
- Disable `allow_url_include` and unnecessary PHP functions.
- Restrict access to log files and sensitive directories.
- Implement proper logging and alerting on abnormal access patterns.
- Ensure the web server has strict permissions on file writes.

---

## 🔗 Author & Profiles

📧 **Author**: Jordan Davis  
🔗 [LinkedIn – jordan-davis](https://www.linkedin.com/in/jordan-davis47/)  
💻 [GitHub – jd-cybersec](https://github.com/jd-cybersec)

---

## 🏁 Final Thoughts

This assessment helped reinforce core LFI concepts and demonstrated how improper handling of logs and file paths can lead to full server compromise. The experience underscored the importance of a methodical approach and the value of validating assumptions during exploitation.

---

