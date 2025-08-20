# Web Attacks Module – Skill Assessment

## 📖 Overview
This repository contains my professional write-up for the **Hack The Box Academy – Web Attacks Module Skill Assessment**.  
The assessment simulated a penetration test against a vulnerable social networking application.  
The objective was to enumerate, identify, and exploit multiple vulnerabilities to achieve full compromise and retrieve the final flag.  

---

## 🔑 Key Concepts Covered
- Insecure Direct Object Reference (**IDOR**)  
- Broken Access Control  
- Password Reset Token Abuse → Account Takeover  
- Privilege Escalation (Admin Account)  
- XML External Entity (**XXE**) Injection  
- `php://filter` Wrapper Exploitation  
- Burp Suite Intruder (parameter fuzzing)  

---

## 📂 Write-Up Contents
- **[Web_Attacks_Skill_Assessment_Jordan_Davis.md](/Web_Attacks_Module/Web_Attacks_Skill_Assessment_Jordan_Davis.md)**  
  Full step-by-step documentation of the assessment, including methodology, payloads, challenges, and screenshots.  

- **images/**  
  Supporting evidence screenshots:  
  - `token-abuse.png` → Password reset token abuse in Burp Repeater  
  - `admin-enum.png` → Enumerated admin account  
  - `xxe-exploit.png` → XXE injection with `php://filter`  

---

## 🛡️ Defense & Remediation (Summary)
- **IDOR & Access Control** → Enforce server-side checks; replace sequential IDs with UUIDs.  
- **Password Reset Security** → Use unpredictable, session-bound, time-limited tokens.  
- **Privilege Escalation** → Apply strict RBAC; restrict and audit admin endpoints.  
- **XXE Mitigation** → Disable external entity parsing; prefer JSON; sanitize all input.  

---

## ✅ Final Thoughts
This assessment highlighted how multiple low-severity issues can be chained into a **full system compromise**:  

- IDOR → Account Takeover  
- Token Abuse → Admin Privileges  
- Admin Access → XXE Exploitation  
- XXE → Arbitrary File Disclosure + Flag Retrieval  

This mirrors real-world penetration tests where layered misconfigurations escalate into critical impact.  

---

## 🔗 Author & Profiles
- **Author:** Jordan Davis  
- [GitHub Profile](https://github.com/jd-cybersec)  
- [LinkedIn Profile](https://www.linkedin.com/in/jordan-davis47/)  
