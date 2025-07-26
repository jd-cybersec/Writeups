# 🔍 Web Reconnaissance with FFUF – HTB Academy Skill Assessment

**Author:** Jordan Davis  
**Module:** Attacking Web Applications with FFUF (Hack The Box Academy)  
**Write-up:** [FFUF_Recon_Portfolio_Writeup_Jordan_Davis.pdf](./FFUF_Recon_Portfolio_Writeup_Jordan_Davis.pdf)

---

## 📄 Overview

This repository contains my full walkthrough and analysis of the FFUF Skill Assessment on Hack The Box Academy, where I successfully completed a series of real-world web reconnaissance tasks using the fuzzing tool **FFUF**.

The goal was to emulate black-box discovery techniques often used in penetration testing and bug bounty engagements — including vHost discovery, page enumeration, extension analysis, parameter fuzzing, and value-based POST fuzzing.

---

## 🎯 Objectives Covered

| Task | Description |
|------|-------------|
| ✅ Subdomain Enumeration | Identify accessible subdomains via vHost fuzzing |
| ✅ Extension Discovery | Detect which file types and back-end technologies are in use |
| ✅ Page & Directory Fuzzing | Discover hidden and sensitive endpoints |
| ✅ Parameter Fuzzing | Enumerate query and POST parameters |
| ✅ Value Enumeration | Discover valid input values triggering server-side behavior |
| ✅ Flag Capture | Complete the end-to-end recon flow to reveal the flag |

---

## 🛠️ Tools & Resources

- [`ffuf`](https://github.com/ffuf/ffuf) – Fast web fuzzer written in Go
- [`curl`](https://curl.se/) – Used for POST requests and validation
- [`SecLists`](https://github.com/danielmiessler/SecLists) – Wordlists used for subdomain, extension, parameter, and value fuzzing
- HTB Pwnbox – Linux environment provided by Hack The Box Academy

---

## 📘 What You'll Find in the PDF

The write-up includes:

- 🧠 My approach and methodology  
- 🔧 All commands and tools used  
- 🧪 Observations from each fuzzing stage  
- ✅ Validation techniques using both `ffuf` and `curl`  
- 📌 Final payload that triggered the hidden flag

> 📎 **Download the full write-up here:**  
> [FFUF_Recon_Portfolio_Writeup_Jordan_Davis.pdf](./FFUF_Recon_Portfolio_Writeup_Jordan_Davis.pdf)

---

## 💡 Key Takeaways

- Proper fuzzing flow saves time and maximizes discovery
- Understanding filter size (`-fs`) and content length is critical for spotting meaningful responses
- Combining different fuzzing techniques (GET, POST, extensions, and parameters) leads to deeper enumeration
- Even a single tool like `ffuf` can be extremely powerful when wielded with precision and context

---
