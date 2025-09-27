---
layout: post
title: "Broken Authentication"
date: 2025-09-27 13:00
categories: [Web Pentesting, HTB CWES]
tags: [Brute-Force Attacks, Password Attacks, Authentication Bypasses]
---

# Introduction to Authentication
## What is Authentication
# Authentication vs. Authorization  

Authentication and Authorization often get mixed up, but they play **different roles** in securing systems.  
Think of it like a **club entry**:  
- Authentication = Showing your ID to prove *who you are*.  
- Authorization = Deciding *where you can go inside* (VIP lounge or just the dance floor).  

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

## Key Takeaways  
- **Knowledge factors** are the easiest to compromise.  
- **Ownership factors** are stronger but face physical risks.  
- **Inherence factors** are convenient but carry irreversible consequences if breached.  
- The strongest defense is **Multi-Factor Authentication (MFA)**, combining two or more factors to raise the attack barrier.  
