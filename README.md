<p align="center">
  <img src="https://raw.githubusercontent.com/RichardBarron27/red-specter-offensive-framework/main/assets/red-specter-logo.png" alt="Red Specter Logo" width="200">
</p>

<br>

# 🗺 Red Specter ScriptMap
[![Stars](https://img.shields.io/github/stars/RichardBarron27/redspecter-scriptmap?style=flat&logo=github)](https://github.com/RichardBarron27/redspecter-scriptmap/stargazers)
![Last Commit](https://img.shields.io/github/last-commit/RichardBarron27/redspecter-scriptmap)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20-purple)
![License](https://img.shields.io/github/license/RichardBarron27/redspecter-scriptmap)



> **ScriptMap** is part of the **Red Specter** tool suite.  
> Companion tools: Offensive Framework · Email OSINT


**Red Specter ScriptMap** is a lightweight AppSec utility that maps and classifies **third-party JavaScript dependencies** in a web application.

It automatically extracts script URLs, identifies analytics/ads/CDN/payment/social/monitoring libraries, flags first-party vs third-party, and generates ready-to-use **Markdown reports** for:

- CSP hardening
- Supply-chain & vendor risk reviews
- Subresource Integrity (SRI) planning
- Penetration testing & AppSec reporting
- Red Specter assessment workflows

> Used during Red Specter appsec engagements to quickly inventory all external JavaScript and highlight potential attack surfaces.


Red Specter ScriptMap is a niche utility for **mapping third-party JavaScript dependencies** in a web application.

Give it a text file of **script URLs or `<script>` tags** and your **primary domain**, and it will:

- Extract script URLs
- Classify them (analytics, ads, CDN, payment, social, monitoring, generic)
- Identify **first-party vs third-party** scripts
- Generate **Markdown reports** for:
  - Vendor / supply-chain security discussions
  - CSP hardening
  - AppSec reviews and client demos

---

## Features

- Understands:
  - Full script URLs (`https://www.googletagmanager.com/gtm.js?id=...`)
  - HTML `<script src="...">` lines
- Categorises scripts into:
  - `analytics`, `ads`, `cdn/library`, `payment`, `social`, `monitoring`, `maps`, or `generic`
- Distinguishes **first-party vs third-party** based on a primary domain you provide
- Produces two Markdown files:
  - `*_summary.md` – high-level overview, counts, and talking points
  - `*_inventory.md` – full table of scripts, domains, categories, and notes

---

## Installation

Clone the repo:

```bash
git clone https://github.com/<your-user>/redspecter-scriptmap.git
cd redspecter-scriptmap

---

### 🔗 Explore the Red Specter tool suite

- 🗺 **ScriptMap** – Map, group, and document your security/automation scripts in seconds.  
  https://github.com/RichardBarron27/redspecter-scriptmap

- 🧨 **Red Specter Offensive Framework** – Modular bash framework for recon, web enum, vuln scanning, and more (Kali-friendly).  
  https://github.com/RichardBarron27/red-specter-offensive-framework

- 📧 **Red Specter Email OSINT** – Email-focused OSINT helper for investigators and defenders.  
  https://github.com/RichardBarron27/redspecter-emailosint

Follow the Red Specter project for more ethical cybersecurity tools and playbooks.




## ❤️ Support Red Specter

If these tools help you, you can support future development:

- ☕ Buy me a coffee: https://www.buymeacoffee.com/redspecter  
- 💼 PayPal: https://paypal.me/richardbarron1747  

Your support helps me keep improving Red Specter and building new tools. Thank you!

Notice for Users: If you cloned this and found it useful, please consider starring the repo! Stars help with visibility and let me know which projects to maintain.
