# Red Specter ScriptMap

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
