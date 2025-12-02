# Red Specter ScriptMap Summary

**Primary domain:** `example.com`
**Total scripts detected:** 5
- First-party: 1
- Third-party: 4

## Category Breakdown

| Category      | Count |
|--------------|-------|
| cdn/library | 2 |
| analytics | 1 |
| generic | 1 |
| payment | 1 |

## Top Third-Party Domains

| Domain | Count |
|--------|-------|
| `js.stripe.com` | 2 |
| `cdn.jsdelivr.net` | 1 |
| `www.googletagmanager.com` | 1 |

## Suggested Talking Points

- Review all **third-party analytics and tracking scripts** for data minimisation and consent.
- Consider **Subresource Integrity (SRI)** for CDN-hosted libraries where feasible.
- Tighten your **Content-Security-Policy (CSP)** `script-src` to only allow the domains listed here.
- Audit embedded **payment, social, and widget scripts** for unnecessary permissions and data access.
- Maintain this script inventory as part of your **vendor and supply-chain security** documentation.
