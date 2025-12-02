#!/usr/bin/env python3
"""
Red Specter ScriptMap
---------------------

Purpose:
    Take a list of <script> tags or JavaScript URLs and:
      - Extract script URLs
      - Classify them by category (analytics, ads, CDN, payment, social, monitoring, generic)
      - Determine if they are first-party or third-party relative to a given primary domain
      - Generate human-readable Markdown reports for risk discussions and CSP hardening

Usage:
    python3 redspecter_scriptmap.py scripts.txt --primary-domain example.com

Input format:
    - One entry per line
    - Each line can be:
        - A full script URL (e.g. https://www.googletagmanager.com/gtm.js?id=GTM-XXXX)
        - A <script> tag line from HTML (the tool will extract src="...")

Author: Richard (Red Specter) + Vigil (AI Partner)
"""

import argparse
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, Iterable
from collections import Counter


SCRIPT_SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)


@dataclass
class ScriptEntry:
    raw: str
    url: str
    scheme: str
    host: str
    path: str
    category: str
    subcategory: str
    first_party: bool
    notes: List[str] = field(default_factory=list)

    def domain_label(self) -> str:
        return self.host or "(no host)"


CATEGORY_RULES: Dict[str, List[str]] = {
    "analytics": [
        "google-analytics.com",
        "analytics.google.com",
        "googletagmanager.com",
        "gtag/js",
        "segment.io",
        "mixpanel.com",
        "matomo",
        "plausible.io",
        "snowplow",
    ],
    "ads": [
        "doubleclick.net",
        "googlesyndication.com",
        "adservice.google.com",
        "adsystem.com",
        "adnxs.com",
        "taboola",
        "outbrain",
    ],
    "cdn/library": [
        "cdn.",
        "cdnjs",
        "jsdelivr",
        "cloudflare.com",
        "unpkg.com",
        "static.",
        "ajax.googleapis.com",
        "code.jquery.com",
        "bootstrap",
    ],
    "payment": [
        "js.stripe.com",
        "stripe.com",
        "paypalobjects.com",
        "braintreepayments.com",
        "checkout.",
    ],
    "social": [
        "connect.facebook.net",
        "facebook.com",
        "platform.twitter.com",
        "twitter.com/widgets",
        "linkedin.com",
        "snap.",
    ],
    "monitoring": [
        "sentry.io",
        "bugsnag",
        "datadoghq.com",
        "newrelic",
        "rollbar",
        "logrocket",
    ],
    "maps": [
        "maps.googleapis.com",
        "mapbox.com",
        "leaflet",
        "openstreetmap",
    ],
}


def extract_url_from_line(line: str) -> Optional[str]:
    line = line.strip()
    if not line:
        return None

    # If it's an HTML <script> tag, try to pull src="..."
    if "<script" in line.lower():
        m = SCRIPT_SRC_RE.search(line)
        if m:
            return m.group(1).strip()

    # Otherwise, if it looks like a URL, just return it
    if line.startswith(("http://", "https://", "//")):
        return line

    # Bare hosts or paths without scheme are ignored for now
    return None


def normalize_url(url: str) -> Tuple[str, str, str]:
    # Handle protocol-relative URLs like //example.com/script.js
    if url.startswith("//"):
        url = "https:" + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.netloc or "").lower()
    path = parsed.path or "/"
    return scheme, host, path


def is_first_party(host: str, primary_domain: str) -> bool:
    if not host or not primary_domain:
        return False
    primary_domain = primary_domain.lower().lstrip(".")
    host = host.lower()
    return host == primary_domain or host.endswith("." + primary_domain)


def classify_script(host: str, path: str) -> Tuple[str, str, List[str]]:
    """
    Return (category, subcategory, notes)
    """
    host = host.lower()
    path = path.lower()
    combined = host + path

    for cat, patterns in CATEGORY_RULES.items():
        for pattern in patterns:
            if pattern.lower() in combined:
                return cat, pattern, []

    # Heuristics for generic but potentially risky cases
    notes: List[str] = []
    if "widget" in combined:
        notes.append("Widget-style script (embedded component)")
    if "tracker" in combined or "track" in combined:
        notes.append("Tracking-related identifier in URL")
    if "bundle" in combined or "vendor" in combined:
        notes.append("Large JS bundle – may include multiple libraries")

    # Default category
    return "generic", "", notes


def read_input_lines(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            yield line.rstrip("\n")


def process_scripts(
    input_path: str,
    primary_domain: str,
) -> List[ScriptEntry]:
    entries: List[ScriptEntry] = []

    for line in read_input_lines(input_path):
        raw = line.strip()
        if not raw or raw.startswith(("#", "//", "<!--")):
            continue

        url = extract_url_from_line(raw)
        if not url:
            continue

        scheme, host, path = normalize_url(url)
        category, subcategory, notes = classify_script(host, path)
        fp = is_first_party(host, primary_domain)

        if not host:
            notes.append("No host component detected")

        entry = ScriptEntry(
            raw=raw,
            url=url,
            scheme=scheme,
            host=host,
            path=path,
            category=category,
            subcategory=subcategory,
            first_party=fp,
            notes=notes,
        )
        entries.append(entry)

    return entries


def generate_markdown_summary(
    entries: List[ScriptEntry],
    primary_domain: str,
) -> str:
    total = len(entries)
    first_party = [e for e in entries if e.first_party]
    third_party = [e for e in entries if not e.first_party]

    cat_counts = Counter(e.category for e in entries)
    domain_counts = Counter(e.host for e in entries if e.host)

    lines: List[str] = []
    lines.append(f"# Red Specter ScriptMap Summary")
    lines.append("")
    lines.append(f"**Primary domain:** `{primary_domain}`")
    lines.append(f"**Total scripts detected:** {total}")
    lines.append(f"- First-party: {len(first_party)}")
    lines.append(f"- Third-party: {len(third_party)}")
    lines.append("")

    lines.append("## Category Breakdown")
    lines.append("")
    if not cat_counts:
        lines.append("_No scripts detected._")
    else:
        lines.append("| Category      | Count |")
        lines.append("|--------------|-------|")
        for cat, count in sorted(cat_counts.items(), key=lambda x: (-x[1], x[0])):
            lines.append(f"| {cat} | {count} |")
    lines.append("")

    lines.append("## Top Third-Party Domains")
    lines.append("")
    tp_domains = Counter(
        e.host for e in third_party if e.host
    )  # third party only
    if not tp_domains:
        lines.append("_No third-party script domains detected._")
    else:
        lines.append("| Domain | Count |")
        lines.append("|--------|-------|")
        for dom, count in sorted(tp_domains.items(), key=lambda x: (-x[1], x[0]))[:20]:
            lines.append(f"| `{dom}` | {count} |")
    lines.append("")

    lines.append("## Suggested Talking Points")
    lines.append("")
    lines.append("- Review all **third-party analytics and tracking scripts** for data minimisation and consent.")
    lines.append("- Consider **Subresource Integrity (SRI)** for CDN-hosted libraries where feasible.")
    lines.append("- Tighten your **Content-Security-Policy (CSP)** `script-src` to only allow the domains listed here.")
    lines.append("- Audit embedded **payment, social, and widget scripts** for unnecessary permissions and data access.")
    lines.append("- Maintain this script inventory as part of your **vendor and supply-chain security** documentation.")
    lines.append("")

    return "\n".join(lines)


def generate_markdown_table(entries: List[ScriptEntry]) -> str:
    lines: List[str] = []
    lines.append("# Script Inventory")
    lines.append("")
    if not entries:
        lines.append("_No script URLs found in input._")
        return "\n".join(lines)

    lines.append("| URL | Host | Category | First/Third Party | Notes |")
    lines.append("|-----|------|----------|-------------------|-------|")

    for e in entries:
        party = "First-party" if e.first_party else "Third-party"
        notes = "; ".join(e.notes) if e.notes else ""
        safe_url = e.url.replace("|", "\\|")
        safe_host = (e.host or "").replace("|", "\\|")
        safe_cat = e.category.replace("|", "\\|")
        safe_notes = notes.replace("|", "\\|")
        lines.append(f"| `{safe_url}` | `{safe_host}` | {safe_cat} | {party} | {safe_notes} |")

    return "\n".join(lines)


def write_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Red Specter ScriptMap - classify and map third-party JavaScript dependencies.",
        epilog=(
            "Example:\n"
            "  python3 redspecter_scriptmap.py scripts.txt --primary-domain example.com\n"
            "\n"
            "Input should be one script URL or <script> tag per line."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "input",
        help="Input file containing one script URL or <script> tag per line.",
    )
    p.add_argument(
        "--primary-domain",
        required=True,
        help="Primary application domain (e.g. example.com) used to distinguish first/third-party.",
    )
    p.add_argument(
        "-o",
        "--output-prefix",
        default="scriptmap",
        help="Prefix for output files (default: scriptmap).",
    )
    return p


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    entries = process_scripts(args.input, args.primary_domain)

    base = args.output_prefix.rstrip(".md")

    summary_md = generate_markdown_summary(entries, args.primary_domain)
    inventory_md = generate_markdown_table(entries)

    write_file(f"{base}_summary.md", summary_md)
    write_file(f"{base}_inventory.md", inventory_md)

    print("[Red Specter] ScriptMap complete.")
    print(f"  Scripts detected: {len(entries)}")
    print(f"  Summary report:   {base}_summary.md")
    print(f"  Inventory table:  {base}_inventory.md")


if __name__ == "__main__":
    main()
