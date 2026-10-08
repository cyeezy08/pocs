# Proof of Concept Collection

Consolidated repository of proof-of-concept exploits and security research tools.

## Structure

### PoCs

| Directory | Target | CVE |
|-----------|--------|-----|
| `pocs/cve-2026-52824-kimai/` | Kimai time-tracking | CVE-2026-52824 |
| `pocs/cve-2026-32475-elementor/` | Elementor Pro | CVE-2026-32475 |
| `pocs/cve-2024-4068-braces-dos/` | braces npm package | CVE-2024-4068 |
| `pocs/cwe-59-decompress/` | decompress npm package | CWE-59 |
| `pocs/tianwen-erp-upload/` | Tianwen Property ERP | CWE-434 |
| `pocs/whatsapp-bug-bounty/` | WhatsApp | Multiple |

### Tools

| Directory | Description |
|-----------|-------------|
| `tools/shodan/` | Shodan search and census tools |
| `tools/firmware-re/` | Firmware reverse engineering scripts |
| `tools/surfacediff/` | Attack surface diffing |
| `tools/leviathan-core/` | Vulnerability risk scoring kernel |
| `tools/leviathan-triage/` | KEV feed triage |
| `tools/huginn-lvx/` | GitHub-to-X auto-pilot |
| `tools/leviathan-intel-bot/` | Threat intel Telegram bot |
| `tools/leviathan-intel/` | Defensive attack-surface management |

## Usage

Each directory contains standalone tools and PoCs. Refer to individual README files within each directory for usage instructions.

## Disclaimer

These tools and PoCs are for authorized security testing and research purposes only. Use only against systems you own or have explicit permission to test.
