# Tool reference

All 31 tools use native OpenTiger handlers and the same JSON export format. Menu numbers run consecutively down each category.

[Back to README](../README.md)

## Network

| ID | Tool | Command |
| --- | --- | --- |
| `01` | Website Overview | `opentiger overview <target>` |
| `02` | Port Scanner | `opentiger port-scan <target>` |
| `03` | Connection Check | `opentiger connection <target>` |
| `04` | Host Discovery | `opentiger hosts <target>` |
| `05` | DNS Lookup | `opentiger dns <target>` |
| `06` | Quick Port Check | `opentiger ports <target>` |
| `07` | DNS Records | `opentiger dns-records <target>` |
| `08` | Reverse IP Lookup | `opentiger reverse-ip <target>` |

## Websites

| ID | Tool | Command |
| --- | --- | --- |
| `09` | Website Check | `opentiger website-check <target>` |
| `10` | Page Crawler | `opentiger crawl <target>` |
| `11` | Page Saver | `opentiger save-page <target>` |
| `12` | Website Headers | `opentiger http <target>` |
| `13` | SSL Certificate | `opentiger tls <target>` |
| `14` | Website Links | `opentiger website-links <target>` |
| `15` | Robots & Sitemap | `opentiger robots <target>` |
| `16` | Broken Links | `opentiger broken-links <target>` |

## OSINT

| ID | Tool | Command |
| --- | --- | --- |
| `17` | Search Builder | `opentiger search <target>` |
| `18` | Wallet Links | `opentiger wallet <target>` |
| `19` | Username Check | `opentiger username <target>` |
| `20` | Email Search | `opentiger email-search <target>` |
| `21` | Email Info | `opentiger email-info <target>` |
| `22` | IP Info | `opentiger ip-info <target>` |
| `23` | Phone Lookup | `opentiger phone <target>` |
| `24` | Profile Link | `opentiger profile <target>` |
| `25` | Domain Lookup | `opentiger rdap <target>` |
| `26` | Email Domain Check | `opentiger email-domain <target>` |

## Files & Utilities

| ID | Tool | Command |
| --- | --- | --- |
| `27` | File Metadata | `opentiger metadata <target>` |
| `28` | Image Metadata Cleaner | `opentiger clean-image <target>` |
| `29` | File Hash | `opentiger file <target>` |
| `30` | File Text Finder | `opentiger file-text <target>` |
| `31` | URL Decoder | `opentiger url-decode <target>` |

## Workflow scope

| Tool | What it does |
| --- | --- |
| Website Overview | Six-stage collection: DNS, HTTP headers, verified TLS where applicable, page checks, links, and discovery files. Findings, review prompts, and errors are separate. |
| Website Check | HTTP transport, page title, and form actions; no submissions or exploit probes. |
| Port Scanner | Bounded TCP connection checks; choose ports with --ports. |
| Page Crawler | Same-origin HTML crawl; --pages 1-30, default 10. No JavaScript or robots enforcement. |
| Connection Check | Three TCP connections to the supplied host/port; no ICMP. |
| Host Discovery | TCP checks on ports 22, 80, 443 across at most 64 addresses. |
| Search Builder | Offline Google/Bing/DuckDuckGo query links. |
| Wallet Links | Offline Bitcoin/EVM explorer links with format hints; no balances or checksum verification. |
| Username Check | Public GitHub/GitLab API checks; exact usernames only, with blocked and unknown responses separate. No cross-site identity claim. |
| Email Search | Offline exact-email search links; no mailbox probing. |
| Email Info | Email syntax and domain MX/SPF/DMARC data; no mailbox existence claim. |
| IP Info | IP classification, PTR, and public-address RDAP registration when available. |
| Phone Lookup | Offline phone-number format, region, and numbering-plan metadata; no live location or owner. |
| Profile Link | An Instagram profile link; existence and private content are not checked. |
| File Metadata | File size, SHA-256, modification time, and supported image EXIF/text metadata. |
| Image Metadata Cleaner | Writes a pixel-only PNG/JPEG copy; preserves original, recompresses JPEG. |
| Page Saver | Saves one HTML response into reports/pages; does not fetch assets or open the file. |

## Inputs and exports

Replace `<target>` with the requested domain, URL, IP, subnet, email, username, phone number, wallet address, file path, or search text. Phone numbers require a +country-code prefix. Commands receiving spaces should be quoted.

Every tool supports `--json`, `--output <new-file.json>`, `--html <new-file.html>`, and `--timeout <seconds>`. Port Scanner and Quick Port Check accept `--ports 22,80,443`; Page Crawler accepts `--pages 10`. `--output` creates a new file and refuses to overwrite. The timeout is per operation, not a whole-run deadline.

External links and registration records are not identity attribution. Local image cleaning cannot hide visual content. Use the tool result notes to understand scope and partial failures.

## Broken Links

`opentiger broken-links https://example.com --max-links 20 --html links.html`

The default scope is the starting page's origin. At most 50 selected links are checked, with HEAD and a GET fallback for 405/501. Only 404/410 are labeled broken; restricted, rate-limited, server-error, and unknown responses remain distinct. `--include-external` explicitly enables external links and redirects. This is not a recursive link audit.
