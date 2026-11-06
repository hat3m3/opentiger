# OpenTiger workflows

OpenTiger 0.1.0 connects target workspaces, collection tools, saved run history, and portable reports. Use the menu or the corresponding command-line workflow.

## One target, several tools

```powershell
opentiger workspace create mysite https://example.com
opentiger overview --html overview.html --output overview.json
opentiger dns
opentiger workspace history mysite
opentiger workspace off
```

Creating a workspace also selects it. A network tool with no explicit target uses the active workspace. `--workspace mysite` selects a workspace for just that run and stores a run record. Supplying an explicit target without `--workspace` runs independently. File paths, usernames, phone numbers, and search text still need explicit values. IP-only tools cannot infer an IP from a workspace hostname; supply an explicit IP or use an IP-target workspace.

Workspaces, favorites, recent targets, and report histories live under `~/.opentiger`. `OPENTIGER_HOME` overrides this location. Workspace names accept letters, digits, underscores, and hyphens. Run JSON files have unique names and are never updated by later runs. These files retain the supplied target and returned evidence; they are local files, not encrypted storage or a cloud sync service.

## Website Overview

The collector performs six stages: DNS addresses, HTTP headers, certificate details where HTTPS applies, page/form observations, links, and robots/sitemap files. Plain HTTP skips TLS rather than inventing a certificate failure. Verification stays enabled for HTTPS. Missing HSTS on a plain-HTTP response is not separately flagged as a missing HTTPS policy.

The report separates:

- **Observations:** returned addresses, HTTP status, verified certificate facts, and link counts.
- **Potential issues:** evidence-backed prompts such as HTTP form actions or missing applicable headers. These are not exploit confirmations.
- **Lookup errors:** collection failures, without treating them as findings.
- **Raw checks:** source data, status, and timing for each stage.

Website Overview makes multiple requests to collect its evidence. It is not a complete security audit. Per-operation timeouts do not impose a whole-run deadline.

## Readable, portable reports

```powershell
opentiger overview https://example.com --html first.html --output first.json
opentiger overview https://example.com --output second.json
opentiger compare first.json second.json --html changes.html --json
```

HTML reports are standalone documents with no scripts, external fonts, or remote assets. Raw text and URLs are escaped; only HTTP(S) links become clickable. Existing output files are preserved. Printing uses a light layout. Terminal exports offer J for JSON, H for HTML, B for both, or Enter to skip.

Comparison accepts reports from the same tool. It compares data fields, ignoring collection times, durations, latency values, DNS TTLs, HTTP Date values, certificate countdowns, and list order. Certificate validity dates and addresses remain meaningful changes. If targets differ, the report says so. A changed record is not automatically an incident.

## Progress and cancellation

The terminal shows the active collection step, completed count, and elapsed time. JSON output has no spinner or progress messages. Ctrl+C during Website Overview, Username Check, and Broken Links returns previously collected data with `status: cancelled`; workspace history saves that partial report. Other tools retain their ordinary interrupt behavior. An in-flight operation may still be limited by OS/network timeout behavior.

## Faster navigation

- Type an exact command such as `dns` to open it, or part of a name to search the menu.
- **W:** create/select/list workspaces, or turn the current workspace off.
- **R:** choose a recent target and a tool; Enter reuses the target at its prompt.
- **F:** run a favorite command. `+dns` adds it; `-dns` removes it.
- **D:** check Python, dependencies, localhost resolution, certificate trust configuration, and writable report storage.

The CLI equivalents are `workspace`, `recent`, `favorite add/remove/list`, and `diagnostics`. Public connectivity is tested only when you add `diagnostics --online`, which requests verified HTTPS from example.com.

## Username Check

`opentiger username example --json` makes at most two public API requests, using [GitHub's user endpoint](https://docs.github.com/en/rest/users/users#get-a-user) and [GitLab's Users API](https://docs.gitlab.com/api/users/). Responses distinguish exact public usernames, no matching public user, blocked/rate-limited requests, and unknown responses. Unexpected payloads, challenges, and failures are not converted into found profiles. A 404 can also hide a private or access-restricted account; it is not proof that an identity never existed. Matching usernames do not establish the same person.

Provider response handling is tested with fixtures, including blocked and malformed responses. Availability and rate limits depend on the provider.

## Broken Links and certificate countdowns

```powershell
opentiger broken-links https://example.com --max-links 20 --html links.html
opentiger tls example.com --json
```

Broken Links reads one starting page, then checks at most the selected limit (1–50) using HEAD and a GET fallback for 405/501. The default scope excludes other origins, including redirects. `--include-external` explicitly expands that scope. Only 404/410 are labeled broken; access restrictions, rate limits, server failures, and unknown responses remain separate. Response bodies of checked links are not read.

Verified certificate reports include UTC expiry, days remaining, and a renewal-window label. No certificate verification bypass was added.

## Menu numbering

Tool numbers follow their displayed category from top to bottom:

| Category | Numbers |
| --- | --- |
| Network | 01–08 |
| Websites | 09–16 |
| OSINT | 17–26 |
| Files & Utilities | 27–31 |

CLI commands, favorites, and workspace history use command names, so menu numbering does not change saved preferences or reports.
