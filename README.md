# Abuse Kit

Find who to report a phishing site, scam domain or abusive IP address to, and
draft the report. Runs entirely in the browser with keyless public sources.
Published at `coolcode.ca/abuse-kit/`.

## Using the tool

<!-- coolcode:guide -->
Enter a domain, URL or IP address. The tool lists who to contact in the order most likely to get a fast result: a CDN such as Cloudflare first (it sits in front of the real host), then the registrar (it can suspend the domain everywhere), then hosting companies and each network's registry abuse contact. Pick a recipient to fill in a ready-to-send report with the registrar's IANA ID, IP addresses, networks and a UTC timestamp. The site itself is never contacted.
<!-- /coolcode:guide -->

**Bulk IP → network** takes pasted log lines or a list of addresses, extracts
every IPv4 and IPv6 address, looks them up and groups them by network with each
network's abuse contact. Download the result as CSV. Private and reserved
addresses are listed in the CSV but not looked up.

### Sources

| What | Source |
| --- | --- |
| DNS (A, AAAA) | Cloudflare DNS-over-HTTPS, `cloudflare-dns.com` |
| Domain registration, registrar, registrar abuse contact | RDAP via `rdap.org`, which redirects to the registry |
| ASN and announced prefix | RIPEstat `network-info` |
| Network name | RIPEstat `as-overview` |
| Network abuse contact | RDAP via `rdap.org`, which redirects to ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC |
| CDN and cloud report pages | `web/config.json` |

No keys are needed. Keyed extras (urlscan.io scans, AbuseIPDB reputation) need a
server-side key and will come with a future Cloudflare Worker.

## Expand or customize

Everything tunable is in `web/config.json`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `max_addresses_per_target` | `4` | How many of a domain's IP addresses to look up |
| `bulk_limit` | `500` | Most addresses looked up in one bulk run |
| `bulk_concurrency` | `4` | Parallel lookups in bulk mode (keep low to be polite to RIPEstat) |
| `ripestat_sourceapp` | `coolcode-abuse-kit` | Identifies the tool to RIPEstat |
| `multi_label_suffixes` | `co.uk`, `com.au`, … | Zones where domains are registered one level deeper |
| `providers` | Cloudflare, AWS, Google, … | Networks with their own report page, keyed by ASN |

To add a provider, add an entry keyed by its ASN (digits only):

```json
"399629": {"name": "Example Host", "kind": "cloud", "report": "https://example.com/abuse"}
```

`kind` is `cdn` (listed first, and its own network abuse contact is skipped
because it only forwards traffic) or `cloud` (listed alongside the network
contact). `report` is an `https://` page or a `mailto:` address; `note` is an
optional explanation shown under the contact.

Changes to `web/config.json` need only a normal commit to `main`;
**Browser tool · Check and publish** rebuilds and redeploys the page. There is no
scheduled data refresh: every lookup is live.

## Development

```sh
node --test tests/*.test.mjs
python3 -m unittest discover -s tests -v
python3 scripts/build.py
python3 -m http.server 8000 --directory dist
```

`tests/browser_smoke.py` mocks every external lookup.

## Files

| Path | Purpose |
| --- | --- |
| `web/config.json` | Limits and provider report pages |
| `web/model.mjs` | Parsing, contact ordering, report drafting, CSV |
| `web/app.mjs` | Lookups and DOM |
| `tool.json` | Catalogue record for coolcode.ca |
