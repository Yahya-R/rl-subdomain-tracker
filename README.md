# RL subdomain tracker

Every 4 hours, a GitHub Action finds the subdomains of each root domain in `domains.txt`.

- **Sources:** crt.sh (database, falling back to its website) and Cert Spotter for certificate transparency logs; HackerTarget and subdomain.center for passive DNS; the Internet Archive's Wayback Machine and RapidDNS for hostnames seen on the web; and subdomainfinder.c99.nl when the `C99_API_KEY` secret is set.
- **Output:**
  - `data/<domain>.json` lists each subdomain with its first-seen date, last-seen date, IP and whether it's live.
  - `INDEX.md` is the summary table.
  - `CHANGELOG.md` records the new finds.
- **Alerts:** a GitHub issue is opened whenever new subdomains appear. The first run for a domain sets the baseline and sends no alert.

To add a company, put its root domain on a new line in `domains.txt`. To run it now, use Actions → Track subdomains → Run workflow.

Each run scans for up to 35 minutes, starting with the domains scanned longest ago, and saves its progress. crt.sh and Cert Spotter rate-limit heavily, so it can take a few runs to cover every domain. A domain only raises alerts once crt.sh (queried through its database, falling back to its website) has answered for it (see the Baseline column in `INDEX.md`).

## Catalogs and samples

`catalogs.py` (run weekly by the "Find catalogs and samples" workflow, or on demand from the Actions tab) visits every live subdomain's public homepage and each company's sitemap, and lists links that look like catalogs, samples, datasets, data cards, brochures or downloadable data files, including ones hosted on Hugging Face, Google Drive and similar. The summary is in `CATALOGS.md`, with full detail in `catalogs/<domain>.json`. It only reads public pages, honours robots.txt, and records links rather than downloading files.
