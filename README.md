# RL subdomain tracker

Every 4 hours, a GitHub Action finds the subdomains of each root domain in `domains.txt`.

- **Sources:** crt.sh and Cert Spotter (certificate transparency logs), HackerTarget (passive DNS), and subdomainfinder.c99.nl when the `C99_API_KEY` secret is set.
- **Output:**
  - `data/<domain>.json` lists each subdomain with its first-seen date, last-seen date, IP and whether it's live.
  - `INDEX.md` is the summary table.
  - `CHANGELOG.md` records the new finds.
- **Alerts:** a GitHub issue is opened whenever new subdomains appear. The first run for a domain sets the baseline and sends no alert.

To add a company, put its root domain on a new line in `domains.txt`. To run it now, use Actions → Track subdomains → Run workflow.

Each run scans for up to 35 minutes, starting with the domains scanned longest ago, and saves its progress. crt.sh and Cert Spotter rate-limit heavily, so it can take a few runs to cover every domain. A domain only raises alerts once crt.sh (queried through its database, falling back to its website) has answered for it (see the Baseline column in `INDEX.md`).
