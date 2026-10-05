# RL subdomain tracker

Every day at 09:17 UTC, a GitHub Action finds the subdomains of each root domain in `domains.txt`.

- **Sources:** crt.sh and Cert Spotter (certificate transparency logs), HackerTarget (passive DNS), and subdomainfinder.c99.nl when the `C99_API_KEY` secret is set.
- **Output:**
  - `data/<domain>.json` lists each subdomain with its first-seen date, last-seen date, IP and whether it's live.
  - `INDEX.md` is the summary table.
  - `CHANGELOG.md` records the new finds.
- **Alerts:** a GitHub issue is opened whenever new subdomains appear. The first run for a domain sets the baseline and sends no alert.

To add a company, put its root domain on a new line in `domains.txt`. To run it now, use Actions → Track subdomains → Run workflow.
