"""Find subdomains of each root in domains.txt, save them to data/, and log new finds."""
from concurrent.futures import ThreadPoolExecutor
import datetime, json, os, pathlib, random, re, socket, sys, threading, time, urllib.error, urllib.request

ROOT = pathlib.Path(__file__).parent
DATA = ROOT / "data"
STATUS = DATA / "_status.json"
BUDGET = int(os.environ.get("SCAN_MINUTES", "35")) * 60  # stop starting new domains after this
C99_KEY = os.environ.get("C99_API_KEY")  # optional: subdomainfinder.c99.nl API key
UA = {"User-Agent": "rl-subdomain-tracker (github.com/yahya-r/rl-subdomain-tracker)"}

# crt.sh and Cert Spotter rate-limit hard, so each gets one request at a time.
LOCKS = {"crt.sh": threading.Lock(), "api.certspotter.com": threading.Lock()}


def get(url, timeout=60, tries=4, gap=2):
    """Return the response body, or None if every attempt failed."""
    lock = LOCKS.get(url.split("/")[2])
    for attempt in range(tries):
        try:
            with lock or threading.Lock():
                req = urllib.request.Request(url, headers=UA)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read().decode("utf-8", "replace")
                time.sleep(gap)  # stay polite while holding the lock
            return body
        except Exception as e:
            wait = 20 * (attempt + 1) + random.uniform(0, 5)
            if isinstance(e, urllib.error.HTTPError) and e.headers.get("Retry-After", "").isdigit():
                wait = max(wait, int(e.headers["Retry-After"]))
            print(f"  {url.split('?')[0]} failed ({e}), try {attempt + 1}/{tries}", file=sys.stderr)
            if attempt + 1 < tries:
                time.sleep(wait)
    return None


def as_json(text):
    try:
        return json.loads(text) if text is not None else None
    except ValueError:
        return None


# Each source returns a list of names, or None when it could not be reached.
def crtsh(d):
    rows = as_json(get(f"https://crt.sh/?q=%25.{d}&output=json", timeout=60, tries=3))
    return None if rows is None else [n for r in rows for n in r["name_value"].split("\n")]


def certspotter(d):
    rows = as_json(get(f"https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names"))
    return None if not isinstance(rows, list) else [n for r in rows for n in r.get("dns_names", [])]


def hackertarget(d):
    text = get(f"https://api.hackertarget.com/hostsearch/?q={d}", tries=1)
    return None if text is None else [l.split(",")[0] for l in text.splitlines() if "," in l]


def c99(d):
    if not C99_KEY:
        return []
    data = as_json(get(f"https://api.c99.nl/subdomainfinder?key={C99_KEY}&domain={d}&json"))
    return None if not isinstance(data, dict) else [s["subdomain"] for s in data.get("subdomains", [])]


SOURCES = (crtsh, certspotter, hackertarget, c99)
REQUIRED = {"crtsh", "certspotter"}  # a scan only counts as complete if these answered


def clean(names, d):
    out = set()
    for n in names:
        n = n.strip().lower().lstrip("*.").rstrip(".")
        if (n == d or n.endswith("." + d)) and re.fullmatch(r"[a-z0-9.-]+", n):
            out.add(n)
    return out


def resolves(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def main():
    DATA.mkdir(exist_ok=True)
    socket.setdefaulttimeout(5)
    roots = [l.split("#")[0].strip().lower() for l in (ROOT / "domains.txt").read_text().splitlines()]
    roots = [r for r in roots if r]
    status = json.loads(STATUS.read_text()) if STATUS.exists() else {}
    today = datetime.date.today().isoformat()
    new_finds = {}

    deadline = time.time() + BUDGET
    scanned = set()
    # Least recently scanned first, so runs that hit the time budget rotate through every domain.
    roots_by_age = sorted(roots, key=lambda d: status.get(d, {}).get("last_scan", ""))

    def scan(d):
        if time.time() > deadline:
            return
        scanned.add(d)
        with ThreadPoolExecutor(len(SOURCES)) as ex:
            results = dict(zip((f.__name__ for f in SOURCES), ex.map(lambda f: f(d), SOURCES)))
        failed = sorted(k for k, v in results.items() if v is None)
        found = clean([n for v in results.values() if v for n in v], d)
        with ThreadPoolExecutor(32) as ex:
            ips = dict(zip(sorted(found), ex.map(resolves, sorted(found))))
        path = DATA / f"{d}.json"
        known = json.loads(path.read_text()) if path.exists() else {}
        # Only alert once this domain has had one complete scan as a baseline.
        alert = status.get(d, {}).get("complete", False)
        for host in sorted(found):
            is_new = host not in known
            entry = known.setdefault(host, {"first_seen": today})
            entry.update(last_seen=today, ip=ips[host], live=bool(ips[host]))
            if is_new and alert:
                new_finds.setdefault(d, []).append(f"{host} ({ips[host] or 'no DNS'})")
        path.write_text(json.dumps(dict(sorted(known.items())), indent=1) + "\n")
        complete = alert or not (REQUIRED & set(failed))
        status[d] = {"complete": complete, "last_scan": datetime.datetime.utcnow().isoformat(timespec="minutes"), "failed_sources": failed}
        print(f"[{d}] {len(found)} found, {len(known)} total, failed: {failed or 'none'}", flush=True)

    with ThreadPoolExecutor(4) as ex:
        list(ex.map(scan, roots_by_age))
    print(f"{len(scanned)} scanned, {len(roots) - len(scanned)} left for the next run")

    if new_finds:
        body = "".join(f"\n### {d}\n" + "".join(f"- {h}\n" for h in hs) for d, hs in sorted(new_finds.items()))
        log = ROOT / "CHANGELOG.md"
        old = log.read_text() if log.exists() else "# New subdomains\n"
        head, _, rest = old.partition("\n")
        log.write_text(f"{head}\n\n## {today}\n{body}{rest}")
        (ROOT / "new.md").write_text(body)
    for p in DATA.glob("*.json"):
        if p != STATUS and p.stem not in roots:
            p.unlink()
    STATUS.write_text(json.dumps({d: status[d] for d in sorted(status) if d in roots}, indent=1) + "\n")
    write_index(status)


def write_index(status):
    lines = ["# Subdomain index", "",
             "Baseline = a full scan has succeeded, so new subdomains now raise alerts.", "",
             "| Root | Subdomains | Live | Baseline | Failed sources (last run) |", "|---|---|---|---|---|"]
    for p in sorted(DATA.glob("*.json")):
        if p == STATUS:
            continue
        k = json.loads(p.read_text())
        s = status.get(p.stem, {})
        lines.append(f"| [{p.stem}](data/{p.name}) | {len(k)} | {sum(v['live'] for v in k.values())} | "
                     f"{'yes' if s.get('complete') else 'not yet'} | {', '.join(s.get('failed_sources', [])) or '-'} |")
    (ROOT / "INDEX.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
