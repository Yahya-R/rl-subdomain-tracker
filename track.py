"""Find subdomains of each root in domains.txt, save them to data/, and log new finds."""
from concurrent.futures import ThreadPoolExecutor
import datetime, json, os, pathlib, random, re, socket, sys, threading, time, urllib.error, urllib.parse, urllib.request

ROOT = pathlib.Path(__file__).parent
DATA = ROOT / "data"
STATUS = DATA / "_status.json"
BUDGET = int(os.environ.get("SCAN_MINUTES", "35")) * 60  # stop starting new domains after this
C99_KEY = os.environ.get("C99_API_KEY")  # optional: subdomainfinder.c99.nl API key
UA = {"User-Agent": "rl-subdomain-tracker (github.com/yahya-r/rl-subdomain-tracker)"}

# crt.sh and Cert Spotter rate-limit hard, so each gets one request at a time.
# Every source host gets one request at a time; crt.sh and Cert Spotter rate-limit hard,
# and the free passive-DNS services ask for the same courtesy.
LOCKS = {h: threading.Lock() for h in ("crt.sh", "api.certspotter.com", "otx.alienvault.com",
                                       "api.subdomain.center", "jldc.me", "web.archive.org", "rapiddns.io")}
DB_BROKEN = threading.Event()  # set if crt.sh's database rejects our query, so we stop trying it


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
def crtsh_db(d):
    """Query crt.sh's public Postgres replica, which stays up when its web frontend returns 502s."""
    if DB_BROKEN.is_set():
        return None
    try:
        import psycopg2
    except ImportError:
        return None
    sql = """SELECT DISTINCT cai.name_value FROM certificate_and_identities cai
             WHERE plainto_tsquery('certwatch', %(d)s) @@ identities(cai.certificate)
               AND (lower(cai.name_value) = %(d)s OR lower(cai.name_value) LIKE %(suffix)s)"""
    for attempt in range(3):
        try:
            with LOCKS["crt.sh"]:
                # crt.sh's connection pooler rejects the "options" startup parameter, so no server-side timeout.
                conn = psycopg2.connect(host="crt.sh", port=5432, user="guest", dbname="certwatch",
                                        connect_timeout=20)
                conn.autocommit = True  # the replica is read-only; crt.sh rejects open transactions
                try:
                    with conn.cursor() as cur:
                        cur.execute(sql, {"d": d, "suffix": "%." + d})
                        return [r[0] for r in cur.fetchall()]
                finally:
                    conn.close()
        except psycopg2.ProgrammingError as e:  # schema or query problem: retrying won't help
            print(f"  crt.sh database query rejected ({str(e).strip()[:200]}); using the website", file=sys.stderr)
            DB_BROKEN.set()
            return None
        except Exception as e:
            print(f"  crt.sh database failed ({str(e).strip()[:120]}), try {attempt + 1}/3", file=sys.stderr)
            if attempt < 2:
                time.sleep(15 * (attempt + 1))
    return None


def crtsh(d):
    names = crtsh_db(d)
    if names is not None:
        return names
    rows = as_json(get(f"https://crt.sh/?q=%25.{d}&output=json&deduplicate=Y", timeout=90, tries=3))
    return None if rows is None else [n for r in rows for n in r["name_value"].split("\n")]


def certspotter(d):
    # One try only: unauthenticated Cert Spotter answers 429 with multi-minute Retry-After
    # waits that stall the whole run, and crt.sh already covers the same CT logs.
    rows = as_json(get(f"https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names",
                       tries=1))
    return None if not isinstance(rows, list) else [n for r in rows for n in r.get("dns_names", [])]


def hackertarget(d):
    text = get(f"https://api.hackertarget.com/hostsearch/?q={d}", tries=1)
    return None if text is None else [l.split(",")[0] for l in text.splitlines() if "," in l]


def alienvault(d):
    data = as_json(get(f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns", tries=2))
    return None if not isinstance(data, dict) else [r.get("hostname", "") for r in data.get("passive_dns", [])]


def subdomain_center(d):
    data = as_json(get(f"https://api.subdomain.center/?domain={d}", tries=2, gap=5))
    return None if not isinstance(data, list) else [n for n in data if isinstance(n, str)]


def anubis(d):
    data = as_json(get(f"https://jldc.me/anubis/subdomains/{d}", tries=2))
    return None if not isinstance(data, list) else [n for n in data if isinstance(n, str)]


def wayback(d):
    """Hostnames from every URL the Internet Archive has captured under the domain."""
    text = get(f"https://web.archive.org/cdx/search/cdx?url=*.{d}&fl=original&collapse=urlkey&limit=50000",
               timeout=120, tries=1)
    if text is None:
        return None
    return [urllib.parse.urlsplit(l if "://" in l else "http://" + l).hostname or "" for l in text.splitlines()]


def rapiddns(d):
    html = get(f"https://rapiddns.io/subdomain/{d}?full=1", tries=1)
    return None if html is None else re.findall(r"[a-z0-9.-]+\." + re.escape(d), html.lower())


def c99(d):
    if not C99_KEY:
        return []
    data = as_json(get(f"https://api.c99.nl/subdomainfinder?key={C99_KEY}&domain={d}&json"))
    return None if not isinstance(data, dict) else [s["subdomain"] for s in data.get("subdomains", [])]


SOURCES = (crtsh, certspotter, hackertarget, alienvault, subdomain_center, anubis, wayback, rapiddns, c99)
# crt.sh returns every logged certificate for a domain, so a scan where it answered is complete.
# Cert Spotter reads the same CT logs but returns only its first page without an API key.
REQUIRED = {"crtsh"}


def write_atomic(path, data):
    """Write JSON via a temp file so a mid-run checkpoint commit never sees half a file."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1) + "\n")
    tmp.replace(path)


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
    for v in status.values():  # re-judge earlier scans against the current REQUIRED set
        if not v.get("complete") and not REQUIRED & set(v.get("failed_sources", [])):
            v["complete"] = True
    today = datetime.date.today().isoformat()
    new_finds = {}

    deadline = time.time() + BUDGET
    scanned = set()
    status_lock = threading.Lock()
    # Incomplete domains first, then least recently scanned, so runs that hit the time budget
    # finish the missing baselines before rotating through everything else.
    roots_by_age = sorted(roots, key=lambda d: (status.get(d, {}).get("complete", False),
                                                status.get(d, {}).get("last_scan", "")))

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
        write_atomic(path, dict(sorted(known.items())))
        complete = alert or not (REQUIRED & set(failed))
        status[d] = {"sources": {k: (None if v is None else len(clean(v, d))) for k, v in results.items()},
                     "complete": complete, "last_scan": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M"), "failed_sources": failed}
        with status_lock:
            write_atomic(STATUS, {k: status[k] for k in sorted(status) if k in roots})
        per = " ".join(f"{k}={'x' if v is None else len(clean(v, d))}" for k, v in results.items())
        print(f"[{d}] {len(found)} found, {len(known)} total | {per}", flush=True)

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
    write_atomic(STATUS, {d: status[d] for d in sorted(status) if d in roots})
    write_index(status)


def write_index(status):
    lines = ["# Subdomain index", "",
             "Baseline = crt.sh has returned every logged certificate for the domain, so new subdomains now raise alerts.", "",
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
