"""Find subdomains of each root in domains.txt, save them to data/, and log new finds."""
from concurrent.futures import ThreadPoolExecutor
import datetime, json, os, pathlib, re, socket, sys, time, urllib.request

ROOT = pathlib.Path(__file__).parent
DATA = ROOT / "data"
C99_KEY = os.environ.get("C99_API_KEY")  # optional: subdomainfinder.c99.nl API key
UA = {"User-Agent": "rl-subdomain-tracker"}


def get(url, timeout=45):
    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:
            print(f"  {url.split('?')[0]} failed ({e}), retry {attempt + 1}", file=sys.stderr)
            time.sleep(5 * (attempt + 1))
    return ""


def crtsh(d):
    try:
        return [n for row in json.loads(get(f"https://crt.sh/?q=%25.{d}&output=json", 90) or "[]")
                for n in row["name_value"].split("\n")]
    except ValueError:
        return []


def certspotter(d):
    try:
        return [n for row in json.loads(get(
            f"https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names") or "[]")
            for n in row.get("dns_names", [])]
    except ValueError:
        return []


def hackertarget(d):
    text = get(f"https://api.hackertarget.com/hostsearch/?q={d}")
    return [line.split(",")[0] for line in text.splitlines() if "," in line]


def c99(d):
    if not C99_KEY:
        return []
    try:
        data = json.loads(get(f"https://api.c99.nl/subdomainfinder?key={C99_KEY}&domain={d}&json") or "{}")
        return [s["subdomain"] for s in data.get("subdomains", [])]
    except (ValueError, TypeError):
        return []


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
    today = datetime.date.today().isoformat()
    new_finds = {}
    def scan(d):
        with ThreadPoolExecutor(4) as ex:
            found = clean(sum(ex.map(lambda f: f(d), (crtsh, certspotter, hackertarget, c99)), []), d)
        with ThreadPoolExecutor(32) as ex:
            ips = dict(zip(sorted(found), ex.map(resolves, sorted(found))))
        path = DATA / f"{d}.json"
        known = json.loads(path.read_text()) if path.exists() else {}
        first_run = not known
        for host in sorted(found):
            entry = known.setdefault(host, {"first_seen": today})
            entry.update(last_seen=today, ip=ips[host], live=bool(ips[host]))
            if entry["first_seen"] == today and not first_run:
                new_finds.setdefault(d, []).append(f"{host} ({ips[host] or 'no DNS'})")
        path.write_text(json.dumps(dict(sorted(known.items())), indent=1) + "\n")
        print(f"[{d}] {len(found)} found, {len(known)} total", flush=True)

    with ThreadPoolExecutor(8) as ex:
        list(ex.map(scan, filter(None, roots)))

    if new_finds:
        body = "".join(f"\n### {d}\n" + "".join(f"- {h}\n" for h in hs) for d, hs in new_finds.items())
        log = ROOT / "CHANGELOG.md"
        old = log.read_text() if log.exists() else "# New subdomains\n"
        head, _, rest = old.partition("\n")
        log.write_text(f"{head}\n\n## {today}\n{body}{rest}")
        (ROOT / "new.md").write_text(body)
    for p in DATA.glob("*.json"):
        if p.stem not in roots:
            p.unlink()
    write_index()


def write_index():
    lines = ["# Subdomain index", "", "| Root | Subdomains | Live |", "|---|---|---|"]
    for p in sorted(DATA.glob("*.json")):
        k = json.loads(p.read_text())
        lines.append(f"| [{p.stem}](data/{p.name}) | {len(k)} | {sum(v['live'] for v in k.values())} |")
    (ROOT / "INDEX.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
