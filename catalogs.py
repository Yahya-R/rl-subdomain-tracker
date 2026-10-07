"""Visit every live subdomain's public homepage, plus each company's sitemap, and record links
that look like catalogs, samples, datasets or downloadable data. Public pages only: no logins,
robots.txt is honoured, and files are recorded as links, never downloaded."""
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
import gzip, json, pathlib, re, sys, threading, urllib.parse, urllib.request, urllib.robotparser

ROOT = pathlib.Path(__file__).parent
DATA, OUT = ROOT / "data", ROOT / "catalogs"
UA = "rl-subdomain-tracker catalog finder (github.com/yahya-r/rl-subdomain-tracker)"
MAX_BYTES = 2_000_000

# What counts as a catalog or sample link, matched against the URL and the link text.
KEYWORDS = re.compile(r"catalog|catalogue|sample|dataset|data[-_ ]?card|datasheet|data[-_ ]?sheet|brochure|"
                      r"one[-_ ]?pager|benchmark|leaderboard|eval|showcase|demo[-_ ]?data|example[-_ ]?data|"
                      r"download|whitepaper|white[-_ ]?paper|case[-_ ]?stud|pricing|rl[-_ ]?env|environment", re.I)
FILES = re.compile(r"\.(pdf|csv|tsv|jsonl?|parquet|zip|tar|gz|xlsx?|pptx?|docx?)(\?|#|$)", re.I)
HOSTED = re.compile(r"huggingface\.co/(datasets|spaces)/|kaggle\.com/datasets|docs\.google\.com|drive\.google\.com|"
                    r"notion\.site|github\.com/[^/]+/[^/]+|arxiv\.org/abs|airtable\.com/(app|shr)|"
                    r"dropbox\.com/s|\.s3[.-][a-z0-9-]*\.?amazonaws\.com|storage\.googleapis\.com", re.I)


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.title, self._href, self._text, self._in_title = [], "", None, [], False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"], []
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append((self._href, " ".join("".join(self._text).split())[:120]))
            self._href = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)
        if self._in_title:
            self.title += data


def fetch(url, timeout=15):
    """Return (final_url, text) or (None, None)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xml;q=0.9,*/*;q=0.5"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(MAX_BYTES)
            if r.headers.get("Content-Encoding") == "gzip" or url.endswith(".gz"):
                body = gzip.decompress(body)
            return r.geturl(), body.decode("utf-8", "replace")
    except Exception:
        return None, None


ROBOTS, ROBOTS_LOCK = {}, threading.Lock()


def allowed(url):
    host = urllib.parse.urlsplit(url).netloc
    with ROBOTS_LOCK:
        rp = ROBOTS.get(host)
    if rp is None:
        rp = urllib.robotparser.RobotFileParser()
        _, text = fetch(f"https://{host}/robots.txt", timeout=8)
        rp.parse((text or "").splitlines())
        with ROBOTS_LOCK:
            ROBOTS[host] = rp
    return rp.can_fetch(UA, url)


def interesting(url, text=""):
    if FILES.search(url):
        return "file"
    if HOSTED.search(url):
        return "hosted"
    if KEYWORDS.search(url) or KEYWORDS.search(text):
        return "page"
    return None


def visit(host):
    """Homepage of one live subdomain: its title and every interesting link on it."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        if not allowed(url):
            return {"host": host, "status": "robots.txt disallows"}
        final, html = fetch(url)
        if html is not None:
            break
    else:
        return {"host": host, "status": "no response"}
    p = Links()
    try:
        p.feed(html)
    except Exception:
        pass
    found = {}
    for href, text in p.links:
        absolute = urllib.parse.urljoin(final, href.strip())
        if not absolute.startswith("http"):
            continue
        kind = interesting(absolute, text)
        if kind:
            found.setdefault(absolute.split("#")[0], {"kind": kind, "text": text})
    return {"host": host, "status": "ok", "url": final, "title": " ".join(p.title.split())[:150],
            "links": [{"url": u, **v} for u, v in sorted(found.items())]}


def sitemap_urls(domain, limit=5000):
    """Every URL in the company's sitemaps (following sitemap indexes), from robots.txt or /sitemap.xml."""
    _, robots = fetch(f"https://{domain}/robots.txt", timeout=8)
    queue = re.findall(r"(?im)^sitemap:\s*(\S+)", robots or "") or [f"https://{domain}/sitemap.xml",
                                                                     f"https://www.{domain}/sitemap.xml"]
    seen, urls = set(), []
    while queue and len(seen) < 50 and len(urls) < limit:
        sm = queue.pop(0)
        if sm in seen:
            continue
        seen.add(sm)
        _, xml = fetch(sm)
        for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml or ""):
            (queue if re.search(r"sitemap[^/]*\.xml", loc) else urls).append(loc.replace("&amp;", "&"))
    return urls[:limit]


def company(domain):
    hosts = json.loads((DATA / f"{domain}.json").read_text())
    live = sorted(h for h, v in hosts.items() if v.get("live"))
    with ThreadPoolExecutor(8) as ex:  # at most 8 requests at a time to any one company
        pages = list(ex.map(visit, live))
    sitemap = [{"url": u, "kind": k} for u in sitemap_urls(domain) if (k := interesting(u))]
    result = {"domain": domain, "live_hosts": len(live), "pages": pages, "sitemap_hits": sitemap}
    (OUT / f"{domain}.json").write_text(json.dumps(result, indent=1) + "\n")
    n = sum(len(p.get("links", [])) for p in pages) + len(sitemap)
    print(f"[{domain}] {len(live)} live hosts, {n} catalog/sample links", flush=True)
    return result


def summary(results):
    lines = ["# Catalogs and samples", "",
             "Links that look like catalogs, samples, datasets or data downloads, found on each live subdomain's",
             "public homepage and in each company's sitemap. Generated by `catalogs.py`; full detail per company",
             "is in `catalogs/<domain>.json`.", ""]
    for r in sorted(results, key=lambda r: r["domain"]):
        hits = {}
        for p in r["pages"]:
            for l in p.get("links", []):
                hits.setdefault(l["url"], (l["kind"], l["text"] or p.get("title", "")))
        for s in r["sitemap_hits"]:
            hits.setdefault(s["url"], (s["kind"], "from sitemap"))
        lines.append(f"## {r['domain']} ({len(hits)} links from {r['live_hosts']} live hosts)\n")
        order = {"file": 0, "hosted": 1, "page": 2}
        for url, (kind, text) in sorted(hits.items(), key=lambda kv: (order[kv[1][0]], kv[0]))[:150]:
            lines.append(f"- `{kind}` [{text or url}]({url})")
        if len(hits) > 150:
            lines.append(f"- …and {len(hits) - 150} more in `catalogs/{r['domain']}.json`")
        lines.append("")
    (ROOT / "CATALOGS.md").write_text("\n".join(lines))


def main():
    OUT.mkdir(exist_ok=True)
    roots = [l.split("#")[0].strip().lower() for l in (ROOT / "domains.txt").read_text().splitlines()]
    only = set(sys.argv[1:])
    roots = [r for r in roots if r and (not only or r in only)]
    with ThreadPoolExecutor(6) as ex:
        results = list(ex.map(company, roots))
    if not only:
        summary(results)


if __name__ == "__main__":
    main()
