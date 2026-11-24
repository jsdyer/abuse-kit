"""Exercise the built page at a project subpath in Chromium with mocked DNS, RDAP and RIPEstat."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
from urllib.parse import urlsplit, parse_qs
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]


def vcard(**fields):
    return ["vcard", [[k, {}, "text", v] for k, v in fields.items()]]


def respond(route):
    url = route.request.url
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    body, status = None, 200
    if parts.hostname == "cloudflare-dns.com":
        kind = query["type"][0]
        answers = {"A": [{"type": 1, "data": "104.16.1.1"}, {"type": 1, "data": "5.6.7.8"}], "AAAA": [], "NS": []}[kind]
        body = {"Status": 0, "Answer": answers}
    elif parts.hostname == "rdap.org" and parts.path.startswith("/domain/"):
        body = {"status": ["client transfer prohibited"],
                "events": [{"eventAction": "registration", "eventDate": "2026-11-20T00:00:00Z"}],
                "entities": [{"roles": ["registrar"], "vcardArray": vcard(fn="<img src=x onerror=alert(1)> Registrar"),
                              "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
                              "entities": [{"roles": ["abuse"], "vcardArray": vcard(email="abuse@registrar.example")}]}]}
    elif parts.hostname == "rdap.org" and parts.path.startswith("/ip/"):
        ip = parts.path.split("/")[-1]
        body = {"name": "NET", "entities": [{"roles": ["abuse"], "vcardArray": vcard(email=f"abuse@{ip.replace('.', '-')}.example")}]}
    elif parts.hostname == "stat.ripe.net" and "network-info" in parts.path:
        ip = query["resource"][0]
        asn = "13335" if ip.startswith("104.") or ip.startswith("1.") else "64500"
        body = {"data": {"asns": [asn], "prefix": f"{ip}/24"}}
    elif parts.hostname == "stat.ripe.net" and "as-overview" in parts.path:
        body = {"data": {"holder": "CLOUDFLARENET" if query["resource"][0] == "AS13335" else "SMALLHOST"}}
    else:
        status, body = 404, {}
    route.fulfill(status=status, content_type="application/json", body=json.dumps(body),
                  headers={"Access-Control-Allow-Origin": "*"})


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def main():
    screenshots = ROOT / "browser-checks"
    screenshots.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        shutil.copytree(ROOT / "dist", Path(temporary) / "abuse-kit")
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=temporary))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with sync_playwright() as p:
                executable = os.environ.get("CHROMIUM_EXECUTABLE")
                browser = p.chromium.launch(executable_path=executable) if executable else p.chromium.launch()
                page = browser.new_page(viewport={"width": 1280, "height": 1000})
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                for host in ("cloudflare-dns.com", "rdap.org", "stat.ripe.net"):
                    page.route(f"https://{host}/**", respond)
                page.goto(f"http://127.0.0.1:{server.server_port}/abuse-kit/")
                page.locator("#lookup-input").fill("https://login.phish.example/verify")
                page.locator("#lookup-form button").click()
                page.wait_for_selector("#lookup-result:not([hidden])")
                contacts = page.locator("#contacts").inner_text()
                assert contacts.index("CDN / proxy") < contacts.index("Registrar") < contacts.index("Network operator"), contacts
                assert "abuse@5-6-7-8.example" in contacts and "abuse@104-16-1-1.example" not in contacts
                assert page.locator("img").count() == 0
                assert page.locator("#addresses tbody tr").count() == 2
                page.locator("#draft-recipient").select_option(index=1)
                page.locator("#draft-brand").fill("Example Bank")
                page.locator("#draft-evidence").fill("urlscan: https://urlscan.io/result/x/")
                page.locator("#draft-reporter").fill("Jeffrey")
                body = page.locator("#draft-body").input_value()
                assert "impersonating Example Bank" in body and "IANA ID 9999" in body and "suspend the domain" in body, body
                assert page.locator("#draft-mail").get_attribute("href").startswith("mailto:abuse@registrar.example?")
                page.locator("#draft-recipient").select_option("")
                assert page.locator("#draft-mail").is_hidden()
                assert page.locator("#draft-body").input_value().startswith("Hello,")
                page.locator("#lookup-input").fill("::1")
                page.locator("#lookup-form button").click()
                page.wait_for_function("document.querySelector('#lookup-status').textContent.includes('Looked up ::1')")
                assert "not sent for lookup" in page.locator("#addresses").inner_text()
                page.locator("#bulk-input").fill("1.1.1.1 - - GET /\n5.6.7.8 POST\n1.1.1.1 again\n10.0.0.1 local")
                page.locator("#bulk-run").click()
                page.wait_for_selector("#bulk-csv:not([hidden])")
                assert page.locator("#bulk tbody tr").count() == 2
                assert "3 addresses in 2 networks; 1 skipped" in page.locator("#bulk-status").inner_text()
                page.screenshot(path=str(screenshots / "desktop.png"), full_page=True)
                page.set_viewport_size({"width": 390, "height": 844})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                page.screenshot(path=str(screenshots / "mobile.png"), full_page=True)
                assert not errors, errors
                browser.close()
            print("Browser checks passed: lookup, contact order, draft, bulk grouping, safe text and mobile layout")
        finally:
            server.shutdown()


if __name__ == "__main__":
    main()
