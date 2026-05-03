from typing import Dict, List, Optional
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


def _is_same_host(base_url: str, target_url: str) -> bool:
    try:
        return urlparse(base_url).netloc == urlparse(target_url).netloc
    except Exception:
        return False


def crawl_spa(
    url: str,
    timeout: int = 15000,
    headless: bool = True,
    ignore_https_errors: bool = True,
    block_images: bool = False,
    extra_wait_ms: int = 2000,
    extra_headers: Optional[Dict[str, str]] = None,
    initial_cookies: Optional[List[Dict]] = None,
) -> Dict:
    """
    Render halaman (SPA/MPA) dengan Playwright.
    Return: html, api_calls, cookies, title, ok, error
    """
    api_calls: List[Dict] = []
    cookies_map: Dict[str, str] = {}
    html = ""
    title = ""
    error_msg = None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=headless,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )

            context = browser.new_context(
                ignore_https_errors=ignore_https_errors,
                extra_http_headers=extra_headers or {},
            )

            # Inject cookies sebelum navigasi (misal: session auth)
            if initial_cookies:
                context.add_cookies(initial_cookies)

            page = context.new_page()

            # Block resource berat agar lebih cepat
            if block_images:
                def route_handler(route):
                    if route.request.resource_type in ("image", "media", "font"):
                        route.abort()
                    else:
                        route.continue_()
                page.route("**/*", route_handler)

            # Capture request + response API calls
            def on_request(req):
                if req.resource_type in ("fetch", "xhr") and _is_same_host(url, req.url):
                    api_calls.append({
                        "url": req.url,
                        "method": req.method,
                        "headers": dict(req.headers),
                        "post_data": req.post_data or None,
                    })

            def on_response(res):
                if res.request.resource_type in ("fetch", "xhr") and _is_same_host(url, res.url):
                    # Update entry terakhir dengan info response
                    for entry in reversed(api_calls):
                        if entry["url"] == res.url:
                            entry["status"] = res.status
                            entry["response_headers"] = dict(res.headers)
                            break

            page.on("request", on_request)
            page.on("response", on_response)

            # Navigasi utama
            try:
                page.goto(url, timeout=timeout, wait_until="domcontentloaded")
                page.wait_for_load_state("networkidle", timeout=timeout)
            except PlaywrightTimeoutError:
                # Timeout networkidle normal di SPA berat, lanjut saja
                pass
            except Exception as e:
                error_msg = str(e)

            # Scroll buat trigger lazy content & deferred API calls
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(extra_wait_ms)
                page.evaluate("window.scrollTo(0, 0)")
                page.wait_for_timeout(500)
            except Exception:
                pass

            # Ambil konten final
            try:
                html = page.content()
                title = page.title()
            except Exception:
                pass

            # Ambil cookies session
            try:
                for c in context.cookies():
                    cookies_map[c["name"]] = c["value"]
            except Exception:
                pass

            # Tutup context + browser dengan benar
            try:
                context.close()
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass

    except Exception as e:
        error_msg = str(e)

    return {
        "ok": html != "",
        "html": html,
        "title": title,
        "api_calls": api_calls,
        "cookies": cookies_map,
        "error": error_msg,
    }