import re
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse


# ------------------------------------------------------------------ #
#  Constants                                                           #
# ------------------------------------------------------------------ #

SPA_SIGNATURES = [
    '<div id="app">',
    'vite app',
    '__nuxt',
    'ng-version',
    'data-reactroot',
    '<div id="root">',
    'nextjs',
    '__next',
    'svelte',
    'webpack',
    'vue-router',
    'react-dom',
    'angular',
]

JS_PATH_PATTERNS = [
    # Explicit API prefix
    r'["\`](/(?:api|v\d+|rest|graphql|auth|admin|users|posts|data)[^"\'`\s<>]{0,120})["\`]',
    # Key assignments
    r'path\s*[:=]\s*["\`](/[^"\'`\s]{2,120})["\`]',
    r'url\s*[:=]\s*["\`](/[^"\'`\s]{2,120})["\`]',
    r'endpoint\s*[:=]\s*["\`](/[^"\'`\s]{2,120})["\`]',
    r'route\s*[:=]\s*["\`](/[^"\'`\s]{2,120})["\`]',
    r'baseURL\s*[:=]\s*["\`](/[^"\'`\s]{2,120})["\`]',  # axios config
    r'baseUrl\s*[:=]\s*["\`](/[^"\'`\s]{2,120})["\`]',
    # HTTP calls
    r'fetch\(["\`](/[^"\'`\s)]{2,120})["\`\)]',
    r'axios\.[a-z]+\(["\`](/[^"\'`\s)]{2,120})["\`\)]',
    r'\$\.(?:get|post|ajax)\(["\`](/[^"\'`\s)]{2,120})["\`\)]',
    r'\.(?:get|post|put|delete|patch)\(["\`](/[^"\'`\s)]{2,120})["\`\)]',
    # Static file paths
    r'["\`](/[^"\'`\s<>]{2,120}\.(?:json|php|asp|aspx|js|ts|mjs|txt))["\`]',
]

FORM_INPUT_TYPES = {
    'text', 'password', 'email', 'number', 'url', 'search',
    'hidden', 'tel', 'date', 'datetime-local', 'file', 'checkbox', 'radio'
}

CSRF_FIELD_NAMES = {
    '_token', 'csrf_token', 'csrfmiddlewaretoken', '_csrf',
    'authenticity_token', '__requestverificationtoken',
}


# ------------------------------------------------------------------ #
#  SPA Detection                                                       #
# ------------------------------------------------------------------ #

def is_spa_html(html: str) -> bool:
    """Return True jika HTML kemungkinan adalah SPA."""
    lower = html.lower()
    return any(sig.lower() in lower for sig in SPA_SIGNATURES)


def spa_confidence(html: str) -> int:
    """
    Return jumlah signature SPA yang cocok (0 = bukan SPA, makin tinggi makin yakin).
    Modul vuln bisa pakai ini: if spa_confidence(html) >= 2: use_browser()
    """
    lower = html.lower()
    return sum(1 for sig in SPA_SIGNATURES if sig.lower() in lower)


# ------------------------------------------------------------------ #
#  URL Utilities                                                       #
# ------------------------------------------------------------------ #

def normalize_url(url: str, base_url: str = '') -> str:
    """Gabungkan URL relatif dengan base, buang fragment, return URL bersih."""
    full = urljoin(base_url, url) if base_url else url
    parsed = urlparse(full)
    # Buang fragment (#section)
    clean = urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, parsed.query, ''
    ))
    return clean


def is_same_host(base_url: str, target_url: str) -> bool:
    try:
        return urlparse(base_url).netloc == urlparse(target_url).netloc
    except Exception:
        return False


# ------------------------------------------------------------------ #
#  HTML Parsers                                                        #
# ------------------------------------------------------------------ #

def extract_title(html: str) -> str:
    soup = BeautifulSoup(html, 'html.parser')
    t = soup.find('title')
    return t.get_text(strip=True) if t else ''


def extract_meta(html: str) -> Dict[str, str]:
    soup = BeautifulSoup(html, 'html.parser')
    metas = {}
    for m in soup.find_all('meta'):
        name = m.get('name') or m.get('property')
        content = m.get('content')
        if name and content:
            metas[name.lower()] = content
    return metas


def extract_links(html: str, base_url: str = '') -> List[str]:
    soup = BeautifulSoup(html, 'html.parser')
    links = []
    for a in soup.find_all('a', href=True):
        href = a.get('href', '').strip()
        if href and not href.startswith(('mailto:', 'tel:', 'javascript:')):
            links.append(normalize_url(href, base_url))
    return list(dict.fromkeys(links))


def extract_script_srcs(html: str, base_url: str = '') -> List[str]:
    soup = BeautifulSoup(html, 'html.parser')
    srcs = []
    for s in soup.find_all('script'):
        src = s.get('src', '').strip()
        if src:
            srcs.append(normalize_url(src, base_url))
    return list(dict.fromkeys(srcs))


def extract_inline_scripts(html: str) -> List[str]:
    """
    Ambil semua konten <script> inline (tanpa src).
    Dipakai extract_paths_from_js() tanpa harus fetch file JS eksternal.
    """
    soup = BeautifulSoup(html, 'html.parser')
    scripts = []
    for s in soup.find_all('script'):
        if not s.get('src') and s.string:
            scripts.append(s.string.strip())
    return scripts


def extract_forms(html: str, base_url: str = '') -> List[Dict]:
    """
    Parse semua form: action, method, inputs (name, type, value, required).
    Termasuk deteksi CSRF token otomatis.
    """
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        action = form.get('action', '').strip()
        method = form.get('method', 'get').lower()
        enctype = form.get('enctype', 'application/x-www-form-urlencoded')
        full_url = normalize_url(action, base_url) if action else base_url

        inputs = []
        csrf_token = None

        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name', '').strip()
            if not name:
                continue
            itype = (inp.get('type') or inp.name or 'text').lower()
            value = inp.get('value', '') or ''

            # Deteksi CSRF token
            if name.lower() in CSRF_FIELD_NAMES:
                csrf_token = value

            inputs.append({
                'name': name,
                'type': itype,
                'value': value,
                'required': inp.has_attr('required'),
            })

        forms.append({
            'action': full_url,
            'method': method,
            'enctype': enctype,
            'inputs': inputs,
            'csrf_token': csrf_token,
            'has_file_upload': any(i['type'] == 'file' for i in inputs),
        })
    return forms


def extract_inputs_flat(html: str, base_url: str = '') -> List[Dict]:
    """
    Shortcut: ambil semua input dari semua form dalam satu list datar.
    Tiap item punya 'form_action' dan 'form_method' untuk konteks.
    """
    flat = []
    for form in extract_forms(html, base_url):
        for inp in form['inputs']:
            flat.append({
                **inp,
                'form_action': form['action'],
                'form_method': form['method'],
            })
    return flat


# ------------------------------------------------------------------ #
#  JavaScript Parsers                                                  #
# ------------------------------------------------------------------ #

def extract_paths_from_js(js_text: str) -> List[str]:
    found = []
    for pattern in JS_PATH_PATTERNS:
        found.extend(re.findall(pattern, js_text))
    cleaned = []
    for p in found:
        p = p.strip().strip('\'"` ')
        if p and p.startswith('/') and len(p) > 1:
            cleaned.append(p)
    return list(dict.fromkeys(cleaned))


def extract_all_js_paths(html: str) -> List[str]:
    """
    Gabungkan semua path dari semua inline script sekaligus.
    Tanpa perlu fetch JS eksternal.
    """
    all_paths = []
    for script in extract_inline_scripts(html):
        all_paths.extend(extract_paths_from_js(script))
    return list(dict.fromkeys(all_paths))