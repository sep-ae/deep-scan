from extensions import db
from models import ReconData, Vulnerability, PoC
from helpers.vuln_profiles import VULN_PROFILES
from helpers.cvss_calculator import calculate_cvss

CATEGORY_LABEL = {
    'xss':               'XSS',
    'sql_injection':     'SQL Injection',
    'command_injection': 'Command Injection',
    'file_upload':       'File Upload',
    'open_redirect':     'Open Redirect',
    'directory_listing': 'Directory Listing',
}

ALL_PROFILES = VULN_PROFILES

CHECKER_VULN_KEY_MAP = {
    'sql_injection':     'SQLI_HIGH',
    'command_injection': 'CMDI_CRITICAL',
    'file_upload':       'FILE_UPLOAD_CRITICAL',
    'open_redirect':     'OPEN_REDIRECT_HIGH',
    'directory_listing': 'DIR_LISTING_HIGH',
    'xss':               'XSS_HIGH',
}


def _extract_poc_data(checker_name: str, vp: dict) -> dict:
    """Ekstrak data PoC dari vulnerable_paths sesuai jenis checker."""
    url = vp.get('url', '')
    method = vp.get('method', 'GET').upper()

    if checker_name == 'sql_injection':
        param = vp.get('param', '?')
        payload = vp.get('payload', '')
        return {
            'payload': f"URL: {url}\nParameter: {param}\nPayload: {payload}\nType: {vp.get('type', '-')}\nDB: {vp.get('db_type', '-')}",
            'response': f"Signature matched. WAF: {vp.get('waf_detected', False)}",
            'http_method': method,
        }

    elif checker_name == 'xss':
        param = vp.get('param', '?')
        payload = vp.get('payload', '')
        return {
            'payload': f"URL: {url}\nParameter: {param}\nPayload: {payload}\nType: {vp.get('type', 'Reflected XSS')}",
            'response': f"Payload reflected in response body without encoding.",
            'http_method': method,
        }

    elif checker_name == 'command_injection':
        param = vp.get('param', '?')
        payload = vp.get('payload', '')
        sig = vp.get('signature', '')
        return {
            'payload': f"URL: {url}\nParameter: {param}\nPayload: 127.0.0.1{payload}",
            'response': f"Signature detected: {sig}",
            'http_method': method,
        }

    elif checker_name == 'file_upload':
        return {
            'payload': f"URL: {url}\nField: {vp.get('field', '-')}\nFilename: {vp.get('filename', '-')}\nExtension: .{vp.get('extension', '-')}\nMIME: {vp.get('mime', '-')}",
            'response': vp.get('response', '')[:2000],
            'http_method': 'POST',
        }

    elif checker_name == 'open_redirect':
        return {
            'payload': f"URL: {url}\nRedirect to: external domain",
            'response': f"Server responded with redirect (HTTP 3xx) to attacker-controlled URL.",
            'http_method': method,
        }

    elif checker_name == 'directory_listing':
        return {
            'payload': f"URL: {url}",
            'response': f"Directory listing page detected with file/folder listing.",
            'http_method': 'GET',
        }

    return None


def _save_vuln_from_profile(vuln_key: str, result_id: int, affected: str = '-', extra: str = None):
    profile = ALL_PROFILES.get(vuln_key)
    if not profile:
        print(f"[DEBUG][_save_vuln_from_profile] Profile not found: {vuln_key}")
        return

    m = profile['metrics']
    score, severity, vector = calculate_cvss(
        m['av'], m['ac'], m['pr'], m['ui'], m['s'], m['c'], m['i'], m['a']
    )

    desc = f"{profile['description']}\nAffected: {affected}\nVector: {vector}\nScore: {score}"
    if extra:
        desc += f"\nDetail: {extra}"

    existing = Vulnerability.query.filter_by(
        scan_results_result_id=result_id,
        vuln_name=profile['name']
    ).first()

    if existing:
        existing.description += f"\n- Terdeteksi pada: {affected}"
    else:
        db.session.add(Vulnerability(
            scan_results_result_id=result_id,
            category=profile['category'],
            vuln_name=profile['name'],
            severity=severity,
            description=desc,
            recommendation=profile['recommendation']
        ))

    print(f"  [!] Vuln found: {profile['name']} ({severity})")


def _create_vulnerability_entry(vuln_key: str, result_id: int, affected_item: str, poc_data: dict = None):
    print(f"[DEBUG][_create] dipanggil: vuln_key={vuln_key} | result_id={result_id} | affected={affected_item}")
    profile = ALL_PROFILES.get(vuln_key)
    if not profile:
        print(f"[DEBUG][_create] Profile NOT FOUND: {vuln_key}")
        print(f"[DEBUG][_create] Keys tersedia: {[k for k in ALL_PROFILES.keys() if 'CMD' in k or 'UPLOAD' in k or 'REDIRECT' in k]}")
        return

    print(f"[DEBUG][_create] Profile ditemukan: {profile['name']}")

    m = profile['metrics']
    score, severity, vector = calculate_cvss(
        m['av'], m['ac'], m['pr'], m['ui'], m['s'], m['c'], m['i'], m['a']
    )

    existing = Vulnerability.query.filter_by(
        scan_results_result_id=result_id,
        vuln_name=profile['name']
    ).first()

    if existing:
        print(f"[DEBUG][_create] Vuln sudah ada, update deskripsi")
        existing.description += f"\n- Terdeteksi pada: {affected_item}"
    else:
        print(f"[DEBUG][_create] Insert vuln baru: {profile['name']} ({severity})")
        new_vuln = Vulnerability(
            scan_results_result_id=result_id,
            category=profile['category'],
            vuln_name=profile['name'],
            severity=severity,
            description=(
                f"{profile['description']}\n"
                f"Affected: {affected_item}\n"
                f"Vector: {vector}\n"
                f"Score: {score}"
            ),
            recommendation=profile['recommendation']
        )
        db.session.add(new_vuln)

        # Simpan PoC jika ada data
        if poc_data:
            db.session.flush()  # agar new_vuln.vuln_id terisi
            poc = PoC(
                vulnerabilities_vuln_id=new_vuln.vuln_id,
                payload=str(poc_data.get('payload', ''))[:2000],
                response=str(poc_data.get('response', ''))[:2000],
                http_method=poc_data.get('http_method', 'GET')[:10],
            )
            db.session.add(poc)
            print(f"  [+] PoC saved: method={poc.http_method} | payload={poc.payload[:80]}...")

    print(f"  [!] Vuln found: {profile['name']} ({severity})")


def process_generic_results(category: str, data, result_id: int):
    if not data:
        return

    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                item_name = str(entry.get('subdomain') or entry.get('port') or 'Unknown')
                vuln_key  = entry.get('vuln_key')
            else:
                item_name = str(entry)
                vuln_key  = None

            db.session.add(ReconData(
                scan_results_result_id=result_id,
                category=category,
                item=item_name[:255],
                details=str(entry)[:500]
            ))

            if vuln_key:
                _create_vulnerability_entry(vuln_key, result_id, item_name)

    elif isinstance(data, dict):
        for key, value in data.items():
            db.session.add(ReconData(
                scan_results_result_id=result_id,
                category=category,
                item=str(key)[:255],
                details=str(value)[:500]
            ))

    db.session.commit()


def process_http_security_results(http_results: dict, result_id: int):
    if not http_results:
        return

    headers_result = http_results.get('headers', {})
    cors_result    = http_results.get('cors', {})

    if headers_result and not headers_result.get('error'):
        for finding in headers_result.get('findings', []):
            db.session.add(ReconData(
                scan_results_result_id=result_id,
                category='HTTP Headers',
                item=finding['header'],
                details=str(finding)[:500]
            ))

        missing_headers = headers_result.get('missing', [])
        if missing_headers:
            _save_vuln_from_profile(
                'missing_security_headers', result_id,
                affected=', '.join(missing_headers)
            )

    if cors_result and not cors_result.get('error'):
        if cors_result.get('cors_headers'):
            db.session.add(ReconData(
                scan_results_result_id=result_id,
                category='CORS',
                item='CORS Configuration',
                details=str(cors_result['cors_headers'])[:500]
            ))

        if cors_result.get('issues'):
            _save_vuln_from_profile(
                'cors_misconfiguration', result_id,
                affected='CORS Policy',
                extra='; '.join(cors_result['issues'])
            )

    db.session.commit()


def process_auth_results(auth_results: dict, result_id: int):
    if not auth_results:
        return

    waf   = auth_results.get('waf',   {})
    rl    = auth_results.get('rate_limit', {})
    login = auth_results.get('login', {})

    if not waf.get('waf_detected'):
        _save_vuln_from_profile('WAF_NOT_DETECTED', result_id, affected='-')
    else:
        db.session.add(ReconData(
            scan_results_result_id=result_id,
            category='Auth Protection',
            item='WAF Detected',
            details=f"{waf.get('waf_name')} ({waf.get('confidence')})"
        ))

    if not rl.get('rate_limit_detected'):
        _save_vuln_from_profile(
            'RATE_LIMIT_NOT_DETECTED', result_id,
            affected=rl.get('login_endpoint', '-')
        )

    if login.get('login_endpoint'):
        ep = login['login_endpoint']
        if not login.get('csrf_protection'):
            _save_vuln_from_profile('LOGIN_NO_CSRF',          result_id, affected=ep)
        if not login.get('captcha_detected'):
            _save_vuln_from_profile('LOGIN_NO_CAPTCHA',       result_id, affected=ep)
        if not login.get('account_lockout_detected'):
            _save_vuln_from_profile('BRUTE_FORCE_NO_LOCKOUT', result_id, affected=ep)
        if login.get('weak_password_allowed'):
            _save_vuln_from_profile('WEAK_PASSWORD_ACCEPTED', result_id, affected=ep)
        if login.get('default_creds_allowed'):
            _save_vuln_from_profile('DEFAULT_CREDENTIALS',    result_id, affected=ep)

    db.session.commit()


def process_web_vuln_results(web_vuln_results: dict, result_id: int):
    if not web_vuln_results:
        return

    for checker_name, result in web_vuln_results.items():
        if not result:
            continue

        category = CATEGORY_LABEL.get(checker_name, checker_name.upper())

        if result.get('error'):
            db.session.add(ReconData(
                scan_results_result_id=result_id,
                category=category,
                item='Checker Error',
                details=str(result['error'])[:500]
            ))
            db.session.commit()
            continue

        if not result.get('vulnerable'):
            continue

        vuln_saved    = 0
        recon_count   = 0
        vuln_key_used = None

        vulnerable_paths = result.get('vulnerable_paths', [])
        print(f"[DEBUG][{checker_name}] vulnerable_paths count: {len(vulnerable_paths)}")
        print(f"[DEBUG][{checker_name}] results count: {len(result.get('results', []))}")
        print(f"[DEBUG][{checker_name}] result keys: {list(result.keys())}")

        for vp in vulnerable_paths:
            url      = vp.get('url', '-')
            severity = vp.get('severity', 'UNKNOWN')
            vuln_key = vp.get('vuln_key') or CHECKER_VULN_KEY_MAP.get(checker_name)

            print(f"[DEBUG][{checker_name}] vp → url={url} | vuln_key={vuln_key} | severity={severity}")

            details = (
                f"Severity: {severity} | "
                f"Files: {vp.get('file_count', 0)} | "
                f"Status: {vp.get('status_code', '-')}"
            )
            notable = vp.get('notable_files', [])
            if notable:
                details += f" | Notable: {', '.join(notable[:3])}"

            db.session.add(ReconData(
                scan_results_result_id=result_id,
                category=category,
                item=url[:255],
                details=details[:500]
            ))
            recon_count += 1

            if vuln_key and vuln_key != vuln_key_used:
                # Build PoC data dari vulnerable_paths
                poc_data = _extract_poc_data(checker_name, vp)
                _create_vulnerability_entry(vuln_key, result_id, url, poc_data=poc_data)
                vuln_saved   += 1
                vuln_key_used = vuln_key

        for item in result.get('results', []):
            if not isinstance(item, dict):
                continue

            url      = item.get('url', '-')
            vuln_key = item.get('vuln_key') or CHECKER_VULN_KEY_MAP.get(checker_name)
            payload  = item.get('payload', '')
            param    = item.get('param', '')

            print(f"[DEBUG][{checker_name}] results item → url={url} | vuln_key={vuln_key}")

            details = f"vuln_key: {vuln_key} | param: {param} | payload: {str(payload)[:100]}"

            db.session.add(ReconData(
                scan_results_result_id=result_id,
                category=category,
                item=url[:255],
                details=details[:500]
            ))
            recon_count += 1

            if vuln_key and vuln_key != vuln_key_used:
                _create_vulnerability_entry(vuln_key, result_id, url)
                vuln_saved   += 1
                vuln_key_used = vuln_key

        if vuln_saved == 0:
            vuln_key = result.get('vuln_key') or CHECKER_VULN_KEY_MAP.get(checker_name)
            print(f"[DEBUG][{checker_name}] Handler 3 fallback → vuln_key={vuln_key}")
            if vuln_key:
                affected = (
                    result.get('url') or
                    result.get('affected_url') or
                    result.get('endpoint') or
                    '-'
                )
                print(f"[DEBUG][{checker_name}] Handler 3 affected={affected}")
                _create_vulnerability_entry(vuln_key, result_id, affected)
                vuln_saved += 1

        for finding in result.get('findings', []):
            if not finding.strip():
                continue
            if finding.strip().startswith('→') or 'File sensitif' in finding:
                continue
            db.session.add(ReconData(
                scan_results_result_id=result_id,
                category=f"{category}:Summary",
                item=finding[:255],
                details=finding[:500]
            ))
            recon_count += 1

        db.session.commit()
        print(f"  [+] {category}: {vuln_saved} vuln disimpan | {recon_count} recon entries")