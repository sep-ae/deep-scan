from extensions import db
from models import ReconData, Vulnerability
from helpers.vuln_profiles import VULN_PROFILES
from helpers.cvss_calculator import calculate_cvss


def _create_vulnerability_entry(vuln_key, result_id, affected_item):
    profile = VULN_PROFILES.get(vuln_key)
    if not profile:
        return

    m = profile['metrics']
    score, severity, vector = calculate_cvss(
        m['av'], m['ac'], m['pr'], m['ui'], m['s'], m['c'], m['i'], m['a']
    )

    existing = Vulnerability.query.filter_by(
        scan_results_result_id=result_id,
        vuln_name=profile['name']
    ).first()

    if existing:
        existing.description += f"\n- Terdeteksi pada: {affected_item}"
    else:
        db.session.add(Vulnerability(
            scan_results_result_id=result_id,
            category=profile['category'],
            vuln_name=profile['name'],
            severity=severity,
            description=f"{profile['description']}\nAffected: {affected_item}\nVector: {vector}\nScore: {score}",
            recommendation=profile['recommendation']
        ))

    db.session.commit()


def process_generic_results(category, data, result_id):
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


def process_http_security_results(http_results, result_id):
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


def process_auth_results(auth_results, result_id):
    if not auth_results:
        return

    waf   = auth_results.get('waf', {})
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
        _save_vuln_from_profile('RATE_LIMIT_NOT_DETECTED', result_id,
                                affected=rl.get('login_endpoint', '-'))

    # Fix key names sesuai output LoginSecurityChecker
    if login.get('login_endpoint'):
        if not login.get('csrf_protection'):
            _save_vuln_from_profile('LOGIN_NO_CSRF', result_id,
                                    affected=login.get('login_endpoint'))
        if not login.get('captcha_detected'):
            _save_vuln_from_profile('LOGIN_NO_CAPTCHA', result_id,
                                    affected=login.get('login_endpoint'))
        if not login.get('account_lockout_detected'):
            _save_vuln_from_profile('BRUTE_FORCE_NO_LOCKOUT', result_id,
                                    affected=login.get('login_endpoint'))
        if login.get('weak_password_allowed'):
            _save_vuln_from_profile('WEAK_PASSWORD_ACCEPTED', result_id,
                                    affected=login.get('login_endpoint'))
        if login.get('default_creds_allowed'):
            _save_vuln_from_profile('DEFAULT_CREDENTIALS', result_id,
                                    affected=login.get('login_endpoint'))

    db.session.commit()

def _save_vuln_from_profile(vuln_key, result_id, affected='-', extra=None):
    profile = VULN_PROFILES.get(vuln_key)
    if not profile:
        print(f"[!] Profile not found: {vuln_key}")
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
