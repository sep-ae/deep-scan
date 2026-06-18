from urllib.parse import urlparse


def extract_root_domain(hostname: str) -> str:
    """
    Mengekstrak root domain dari hostname.

    Contoh:
        blog.septito.my.id  ->  septito.my.id
        api.example.com     ->  example.com
        localhost            ->  localhost
    """
    hostname = hostname.lower().strip()
    parts = hostname.split('.')

    # TLD dua bagian umum di Indonesia & internasional
    two_part_tlds = {
        'co.id', 'ac.id', 'go.id', 'or.id', 'web.id', 'my.id', 'sch.id',
        'co.uk', 'co.jp', 'co.kr', 'com.au', 'com.br', 'com.sg',
    }

    if len(parts) >= 3:
        last_two = '.'.join(parts[-2:])
        if last_two in two_part_tlds:
            # my.id, co.id -> ambil 3 bagian terakhir sebagai root
            return '.'.join(parts[-3:]) if len(parts) >= 3 else hostname
        # .com, .net, .org -> ambil 2 bagian terakhir
        return '.'.join(parts[-2:])

    return hostname


def is_in_scope(url: str, target_url: str, scope_mode: str = 'wildcard') -> bool:
    """
    Cek apakah sebuah URL masih dalam scope scan.

    Args:
        url:         URL yang akan dicek (misal endpoint API dari JS)
        target_url:  URL target utama yang diinput user
        scope_mode:  'strict' (hanya domain persis) atau 'wildcard' (termasuk subdomain)

    Returns:
        True jika URL masih dalam scope, False jika di luar scope.

    Contoh (target = https://blog.septito.my.id):
        strict mode:
            blog.septito.my.id/api   -> True
            api.septito.my.id/users  -> False (beda subdomain)

        wildcard mode:
            blog.septito.my.id/api   -> True
            api.septito.my.id/users  -> True  (subdomain sama)
            other-site.com/api       -> False (beda domain)
    """
    parsed_check = urlparse(url)
    check_host = (parsed_check.netloc or '').lower().strip()

    # URL relative (tanpa host) -> selalu in-scope
    if not check_host:
        return True

    parsed_target = urlparse(target_url)
    target_host = (parsed_target.netloc or '').lower().strip()

    if not target_host:
        return True

    if scope_mode == 'strict':
        return check_host == target_host

    # Wildcard mode — bandingkan root domain
    target_root = extract_root_domain(target_host)
    check_root = extract_root_domain(check_host)
    return check_root == target_root
