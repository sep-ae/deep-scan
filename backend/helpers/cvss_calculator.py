import math

def calculate_cvss(av, ac, pr, ui, s, c, i, a):
    """
    Kalkulator CVSS v3.1 yang disederhanakan namun akurat.
    Mengikuti logika resmi FIRST.org untuk keperluan testing.
    """
    # 1. Metrik Bobot (Official Weights)
    w_av = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}[av]
    w_ac = {'L': 0.77, 'H': 0.44}[ac]
    w_ui = {'N': 0.85, 'R': 0.62}[ui]
    
    # Privileges Required (PR) bergantung pada metrik Scope (S)
    if s == 'U':
        w_pr = {'N': 0.85, 'L': 0.62, 'H': 0.27}[pr]
    else:
        w_pr = {'N': 0.85, 'L': 0.68, 'H': 0.50}[pr]

    # Impact Metrics
    w_c = {'H': 0.56, 'L': 0.22, 'N': 0.0}[c]
    w_i = {'H': 0.56, 'L': 0.22, 'N': 0.0}[i]
    w_a = {'H': 0.56, 'L': 0.22, 'N': 0.0}[a]

    # 2. Perhitungan Impact Sub-Score (ISS)
    iss = 1 - ((1 - w_c) * (1 - w_i) * (1 - w_a))

    # 3. Perhitungan Impact Score
    if s == 'U':
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # 4. Perhitungan Exploitability
    exploitability = 8.22 * w_av * w_ac * w_pr * w_ui

    # 5. Final Base Score
    if impact <= 0:
        base_score = 0
    else:
        if s == 'U':
            base_score = min((impact + exploitability), 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)

    # Pembulatan ke atas (Official CVSS Rounding)
    score = math.ceil(base_score * 10) / 10.0

    # 6. Severity Rating
    if score == 0.0: severity = "None"
    elif score <= 3.9: severity = "Low"
    elif score <= 6.9: severity = "Medium"
    elif score <= 8.9: severity = "High"
    else: severity = "Critical"

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    
    return score, severity, vector