def calculate_cvss(av, ac, pr, ui, s, c, i, a):
    """
    Official CVSS v3.1 Base Score Calculator (FIRST.org)
    https://www.first.org/cvss/v3.1/specification-document
    """
    
    # Impact Sub Score Metrics (0-1)
    conf = {"H": 0.56, "L": 0.22, "N": 0.0}[c]
    integ = {"H": 0.56, "L": 0.22, "N": 0.0}[i] 
    avail = {"H": 0.56, "L": 0.22, "N": 0.0}[a]
    
    # ISC Base (Impact Sub Score)
    isc_base = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    
    # Base Score
    if s == "U":  # Scope Unchanged
        base_score = min(8.22 * isc_base, 10.0)
    else:         # Scope Changed
        base_score = min(7.52 * isc_base, 10.0)
    
    # Round to 1 decimal
    score = round(base_score, 1)
    
    # Severity Rating
    if score == 0.0:
        severity = "None"
    elif score <= 3.9:
        severity = "Low"
    elif score <= 6.9:
        severity = "Medium" 
    elif score <= 8.9:
        severity = "High"
    else:
        severity = "Critical"
    
    # Vector String
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    
    return score, severity, vector
