"""
Fixed Metrics → Auto Calculate Score
Metrics dari FIRST.org CVSS Examples + OWASP
"""

VULN_PROFILES = {
    "SQL_INJECTION": {
        "name": "SQL Injection (Error-based)",
        "category": "Injection",
        "metrics": {  # Fixed metrics
            "av": "N", "ac": "L", "pr": "N", 
            "ui": "N", "s": "C", "c": "H", 
            "i": "H", "a": "N"
        },
        "description": "Error-based SQL Injection detected.",
        "recommendation": "Parameterized queries + input validation"
    },
    
    "XSS_REFLECTED": {
        "name": "Reflected XSS",
        "category": "Injection",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", 
            "ui": "R", "s": "U", "c": "L", 
            "i": "L", "a": "N"
        },
        "description": "Reflected payload without encoding.",
        "recommendation": "Output encoding + CSP"
    },
    
    "OPEN_REDIRECT": {
        "name": "Open Redirect",
        "category": "Broken Access Control",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", 
            "ui": "R", "s": "U", "c": "N", 
            "i": "L", "a": "N"
        },
        "description": "Arbitrary external redirects allowed.",
        "recommendation": "Whitelist redirect domains"
    },
    
    "COMMAND_INJECTION": {
        "name": "Command Injection",
        "category": "Injection",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", 
            "ui": "N", "s": "U", "c": "H", 
            "i": "H", "a": "H"
        },
        "description": "OS command execution via input.",
        "recommendation": "Avoid shell execution with user input"
    },
    
    "FILE_UPLOAD": {
        "name": "File Upload Misconfiguration",
        "category": "Broken Access Control",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", 
            "ui": "N", "s": "U", "c": "H", 
            "i": "H", "a": "N"
        },
        "description": "Dangerous file types allowed.",
        "recommendation": "MIME validation + store outside webroot"
    },
    
    "DIRECTORY_LISTING": {
        "name": "Directory Listing Enabled",
        "category": "Security Misconfiguration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", 
            "ui": "N", "s": "U", "c": "L", 
            "i": "N", "a": "N"
        },
        "description": "File structure exposed.",
        "recommendation": "Disable directory indexes"
    },
    
    "MISSING_HEADERS": {
        "name": "Missing Security Headers",
        "category": "Security Misconfiguration", 
        "metrics": {
            "av": "N", "ac": "H", "pr": "N", 
            "ui": "N", "s": "U", "c": "L", 
            "i": "N", "a": "N"
        },
        "description": "CSP, HSTS, X-Frame-Options missing.",
        "recommendation": "Add security headers"
    },
    
    "CORS_MISCONFIG": {
        "name": "CORS Misconfiguration",
        "category": "Security Misconfiguration",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", 
            "ui": "R", "s": "C", "c": "L", 
            "i": "L", "a": "N"
        },
        "description": "Wildcard CORS with credentials.",
        "recommendation": "Specific origin whitelist"
    },
    
    "NO_RATE_LIMIT": {
        "name": "No Rate Limiting",
        "category": "Identification Failures",
        "metrics": {
            "av": "N", "ac": "L", "pr": "N", 
            "ui": "N", "s": "U", "c": "N", 
            "i": "L", "a": "N"
        },
        "description": "Unlimited login attempts.",
        "recommendation": "Rate limit + lockout"
    }
}
