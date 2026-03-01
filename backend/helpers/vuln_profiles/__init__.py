from .recon_profiles import RECON_PROFILES
from .http_profiles import HTTP_PROFILES
from .auth_profiles import AUTH_PROFILES
from .webvuln_profiles import WEBVULN_PROFILES

VULN_PROFILES = {
    **RECON_PROFILES,
    **HTTP_PROFILES,
    **AUTH_PROFILES,
    **WEBVULN_PROFILES,
}
