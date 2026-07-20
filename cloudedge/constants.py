"""
Configuration constants for CloudEdge API
"""

# Global redirect endpoint — used to discover the correct regional server.
REDIRECT_URL = "https://apis-eu-frankfurt.cloudedge360.com/ppstrongs/redirect"

# API Keys (Meari / ieGeek)
CA_KEY = "bc29be30292a4309877807e101afbd51"
CA_SECRET = "123456781234567812345678"

# Default Headers
DEFAULT_HEADERS = {
    "Accept-Language": "en-US,en;q=0.8",
    "User-Agent": "Mozilla/5.0 (Linux; U; Android 10; en-us; Android SDK built for arm64 Build/QSR1.211112.002) AppleWebKit/533.1 (KHTML, like Gecko) Version/5.0 Mobile Safari/533.1",
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept-Encoding": "gzip, deflate, br"
}

# API Constants ieGeek
PHONE_TYPE = "a"
SOURCE_APP = "81"
APP_VERSION = "6.1.1"
IOT_TYPE = "4"
APP_VERSION_CODE = "1035"
DEFAULT_LANGUAGE = "en"

# Timeout values (seconds)
DEFAULT_TIMEOUT = 30
PING_TIMEOUT = 2.0

# Cache settings
DEFAULT_CACHE_FILE = ".cloudedge_session_cache"
