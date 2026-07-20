def __init__(
        self, 
        username: str, 
        password: str, 
        country_code: str, 
        phone_code: str,
        debug: bool = False,
        session_cache_file: str = ".cloudedge_session_cache",
        enable_network_ping: bool = True,
        ping_timeout: float = 2.0,
    ):
        self.username = username
        self.password = password
        self.country_code = country_code.upper() if country_code else "IT"
        self.phone_code = phone_code if phone_code and phone_code.startswith('+') else f'+{phone_code}'
        
        # Server ieGeek / CloudEdge Europa
        self.BASE_URL = "https://apis-eu-frankfurt.cloudedge360.com"
        self.OPENAPI_BASE_URL = "https://openapi-eu-frankfurt.cloudedge360.com"
        
        self.logger = get_logger("client")
        if debug:
            self.logger.setLevel(logging.DEBUG)
        self.debug = debug
        
        self.session_cache_file = session_cache_file
        self.enable_network_ping = enable_network_ping
        self.ping_timeout = ping_timeout
        
        self.session_data: Optional[Dict] = None
        self._session = requests.Session()
        self._session.headers.update({'User-Agent': DEFAULT_HEADERS['User-Agent']})
        
        self._local_network = None
        self._network_detected = False
