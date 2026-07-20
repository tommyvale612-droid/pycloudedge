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
        if not validate_email(username):
            raise ValidationError(
                f"Invalid email format: {username}",
                details={"field": "username", "value": username}
            )
        
        if not validate_country_code(country_code):
            raise ValidationError(
                f"Invalid country code (use 2-letter code like 'US'): {country_code}",
                details={"field": "country_code", "value": country_code}
            )
        
        if not validate_phone_code(phone_code):
            raise ValidationError(
                f"Invalid phone code (use format like '+1'): {phone_code}",
                details={"field": "phone_code", "value": phone_code}
            )
        
        normalized_country_code = country_code.upper()
        if normalized_country_code == "UK":
            normalized_country_code = "GB"

        self.username = username
        self.password = password
        self.country_code = normalized_country_code
        self.phone_code = phone_code if phone_code.startswith('+') else f'+{phone_code}'
        
        # Server ieGeek / CloudEdge Francoforte (Europa)
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
