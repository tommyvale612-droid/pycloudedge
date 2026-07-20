"""
CloudEdge API Client
============================

Main client class for interacting with CloudEdge cameras.
Provides authentication, device management, and configuration capabilities.
"""

import os
import json
import time
import base64
import hmac
import hashlib
import datetime
import subprocess
import socket
import ipaddress
import logging
from typing import Dict, List, Optional, Union, Any
from urllib.parse import quote, urlencode

import requests

from .exceptions import (
    CloudEdgeError, 
    AuthenticationError, 
    DeviceNotFoundError, 
    ConfigurationError,
    NetworkError,
    ValidationError
)
from .iot_parameters import (
    get_parameter_name, 
    get_parameter_code_by_name, 
    format_parameter_value
)
from .constants import (
    CA_KEY, CA_SECRET, DEFAULT_HEADERS, DEFAULT_TIMEOUT,
    REDIRECT_URL,
)
from .validators import validate_email, validate_country_code, validate_phone_code
from .logging_config import get_logger
from .utils import retry_on_failure

# Device online status values returned by get_device_online_status()
DEVICE_STATUS_ONLINE = "online"
DEVICE_STATUS_DORMANCY = "dormancy"
DEVICE_STATUS_OFFLINE = "offline"

# API list keys → readable product type when deviceTypeName is a CDN image URL
_DEVICE_LIST_CATEGORY_LABELS = {
    "snap": "Camera",
    "ipc": "Camera",
    "nvr": "NVR",
    "doorbell": "Doorbell",
    "chime": "Chime",
}

# Extra app fields needed by the native P2P streaming handshake.
_APP_STREAMING_METADATA_FIELDS = {
    "device_uuid": "deviceUUID",
    "p2p_init": "p2pInit",
    "device_p2p": "deviceP2P",
    "relay_license_id": "relayLicenseID",
    "host_key1": "hostKey1",
    "share_access_sign": "shareAccessSign",
    "as_friend": "asFriend",
    "device_region": "region",
}


def _extract_app_streaming_metadata(device: Dict[str, Any]) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    for normalized_key, source_key in _APP_STREAMING_METADATA_FIELDS.items():
        value = device.get(source_key)
        if value not in (None, ""):
            metadata[normalized_key] = value
    return metadata


def _device_icon_url_from_type_name(device_type_name: Any) -> Optional[str]:
    """Return URL if deviceTypeName is an http(s) icon URL (Meari/OSS), else None."""
    if not isinstance(device_type_name, str):
        return None
    s = device_type_name.strip()
    if s.startswith(("http://", "https://")):
        return s
    return None


def _human_type_and_icon_url(
    device: Dict[str, Any],
    list_category: Optional[str] = None,
) -> tuple[str, Optional[str]]:
    """
    CloudEdge often puts a product image URL in deviceTypeName instead of a label.
    Return a human-readable type for UIs (e.g. Home Assistant model) and optional icon URL.
    """
    raw = device.get("deviceTypeName")
    icon_url = _device_icon_url_from_type_name(raw)
    if icon_url is not None:
        label = _DEVICE_LIST_CATEGORY_LABELS.get(list_category or "", "SmartEye Camera")
        lower = icon_url.lower()
        if "doorbell" in lower:
            label = "Doorbell"
        elif "chime" in lower:
            label = "Chime"
        elif "nvr" in lower:
            label = "NVR"
        elif "snap" in lower or "ipc" in lower:
            label = "Camera"
        return label, icon_url
    if raw is not None and str(raw).strip():
        return str(raw).strip(), None
    if list_category:
        return _DEVICE_LIST_CATEGORY_LABELS.get(list_category, "Unknown"), None
    return "Unknown", None


class CloudEdgeClient:
    """
    CloudEdge / ieGeek API Client
    """
    
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
        
        self.BASE_URL: Optional[str] = None
        self.OPENAPI_BASE_URL: Optional[str] = None
        
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

    def _log(self, message: str) -> None:
        self.logger.debug(message)
            
    def _error(self, message: str) -> None:
        self.logger.error(message)

    def _des_encode(self, password: str) -> str:
        key = "123456781234567812345678".encode('utf-8')
        iv = "01234567".encode('utf-8')
        
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding

            algorithm = algorithms.TripleDES(key)
            cipher = Cipher(algorithm, modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            padder = padding.PKCS7(64).padder()
            padded_data = padder.update(password.encode('utf-8')) + padder.finalize()
            
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            return base64.b64encode(encrypted).decode('utf-8')
            
        except Exception as e:
            raise CloudEdgeError(f"Error during password encryption: {e}")

    def _aes_encode_param(self, user_account: str, api_endpoint: str, partner_id: int = 8, 
                          ttid: str = "", timestamp: Optional[int] = None) -> str:
        if timestamp is None:
            timestamp = int(time.time() * 1000)
        
        key_material = f"{api_endpoint}{partner_id}{ttid}{timestamp}"
        key_b64 = base64.b64encode(key_material.encode('utf-8')).decode('utf-8')
        aes_key = key_b64[:16].encode('utf-8')
        
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding

            algorithm = algorithms.AES(aes_key)
            cipher = Cipher(algorithm, modes.CBC(aes_key))
            encryptor = cipher.encryptor()
            
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(user_account.encode('utf-8')) + padder.finalize()
            
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            return base64.b64encode(encrypted).decode('utf-8')
            
        except Exception as e:
            raise CloudEdgeError(f"Error during username encryption: {e}")

    def _discover_endpoints(self) -> None:
        import random

        timestamp = int(time.time() * 1000)
        encrypted_account = self._aes_encode_param(
            self.username, "/ppstrongs/redirect", timestamp=timestamp,
        )
        query_nonce = "".join(
            [str(random.randint(0, 9)) for _ in range(8)]
        )
        header_nonce = str(random.randint(100000, 999999))

        phone_code_bare = self.phone_code.lstrip("+")
        params = {
            "phoneType": "a",
            "sourceApp": "81",
            "appVer": "6.1.1",
            "appVerCode": "1035",
            "localTime": str(timestamp),
            "t": str(timestamp),
            "lngType": "en",
            "countryCode": self.country_code,
            "userAccount": encrypted_account,
            "phoneCode": phone_code_bare,
            "partnerId": "8",
            "nonce": query_nonce,
        }

        params["sign"] = hashlib.md5(
            f"GET|/ppstrongs/redirect|{timestamp}|apis.meari.com.cn".encode()
        ).hexdigest()

        ca_sign_data = (
            f"api=/ppstrongs//ppstrongs/redirect"
            f"|X-Ca-Key={CA_KEY}"
            f"|X-Ca-Timestamp={timestamp}"
            f"|X-Ca-Nonce={header_nonce}"
        )
        ca_signature = base64.b64encode(
            hmac.new(CA_SECRET.encode(), ca_sign_data.encode(), hashlib.sha1).digest()
        ).decode()

        headers = {
            **DEFAULT_HEADERS,
            "X-Ca-Timestamp": str(timestamp),
            "X-Ca-Sign": ca_signature,
            "X-Ca-Key": CA_KEY,
            "X-Ca-Nonce": header_nonce,
        }

        try:
            resp = self._session.get(
                REDIRECT_URL, params=params, headers=headers, timeout=DEFAULT_TIMEOUT,
            )
            data = resp.json()
            if data.get("resultCode") != "1001":
                raise NetworkError(
                    f"Redirect discovery returned unexpected code: {data.get('resultCode')}"
                )

            result = data.get("result", {})
            api_server = result.get("apiServer") or result.get("gwUrl") or ""
            if api_server:
                self.BASE_URL = api_server.rstrip("/")
                self._log(f"Discovered API server: {self.BASE_URL}")

            pf_api = result.get("pfApi", {})
            openapi_domain = pf_api.get("openapi", {}).get("domain", "")
            if openapi_domain:
                self.OPENAPI_BASE_URL = openapi_domain.rstrip("/")
                self._log(f"Discovered OpenAPI server: {self.OPENAPI_BASE_URL}")

            if not self.BASE_URL:
                raise NetworkError(
                    "Redirect API did not return an apiServer"
                )

        except NetworkError:
            raise
        except Exception as exc:
            raise NetworkError(f"Endpoint discovery failed: {exc}") from exc

    def authenticate(self) -> bool:
        self.session_data = self._load_session_cache()
        if self.session_data:
            self._log("Using cached session")
            if self.session_data.get("apiServer"):
                self.BASE_URL = self.session_data["apiServer"]
            if self.session_data.get("openapiServer"):
                self.OPENAPI_BASE_URL = self.session_data["openapiServer"]
            return True

        self._discover_endpoints()

        self._log("Performing ieGeek login...")
        
        timestamp = int(time.time() * 1000)
        try:
            encrypted_username = self._aes_encode_param(
                self.username, "/meari/app/login", timestamp=timestamp
            )
            encrypted_password = self._des_encode(self.password)
        except Exception as e:
            raise AuthenticationError(f"Failed to encrypt credentials: {e}")
            
        ca_timestamp = str(timestamp)
        ca_nonce = str(int(time.time() * 1000000) % 100000000)
        ca_key = "bc29be30292a4309877807e101afbd51"
        
        ca_sign_data = (
            f"phoneType=a&sourceApp=81&appVer=6.1.1&iotType=4&equipmentNo=&"
            f"appVerCode=1035&localTime={timestamp}&password={encrypted_password}&"
            f"t={timestamp}&lngType=en&countryCode={self.country_code}&"
            f"userAccount={encrypted_username}&phoneCode={self.phone_code}"
        )
        ca_signature = base64.b64encode(
            hmac.new(ca_key.encode(), ca_sign_data.encode(), hashlib.sha1).digest()
        ).decode()
        
        login_data = {
            "phoneType": "a",
            "sourceApp": "81",
            "appVer": "6.1.1",
            "iotType": "4",
            "equipmentNo": "",
            "appVerCode": "1035",
            "localTime": timestamp,
            "password": encrypted_password,
            "t": timestamp,
            "lngType": "en",
            "countryCode": self.country_code,
            "userAccount": encrypted_username,
            "phoneCode": self.phone_code
        }
        
        headers = {
            "Accept-Language": "en-US,en;q=0.8",
            "User-Agent": "Mozilla/5.0 (Linux; U; Android 10; en-us; Android SDK built for arm64 Build/QSR1.211112.002) AppleWebKit/533.1 (KHTML, like Gecko) Version/5.0 Mobile Safari/533.1",
            "X-Ca-Timestamp": ca_timestamp,
            "X-Ca-Sign": ca_signature,
            "X-Ca-Key": ca_key,
            "X-Ca-Nonce": ca_nonce,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br"
        }
        
        try:
            response = self._session.post(
                f"{self.BASE_URL}/meari/app/login", 
                headers=headers, 
                data=login_data,
                timeout=30
            )
            response.raise_for_status()
            response_data = response.json()
            
            if response_data.get("resultCode") == "1001":
                self._log("Authentication successful!")
                
                result = response_data.get("result", {})
                user_token = result.get("userToken")
                user_id = result.get("userID")
                
                if not user_token or not user_id:
                    raise AuthenticationError(
                        "Missing user token or ID in response",
                        details={"response": response_data}
                    )
                
                self.session_data = {
                    "userToken": user_token,
                    "userID": user_id,
                    "caKey": ca_key,
                    "loginTime": int(time.time()),
                    "apiServer": self.BASE_URL,
                    "openapiServer": self.OPENAPI_BASE_URL
                }
                self._save_session_cache(self.session_data)
                return True
            else:
                raise AuthenticationError(
                    f"Login failed: {response_data.get('resultMsg', 'Unknown error')}",
                    details={"response": response_data}
                )
        except Exception as e:
            raise AuthenticationError(f"Login request failed: {e}")

    def _load_session_cache(self) -> Optional[Dict]:
        if not os.path.exists(self.session_cache_file):
            return None
        try:
            with open(self.session_cache_file, 'r') as f:
                session_data = json.load(f)
            if time.time() - session_data.get('loginTime', 0) > 86400:
                return None
            return session_data
        except Exception:
            return None

    def _save_session_cache(self, session_data: Dict) -> None:
        try:
            with open(self.session_cache_file, 'w') as f:
                json.dump(session_data, f)
        except Exception as e:
            self._log(f"Failed to save session cache: {e}")
