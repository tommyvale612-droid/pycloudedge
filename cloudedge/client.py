"""
CloudEdge API Client
"""

import os
import json
import time
import base64
import hmac
import hashlib
import logging
from typing import Dict, List, Optional, Any
import requests

from .constants import CA_KEY, CA_SECRET, DEFAULT_HEADERS, DEFAULT_TIMEOUT, REDIRECT_URL
from .exceptions import CloudEdgeError, AuthenticationError, DeviceNotFoundError, NetworkError

logger = logging.getLogger(__name__)


class CloudEdgeClient:
    """CloudEdge / ieGeek API Client."""

    def __init__(
        self,
        username: str,
        password: str,
        country_code: str = "IT",
        phone_code: str = "+39",
        debug: bool = False,
        session_cache_file: str = ".cloudedge_session_cache",
        enable_network_ping: bool = True,
        ping_timeout: float = 2.0,
    ):
        self.username = username
        self.password = password
        self.country_code = country_code.upper() if country_code else "IT"
        self.phone_code = phone_code if phone_code and phone_code.startswith("+") else f"+{phone_code}"

        self.BASE_URL = "https://apis-eu-frankfurt.cloudedge360.com"
        self.OPENAPI_BASE_URL = "https://openapi-eu-frankfurt.cloudedge360.com"

        self.logger = logger
        if debug:
            self.logger.setLevel(logging.DEBUG)

        self.session_cache_file = session_cache_file
        self.session_data: Optional[Dict] = None
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": DEFAULT_HEADERS.get("User-Agent", "")})

    def _des_encode(self, password: str) -> str:
        key = b"123456781234567812345678"
        iv = b"01234567"
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding

            algorithm = algorithms.TripleDES(key)
            cipher = Cipher(algorithm, modes.CBC(iv))
            encryptor = cipher.encryptor()

            padder = padding.PKCS7(64).padder()
            padded_data = padder.update(password.encode("utf-8")) + padder.finalize()

            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            return base64.b64encode(encrypted).decode("utf-8")
        except Exception as e:
            raise CloudEdgeError(f"Error during password encryption: {e}")

    def _aes_encode_param(
        self, user_account: str, api_endpoint: str, partner_id: int = 8, ttid: str = "", timestamp: Optional[int] = None
    ) -> str:
        if timestamp is None:
            timestamp = int(time.time() * 1000)

        key_material = f"{api_endpoint}{partner_id}{ttid}{timestamp}"
        key_b64 = base64.b64encode(key_material.encode("utf-8")).decode("utf-8")
        aes_key = key_b64[:16].encode("utf-8")

        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding

            algorithm = algorithms.AES(aes_key)
            cipher = Cipher(algorithm, modes.CBC(aes_key))
            encryptor = cipher.encryptor()

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(user_account.encode("utf-8")) + padder.finalize()

            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            return base64.b64encode(encrypted).decode("utf-8")
        except Exception as e:
            raise CloudEdgeError(f"Error during username encryption: {e}")

    def authenticate(self) -> bool:
        timestamp = int(time.time() * 1000)
        try:
            encrypted_username = self._aes_encode_param(self.username, "/meari/app/login", timestamp=timestamp)
            encrypted_password = self._des_encode(self.password)
        except Exception as e:
            raise AuthenticationError(f"Failed to encrypt credentials: {e}")

        ca_timestamp = str(timestamp)
        ca_nonce = str(int(time.time() * 1000000) % 100000000)
        ca_key = CA_KEY

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
            "phoneCode": self.phone_code,
        }

        headers = {
            "Accept-Language": "en-US,en;q=0.8",
            "User-Agent": DEFAULT_HEADERS.get("User-Agent", ""),
            "X-Ca-Timestamp": ca_timestamp,
            "X-Ca-Sign": ca_signature,
            "X-Ca-Key": ca_key,
            "X-Ca-Nonce": ca_nonce,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            response = self._session.post(
                f"{self.BASE_URL}/meari/app/login", data=login_data, headers=headers, timeout=30
            )
            response.raise_for_status()
            res_json = response.json()

            if res_json.get("resultCode") == "1001":
                result = res_json.get("result", {})
                self.session_data = {
                    "userToken": result.get("userToken"),
                    "userID": result.get("userID"),
                }
                return True
            else:
                raise AuthenticationError(f"Login failed: {res_json.get('resultMsg')}")
        except Exception as e:
            raise AuthenticationError(f"Login request failed: {e}")

    def get_mqtt_config(self) -> Dict[str, Any]:
        """Stub: MQTT non ancora implementato, evita il crash del setup."""
        return {}

    def get_all_devices(self) -> List[Dict[str, Any]]:
        if not self.session_data or not self.session_data.get("userToken"):
            raise AuthenticationError("Not authenticated - call authenticate() first")

        timestamp = int(time.time() * 1000)
        params = {
            "appVer": "6.1.1",
            "appVerCode": "1035",
            "countryCode": self.country_code,
            "lngType": "en",
            "phoneCode": self.phone_code.lstrip("+"),
            "phoneType": "a",
            "signatureMethod": "HMAC-SHA1",
            "signatureNonce": str(timestamp),
            "signatureVersion": "1.0",
            "sourceApp": "81",
            "t": str(timestamp),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(timestamp / 1000)),
            "userID": self.session_data["userID"],
        }
        msg = "&".join(f"{k}={params[k]}" for k in sorted(params))
        signature = base64.b64encode(
            hmac.new(self.session_data["userToken"].encode(), msg.encode(), hashlib.sha1).digest()
        ).decode()
        params["signature"] = signature

        try:
            response = self._session.get(
                f"{self.BASE_URL}/v1/app/home/list", params=params, timeout=DEFAULT_TIMEOUT
            )
            response.raise_for_status()
            res_json = response.json()
            if res_json.get("resultCode") == "1001":
                return res_json.get("result", {}).get("deviceList", [])
            raise CloudEdgeError(f"get_all_devices failed: {res_json.get('resultMsg')}")
        except requests.RequestException as e:
            raise NetworkError(f"Request failed: {e}")
