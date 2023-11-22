#!/usr/bin/env python3

"""Basic authentication module
"""

import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


# Basic authentication declaration
class BasicAuth(Auth):
    """Performs basic authentication
    """

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """Extracts the Base64 part of the authorization
        """

        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            field = re.fullmatch(pattern, authorization_header.strip())

            if field is not None:
                return field.group('token')

        return None

    def decode_base64_authorization_header(
        self,
        base64_authorization_header: str
    ) -> str:
        """Decode base64 authorization header
        """

        if type(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> (str, str):

        """Extracts user credential from a base64 encoded authorization header
        """

        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            field = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if field is not None:
                user = field.group('user')
                password = field.group('password')
                return user, password
        return None, None
