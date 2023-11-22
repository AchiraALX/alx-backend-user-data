#!/usr/bin/env python3

"""Basic authentication module
"""

import re

from .auth import Auth


# Basic authentication declaration
class BasicAuth(Auth):
    """Performs basic authentication
    """

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """Extracts the Base64 part of the authorization
        """

        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            field = re.fullmatch(pattern, authorization_header.strip())

            if field is not None:
                return field.group('token')

        return None