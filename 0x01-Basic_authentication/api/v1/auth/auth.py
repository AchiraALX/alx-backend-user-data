#!/usr/bin/env python3

"""Authentication module
"""

from flask import request
from typing import List, TypeVar


# Authentication class declaration
class Auth:
    """Authentcation class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check if a path is in authentication list
        """

        if path is None:
            return True
        
        if excluded_paths is None or len(excluded_paths) <= 0:
            return True
        
        if path.endswith('/'):
            path2 = path[:-1]

            if path in excluded_paths or path2 in excluded_paths:
                return False
            
        else:
            if path + '/' in excluded_paths:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """ Strips header from a request for Authorization key
        """

        if request is not None:
            return request.headers.get('Authorization', None)
        
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Fetch for the currently logged in user
        """

        return None