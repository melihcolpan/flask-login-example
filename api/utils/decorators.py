#!/usr/bin/python
# -*- coding: utf-8 -*-

import functools
import logging

import api.utils.responses as resp
from api.utils.auth import jwt
from api.utils.responses import m_return
from flask import request


def permission(arg):
    """Allow the request only if its Bearer token grants at least permission level ``arg``.

    Levels: user=0, admin=1, super admin=2. Any request without a valid Bearer
    token, or whose token does not grant the level, is rejected (deny by default).
    """

    def check_permissions(f):

        @functools.wraps(f)
        def decorated(*args, **kwargs):

            # Werkzeug parses the Authorization header, including Bearer tokens.
            auth = request.authorization
            if auth is None or auth.type != 'bearer' or not auth.token:
                return m_return(http_code=resp.UNAUTHORIZED_401['http_code'],
                                message=resp.UNAUTHORIZED_401['message'])

            try:
                data = jwt.loads(auth.token)
            except Exception as why:
                logging.info('Rejected token in permission check: %s', why)
                return m_return(http_code=resp.UNAUTHORIZED_401['http_code'],
                                message=resp.UNAUTHORIZED_401['message'])

            # Deny unless the token explicitly grants a high enough level.
            level = data.get('admin') if isinstance(data, dict) else None
            if not isinstance(level, int) or level < arg:
                return m_return(http_code=resp.NOT_ADMIN['http_code'], message=resp.NOT_ADMIN['message'])

            return f(*args, **kwargs)

        return decorated

    return check_permissions
